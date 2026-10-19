"""Tamper-evident audit log for every agent action (STD-AI-04).

Each line is a JSON record. Every record stores the SHA-256 hash of the record
before it, so editing, reordering, or deleting any line breaks the chain from
that point on. A hash chain alone can't tell if records were cut off the END,
so the latest seq and hash are also kept in a separate "head" file
(agent-audit.jsonl.head). In production the head would go to a different
system (like write-once storage) so one compromised machine can't rewrite both.
`verify` recomputes the chain, compares it to the head, and reports exactly
where it breaks.

    python -m agent_gateway.audit verify [--path state/agent-audit.jsonl]
    python -m agent_gateway.audit tail [--path ...] [-n 20]
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def default_path() -> Path:
    state = Path(os.environ.get("AGENTGATE_STATE_DIR", Path(__file__).resolve().parent.parent / "state"))
    return state / "agent-audit.jsonl"


def head_path(path: Path) -> Path:
    return path.with_name(path.name + ".head")


def _hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or default_path())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _last(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open() as f:
            for line in f:
                if line.strip():
                    last = line
        if not last:
            return 0, GENESIS
        record = json.loads(last)
        return record["seq"], record["hash"]

    def write(self, **fields) -> dict:
        # The thread lock covers this process; the file lock covers other processes
        # (for example the approvals CLI writing while the gateway is running).
        with self._lock, self.path.open("a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                seq, prev = self._last()
                record = {"seq": seq + 1, "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                          **fields, "prev_hash": prev}
                record["hash"] = _hash(record)
                f.write(json.dumps(record, sort_keys=True) + "\n")
                f.flush()
                tmp = head_path(self.path).with_suffix(".tmp")
                tmp.write_text(json.dumps({"seq": record["seq"], "hash": record["hash"]}))
                tmp.replace(head_path(self.path))  # atomic swap
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        return record

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]


def verify(path: Path) -> tuple[bool, str]:
    prev, expected_seq = GENESIS, 1
    if not path.exists():
        return True, "No audit log yet."
    for n, line in enumerate(path.read_text().splitlines(), start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False, f"Line {n} is not valid JSON."
        if record.get("seq") != expected_seq:
            return False, f"Line {n}: expected seq {expected_seq}, found {record.get('seq')} (a record was removed or reordered)."
        if record.get("prev_hash") != prev:
            return False, f"Line {n} (seq {record['seq']}): prev_hash doesn't match the previous record."
        if _hash(record) != record.get("hash"):
            return False, f"Line {n} (seq {record['seq']}): contents were modified after it was written."
        prev, expected_seq = record["hash"], expected_seq + 1
    count = expected_seq - 1
    head = head_path(path)
    if not head.exists():
        return True, f"OK: {count} records, chain intact (no head file, so truncation can't be checked)."
    expected = json.loads(head.read_text())
    if expected.get("seq") != count or expected.get("hash") != prev:
        return False, (f"The log ends at seq {count}, but the head record says seq {expected.get('seq')}: "
                       "records were removed from the end, or the log was replaced.")
    return True, f"OK: {count} records, chain intact, matches head."


def main() -> int:
    parser = argparse.ArgumentParser(description="Agent audit log tools")
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check that no record was modified, removed, or reordered")
    v.add_argument("--path", type=Path, default=default_path())
    t = sub.add_parser("tail", help="show the latest records")
    t.add_argument("--path", type=Path, default=default_path())
    t.add_argument("-n", type=int, default=20)
    args = parser.parse_args()

    if args.cmd == "verify":
        ok, message = verify(args.path)
        print(message)
        return 0 if ok else 1
    for r in AuditLog(args.path).records()[-args.n:]:
        print(f"#{r['seq']:<4} {r['ts']}  {r.get('agent_id', '-'):<24} {r.get('event'):<18} "
              f"{r.get('tool') or '':<20} {r.get('decision') or ''}  {r.get('reason') or ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
