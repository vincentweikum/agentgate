"""Contract tests: prove the running API actually behaves the way its spec says.

    python scripts/contract_test.py [--max-examples 50] [--spec openapi/agentgate-claims.yaml]

Starts the API on a free local port, gets an OAuth token, then runs
Schemathesis. Schemathesis reads the OpenAPI spec and generates hundreds of
requests (valid and deliberately invalid) and checks that every response
matches the spec: status codes, headers, and body schemas, and that the
server never crashes. If the code and the contract disagree, this fails.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", default=str(ROOT / "openapi" / "agentgate-claims.yaml"))
    parser.add_argument("--max-examples", type=int, default=50)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    secret = secrets.token_urlsafe(24)
    env = {
        **os.environ,
        "ADJUSTER_CONSOLE_SECRET": secret,
        # High limit so the fuzzer isn't throttled (still within the documented maximum).
        "AGENTGATE_RATE_LIMIT_PER_MINUTE": "100000",
        "AGENTGATE_STATE_DIR": tempfile.mkdtemp(prefix="agentgate-contract-"),
    }
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env,
    )
    try:
        for _ in range(50):
            try:
                if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            print("API did not start", file=sys.stderr)
            return 1

        token = httpx.post(f"{base}/oauth/token", data={
            "grant_type": "client_credentials", "client_id": "adjuster-console", "client_secret": secret,
        }).json()["access_token"]

        # Prefer the copy installed next to this Python (works without activating the venv).
        local = Path(sys.executable).parent / "schemathesis"
        st = str(local) if local.exists() else shutil.which("schemathesis")
        if not st:
            print("schemathesis not found. Run: pip install -r requirements-dev.txt", file=sys.stderr)
            return 1
        cmd = [
            st, "run", args.spec, "--url", base,
            "--header", f"Authorization: Bearer {token}",
            "--checks", "all",
            "--max-examples", str(args.max_examples),
            "--seed", str(args.seed),
            "--report", "junit", "--report-dir", str(ROOT / "reports" / "contract"),
        ]
        print("Running:", " ".join(c if "Bearer" not in c else "Authorization: Bearer ***" for c in cmd))
        return subprocess.run(cmd, cwd=ROOT).returncode
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
