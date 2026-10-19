"""The guardrail scenarios run as part of the test suite too."""

from evals.run import main


def test_all_guardrail_scenarios_pass(tmp_path):
    assert main(["--out", str(tmp_path)]) == 0
    assert (tmp_path / "eval-report.json").exists() and (tmp_path / "eval-audit.jsonl").exists()
