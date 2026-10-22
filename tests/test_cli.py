from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hardening_auditor.cli import EXIT_ERROR, EXIT_GATE, EXIT_OK, main
from tests.conftest import FIXTURES

WIN_BAD = str(FIXTURES / "windows-noncompliant.json")
WIN_GOOD = str(FIXTURES / "windows-compliant.json")
LNX_BAD = str(FIXTURES / "linux-noncompliant.json")


def test_audit_writes_every_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "reports"
    ndjson = tmp_path / "events.ndjson"
    assert main(["audit", WIN_BAD, "--out-dir", str(out), "--ndjson", str(ndjson)]) == EXIT_OK
    for suffix in ("html", "json", "csv"):
        assert (out / f"srv-legacy02-report.{suffix}").stat().st_size > 0
    assert ndjson.read_text(encoding="utf-8").count("\n") == 35
    printed = capsys.readouterr().out
    assert "Score    0.0/100" in printed
    assert "WIN-NET-001" in printed


def test_audit_explicit_outputs_quiet(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    html = tmp_path / "r.html"
    assert main(["audit", WIN_GOOD, "--html", str(html), "-q"]) == EXIT_OK
    assert html.exists()
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("args", "code", "message"),
    [
        (["--fail-under", "50"], EXIT_GATE, "below 50"),
        (["--fail-on", "critical"], EXIT_GATE, "severity critical or higher"),
        (["--fail-under", "0"], EXIT_OK, ""),
    ],
)
def test_audit_gates(args: list[str], code: int, message: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["audit", LNX_BAD, "-q", *args]) == code
    assert message in capsys.readouterr().err


def test_max_unknown_gate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = json.loads(Path(WIN_GOOD).read_text(encoding="utf-8"))
    data["host"]["elevated"] = False
    del data["facts"]["policy.password.min_length"]
    facts = tmp_path / "partial.json"
    facts.write_text(json.dumps(data), encoding="utf-8")
    assert main(["audit", str(facts), "--max-unknown", "0"]) == EXIT_GATE
    captured = capsys.readouterr()
    assert "WIN-ACC-001" in captured.err
    assert "without administrator/root rights" in captured.out
    assert main(["audit", str(facts), "--max-unknown", "1", "-q"]) == EXIT_OK


EXCEPTIONS = """\
exceptions:
  - rule: WIN-SVC-001
    justification: Print server, accepted.
    expires: 2099-01-01
  - rule: WIN-NET-003
    justification: Expired a long time ago.
    expires: 2001-01-01
"""


def test_audit_with_exceptions_and_expired_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exceptions = tmp_path / "exceptions.yml"
    exceptions.write_text(EXCEPTIONS, encoding="utf-8")
    report = tmp_path / "r.json"
    assert main(["audit", WIN_BAD, "--exceptions", str(exceptions), "--json", str(report)]) == EXIT_OK
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["accepted"] == 1
    assert data["exceptions"]["expired"][0]["rule"] == "WIN-NET-003"
    assert "exception for WIN-NET-003 expired" in capsys.readouterr().out
    assert main(["audit", WIN_GOOD, "--exceptions", str(exceptions)]) == EXIT_OK
    assert "exception for WIN-SVC-001 is no longer needed" in capsys.readouterr().out


def test_compare_reports_and_raw_facts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = tmp_path / "before.json"
    assert main(["audit", WIN_BAD, "--json", str(before), "-q"]) == EXIT_OK
    assert main(["compare", str(before), WIN_GOOD, "--format", "markdown"]) == EXIT_OK
    assert "### Fixed (35)" in capsys.readouterr().out
    assert main(["compare", WIN_GOOD, WIN_BAD, "--fail-on-regression"]) == EXIT_GATE
    captured = capsys.readouterr()
    assert "Regressions (35):" in captured.out
    assert "35 regression(s)" in captured.err
    assert main(["compare", WIN_GOOD, WIN_GOOD, "--format", "json"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["delta"] == 0.0


def test_rules_listing(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules", "--platform", "linux"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "LNX-SSH-001" in out
    assert "WIN-" not in out
    assert main(["rules", "--format", "json"]) == EXIT_OK
    rules = json.loads(capsys.readouterr().out)
    assert {"WIN", "LNX"} == {r["id"].split("-")[0] for r in rules}


def test_validate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    example = Path(__file__).resolve().parents[1] / "examples" / "exceptions.yml"
    assert main(["validate", "--exceptions", str(example)]) == EXIT_OK
    assert "Exceptions OK: 3 entries" in capsys.readouterr().out
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "exceptions:\n  - rule: WIN-NOPE-001\n    justification: Unknown rule id.\n    expires: 2030-01-01\n",
        encoding="utf-8",
    )
    assert main(["validate", "--exceptions", str(bad)]) == EXIT_ERROR
    assert "unknown rules ['WIN-NOPE-001']" in capsys.readouterr().err


def test_errors_are_reported_without_traceback(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert main(["audit", str(broken)]) == EXIT_ERROR
    assert capsys.readouterr().err.startswith("error:")
    assert main(["rules", "--no-default-rules"]) == EXIT_ERROR
    assert "--no-default-rules needs" in capsys.readouterr().err
    listing = tmp_path / "list.json"
    listing.write_text("[]", encoding="utf-8")
    assert main(["compare", str(listing), WIN_GOOD]) == EXIT_ERROR


def test_bom_encoded_input_from_windows_powershell(tmp_path: Path) -> None:
    facts = tmp_path / "bom.json"
    facts.write_bytes(b"\xef\xbb\xbf" + Path(WIN_GOOD).read_bytes())
    assert main(["audit", str(facts), "-q"]) == EXIT_OK


def test_redirected_output_is_utf8() -> None:
    """compare --format markdown prints arrows; a cp1252 pipe on Windows must not crash."""
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    args = ["compare", WIN_BAD, WIN_GOOD, "--format", "markdown"]
    command = [sys.executable, "-m", "hardening_auditor", *args]
    result = subprocess.run(command, capture_output=True, check=True, env=env)
    assert "→".encode() in result.stdout
