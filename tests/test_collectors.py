"""Run the real collector of the current platform (read-only) and check that its output is usable."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hardening_auditor.catalog import load_catalog
from hardening_auditor.engine import audit
from hardening_auditor.facts import load_facts
from hardening_auditor.models import Status

COLLECTORS = Path(__file__).resolve().parents[1] / "collectors"


def _check(output: Path, family: str) -> None:
    document = load_facts(output)
    assert document.host.os_family == family
    assert len(document.facts) >= 20
    result = audit(document, load_catalog(platform=family))
    evaluated = [r for r in result.results if r.status in (Status.PASS, Status.FAIL)]
    assert len(evaluated) >= len(result.results) // 2


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux collector")
def test_linux_collector(tmp_path: Path) -> None:
    output = tmp_path / "facts.json"
    subprocess.run(
        ["sh", str(COLLECTORS / "linux" / "collect.sh"), "-o", str(output)], check=True, timeout=120
    )
    _check(output, "linux")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows collector")
def test_windows_collector(tmp_path: Path) -> None:
    output = tmp_path / "facts.json"
    powershell = shutil.which("powershell.exe")
    assert powershell is not None
    script = COLLECTORS / "windows" / "Invoke-HardeningCollector.ps1"
    command = [
        powershell,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        "-OutputPath",
        str(output),
    ]
    subprocess.run(command, check=True, timeout=300)
    _check(output, "windows")
