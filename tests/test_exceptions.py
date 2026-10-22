from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest

from hardening_auditor.exceptions import (
    ExceptionsError,
    for_host,
    is_active,
    load_exceptions,
    matches_host,
    parse_exceptions,
)
from hardening_auditor.models import AcceptedRisk

ENTRY: dict[str, Any] = {
    "rule": "LNX-SSH-001",
    "justification": "Break-glass access during the PAM bastion rollout.",
    "approved_by": "RSSI",
    "ticket": "SEC-142",
    "expires": date(2027, 3, 31),
}


def test_parse_and_defaults() -> None:
    [risk] = parse_exceptions({"exceptions": [ENTRY]})
    assert risk.rule_id == "LNX-SSH-001"
    assert risk.hosts == ("*",)
    assert risk.ticket == "SEC-142"
    assert parse_exceptions(None) == []


def test_host_patterns() -> None:
    [risk] = parse_exceptions({"exceptions": [{**ENTRY, "hosts": "bastion-*"}]})
    assert matches_host(risk, "BASTION-01")
    assert not matches_host(risk, "web-01")
    assert for_host([risk], "web-01") == []


def test_expiry_is_inclusive() -> None:
    risk = AcceptedRisk("LNX-SSH-001", "justified enough", date(2026, 10, 20))
    assert is_active(risk, date(2026, 10, 20))
    assert not is_active(risk, date(2026, 10, 21))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"rule": "ssh"}, "'rule' must be"),
        ({"justification": "because"}, "at least 10 characters"),
        ({"expires": "someday"}, "must be a date"),
        ({"hosts": []}, "host name patterns"),
        ({"hosts": [""]}, "host name patterns"),
        ({"owner": "me"}, "unknown field"),
    ],
)
def test_invalid_entries(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ExceptionsError, match=message):
        parse_exceptions({"exceptions": [{**ENTRY, **change}]})


def test_invalid_documents(tmp_path: Path) -> None:
    with pytest.raises(ExceptionsError, match="top-level 'exceptions' list"):
        parse_exceptions({"exception": []})
    with pytest.raises(ExceptionsError, match="must be a mapping"):
        parse_exceptions({"exceptions": ["LNX-SSH-001"]})
    with pytest.raises(ExceptionsError, match="cannot read"):
        load_exceptions(tmp_path / "missing.yml")


def test_load_example_file() -> None:
    example = Path(__file__).resolve().parents[1] / "examples" / "exceptions.yml"
    risks = load_exceptions(example)
    assert risks
    assert all(risk.justification for risk in risks)
