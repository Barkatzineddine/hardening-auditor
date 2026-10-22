from __future__ import annotations

import json
from datetime import date
from typing import Any

import pytest

from hardening_auditor import compare, report
from hardening_auditor.engine import audit
from hardening_auditor.facts import parse_facts
from hardening_auditor.models import Rule
from tests.conftest import fixture_data

TODAY = date(2026, 10, 20)


def _report(catalog: list[Rule], data: dict[str, Any]) -> dict[str, Any]:
    return report.to_dict(audit(parse_facts(data), catalog, today=TODAY))


@pytest.fixture
def before_after(catalog: list[Rule]) -> tuple[dict[str, Any], dict[str, Any]]:
    before = fixture_data("linux-noncompliant")
    after = fixture_data("linux-noncompliant")
    after["facts"]["ssh.permitrootlogin"] = "no"
    after["facts"]["firewall.active"] = True
    after["facts"]["sysctl.net.ipv4.ip_forward"] = 0
    # A regression on a control that passed before.
    before["facts"]["time.sync_active"] = True
    return _report(catalog, before), _report(catalog, after)


def test_fixed_and_regressed(before_after: tuple[dict[str, Any], dict[str, Any]]) -> None:
    result = compare.compare(*before_after)
    assert [c.rule_id for c in result.fixed] == ["LNX-FW-001", "LNX-SSH-001", "LNX-NET-001"]
    assert [c.rule_id for c in result.regressed] == ["LNX-TIME-001"]
    assert result.delta is not None and result.delta > 0
    assert result.still_failing == 31


def test_renderers(before_after: tuple[dict[str, Any], dict[str, Any]]) -> None:
    result = compare.compare(*before_after)
    text = compare.to_text(result)
    assert "Fixed (3):" in text
    assert "LNX-TIME-001" in text
    markdown = compare.to_markdown(result)
    assert "### Regressions (1)" in markdown
    data = json.loads(compare.to_json(result))
    assert data["regressed"][0]["id"] == "LNX-TIME-001"
    assert data["delta"] == result.delta


def test_rule_added_or_removed_and_status_changes(catalog: list[Rule]) -> None:
    before = _report(catalog, fixture_data("linux-noncompliant"))
    after = _report(catalog, fixture_data("linux-noncompliant"))
    after["results"] = [r for r in after["results"] if r["id"] != "LNX-MNT-001"]
    accepted = next(r for r in after["results"] if r["id"] == "LNX-SVC-002")
    accepted["status"] = "accepted"
    result = compare.compare(before, after)
    assert {(c.rule_id, c.before, c.after) for c in result.other_changes} == {
        ("LNX-MNT-001", "fail", None),
        ("LNX-SVC-002", "fail", "accepted"),
    }
    assert "none" in compare.to_text(result)


def test_unknown_scores_and_invalid_input() -> None:
    empty = {"score": {"overall": None, "categories": []}, "results": []}
    result = compare.compare(empty, empty)
    assert result.delta is None
    assert "n/a" in compare.to_text(result)
    with pytest.raises(compare.CompareError, match="first file"):
        compare.compare({"results": []}, empty)
