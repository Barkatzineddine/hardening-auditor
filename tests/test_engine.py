from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime

import pytest

from hardening_auditor.catalog import parse_rule
from hardening_auditor.engine import audit, evaluate_rule, format_value, score
from hardening_auditor.facts import FactsError, parse_facts
from hardening_auditor.models import AcceptedRisk, Rule, RuleResult, Severity, Status
from tests.conftest import fixture_data, fixture_document

TODAY = date(2026, 10, 20)


@pytest.mark.parametrize("name", ["windows-compliant", "linux-compliant"])
def test_compliant_fixture_passes_every_control(name: str, catalog: list[Rule]) -> None:
    result = audit(fixture_document(name), catalog, today=TODAY)
    statuses = {r.rule.id: r.status for r in result.results}
    assert set(statuses.values()) == {Status.PASS}, statuses
    assert result.overall_score == 100.0
    assert all(c.score == 100.0 for c in result.categories)


@pytest.mark.parametrize("name", ["windows-noncompliant", "linux-noncompliant"])
def test_noncompliant_fixture_fails_every_control(name: str, catalog: list[Rule]) -> None:
    result = audit(fixture_document(name), catalog, today=TODAY)
    passed = [r.rule.id for r in result.results if r.status is not Status.FAIL]
    assert passed == []
    assert result.overall_score == 0.0
    assert all(r.reason for r in result.results)


def test_only_rules_of_the_host_platform_are_evaluated(catalog: list[Rule]) -> None:
    result = audit(fixture_document("linux-compliant"), catalog, today=TODAY)
    assert {r.rule.platform for r in result.results} == {"linux"}
    assert result.catalogue_size == len(result.results)


def test_results_are_sorted_by_severity(catalog: list[Rule]) -> None:
    result = audit(fixture_document("windows-noncompliant"), catalog, today=TODAY)
    ranks = [r.rule.severity.rank for r in result.results]
    assert ranks == sorted(ranks)


def test_applicability(catalog: list[Rule]) -> None:
    data = fixture_data("windows-compliant")
    data["facts"]["os.product_type"] = "domain_controller"
    data["facts"]["rdp.enabled"] = False
    result = audit(parse_facts(data), catalog, today=TODAY)
    not_applicable = {r.rule.id for r in result.results if r.status is Status.NOT_APPLICABLE}
    assert {"WIN-ACC-006", "WIN-ACC-007", "WIN-ACC-008", "WIN-RDP-001", "WIN-AUTH-004"} <= not_applicable
    assert "WIN-SVC-001" not in not_applicable


def test_unknown_when_facts_are_missing(catalog: list[Rule]) -> None:
    data = fixture_data("windows-compliant")
    for key in [k for k in data["facts"] if k.startswith(("policy.", "os.product_type"))]:
        del data["facts"][key]
    result = audit(parse_facts(data), catalog, today=TODAY)
    unknown = {r.rule.id: r for r in result.results if r.status is Status.UNKNOWN}
    assert {"WIN-ACC-001", "WIN-ACC-004", "WIN-ACC-006"} <= set(unknown)
    assert unknown["WIN-ACC-001"].reason == "Not collected: policy.password.min_length"
    assert unknown["WIN-ACC-006"].reason == "Applicability could not be determined"
    # Unknown controls do not lower the score.
    assert result.overall_score == 100.0


def test_score_is_weighted_by_severity() -> None:
    def result(severity: Severity, status: Status) -> RuleResult:
        rule = parse_rule(
            {
                "id": f"WIN-T-{severity.value.upper()}",
                "title": "t",
                "platform": "windows",
                "category": "c",
                "severity": severity.value,
                "rationale": "r",
                "references": {"anssi": [1]},
                "check": {"fact": "f", "op": "exists"},
                "remediation": {"summary": "s"},
            }
        )
        return RuleResult(rule, status)

    results = [
        result(Severity.CRITICAL, Status.PASS),
        result(Severity.LOW, Status.FAIL),
        result(Severity.HIGH, Status.ACCEPTED),
        result(Severity.MEDIUM, Status.NOT_APPLICABLE),
    ]
    assert score(results) == 80.0
    assert score([]) is None


def test_exceptions_are_applied_and_reported(catalog: list[Rule]) -> None:
    risks = [
        AcceptedRisk(
            "WIN-SVC-001", "Print server for the accounting floor.", date(2027, 1, 31), "RSSI", "SEC-1"
        ),
        AcceptedRisk("WIN-NET-003", "Old copier, replacement ordered.", date(2026, 9, 30)),
        AcceptedRisk("WIN-ACC-001", "Should not be needed on this host.", date(2027, 1, 31)),
        AcceptedRisk("WIN-NET-001", "Only for another host.", date(2027, 1, 31), hosts=("SRV-OTHER*",)),
    ]
    result = audit(fixture_document("windows-noncompliant"), catalog, risks, today=TODAY)
    by_id = {r.rule.id: r for r in result.results}
    assert by_id["WIN-SVC-001"].status is Status.ACCEPTED
    assert by_id["WIN-SVC-001"].exception is risks[0]
    assert by_id["WIN-NET-003"].status is Status.FAIL
    assert by_id["WIN-NET-001"].status is Status.FAIL
    assert [r.rule_id for r in result.expired_exceptions] == ["WIN-NET-003"]
    assert result.unused_exceptions == ()
    compliant = audit(fixture_document("windows-compliant"), catalog, risks, today=TODAY)
    assert {r.rule_id for r in compliant.unused_exceptions} == {"WIN-SVC-001", "WIN-ACC-001"}


def test_generated_at_and_evaluate_rule(catalog: list[Rule]) -> None:
    now = datetime(2026, 10, 20, 9, 30, tzinfo=UTC)
    result = audit(fixture_document("linux-compliant"), catalog, today=TODAY, now=now)
    assert result.generated_at == "2026-10-20T09:30:00+00:00"
    rule = next(r for r in catalog if r.id == "LNX-SSH-001")
    assert evaluate_rule(replace(rule, applies_if=None), {}).status is Status.UNKNOWN


@pytest.mark.parametrize(
    ("value", "text"),
    [(None, "not set"), (True, "true"), (False, "false"), ([], "[]"), (["a", 1], "[a, 1]"), (3, "3")],
)
def test_format_value(value: object, text: str) -> None:
    assert format_value(value) == text


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"schema_version": 2}, "schema_version"),
        ({"host": []}, "must be objects"),
        ({"host": {"os_family": "linux"}}, "hostname"),
        ({"host": {"hostname": "h", "os_family": "aix"}}, "os_family"),
        ({"warnings": "none"}, "'warnings' must be a list"),
    ],
)
def test_invalid_facts_documents(change: dict[str, object], message: str) -> None:
    data = {**fixture_data("linux-compliant"), **change}
    with pytest.raises(FactsError, match=message):
        parse_facts(data)
    with pytest.raises(FactsError, match="JSON object"):
        parse_facts([data])
