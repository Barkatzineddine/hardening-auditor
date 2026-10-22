"""Evaluation of the catalogue against a host's facts, and the compliance score."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime

from . import conditions
from . import exceptions as exc_mod
from .models import (
    AcceptedRisk,
    AuditResult,
    CategoryScore,
    FactsDocument,
    Outcome,
    Rule,
    RuleResult,
    Status,
)


def evaluate_rule(rule: Rule, facts: dict[str, object]) -> RuleResult:
    if rule.applies_if is not None:
        applies, details = conditions.evaluate(rule.applies_if, facts)
        if applies is Outcome.FAIL:
            return RuleResult(rule, Status.NOT_APPLICABLE, tuple(details), "Applicability condition not met")
        if applies is Outcome.UNKNOWN:
            return RuleResult(rule, Status.UNKNOWN, tuple(details), "Applicability could not be determined")
    outcome, details = conditions.evaluate(rule.check, facts)
    status = {Outcome.PASS: Status.PASS, Outcome.FAIL: Status.FAIL, Outcome.UNKNOWN: Status.UNKNOWN}[outcome]
    reason = ""
    if status is Status.UNKNOWN:
        missing = sorted({d.fact for d in details if d.outcome is Outcome.UNKNOWN})
        reason = "Not collected: " + ", ".join(missing)
    elif status is Status.FAIL:
        failed = [d for d in details if d.outcome is Outcome.FAIL]
        reason = "; ".join(f"{d.fact} = {format_value(d.actual)}" for d in failed)
    return RuleResult(rule, status, tuple(details), reason)


def format_value(value: object) -> str:
    if value is None:
        return "not set"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list | tuple):
        return "[" + ", ".join(format_value(item) for item in value) + "]" if value else "[]"
    return str(value)


def score(results: Iterable[RuleResult]) -> float | None:
    """Severity-weighted share of passed controls among those that passed or failed.

    Accepted, not-applicable and unknown controls are left out: an accepted risk is neither a
    pass nor a fail, and an unknown control is reported separately rather than guessed.
    """
    earned = total = 0
    for result in results:
        if result.status in (Status.PASS, Status.FAIL):
            total += result.rule.severity.weight
            if result.status is Status.PASS:
                earned += result.rule.severity.weight
    return round(100 * earned / total, 1) if total else None


def _category_score(name: str, results: Sequence[RuleResult]) -> CategoryScore:
    def count(status: Status) -> int:
        return sum(1 for r in results if r.status is status)

    return CategoryScore(
        name=name,
        score=score(results),
        passed=count(Status.PASS),
        failed=count(Status.FAIL),
        accepted=count(Status.ACCEPTED),
        not_applicable=count(Status.NOT_APPLICABLE),
        unknown=count(Status.UNKNOWN),
    )


def _apply_exception(result: RuleResult, risks: Sequence[AcceptedRisk], today: date) -> RuleResult:
    if result.status is not Status.FAIL:
        return result
    for risk in risks:
        if risk.rule_id == result.rule.id and exc_mod.is_active(risk, today):
            return RuleResult(result.rule, Status.ACCEPTED, result.details, result.reason, risk)
    return result


def audit(
    document: FactsDocument,
    rules: Sequence[Rule],
    risks: Sequence[AcceptedRisk] = (),
    today: date | None = None,
    now: datetime | None = None,
) -> AuditResult:
    """Evaluate every rule of the host's platform and apply the accepted-risk exceptions."""
    today = today or date.today()
    platform_rules = [rule for rule in rules if rule.platform == document.host.os_family]
    host_risks = exc_mod.for_host(risks, document.host.hostname)

    results = [
        _apply_exception(evaluate_rule(rule, document.facts), host_risks, today) for rule in platform_rules
    ]
    used = {r.exception for r in results if r.exception is not None}
    failing_ids = {r.rule.id for r in results if r.status is Status.FAIL}
    expired = tuple(r for r in host_risks if not exc_mod.is_active(r, today) and r.rule_id in failing_ids)
    unused = tuple(r for r in host_risks if exc_mod.is_active(r, today) and r not in used)

    by_category: dict[str, list[RuleResult]] = {}
    for result in results:
        by_category.setdefault(result.rule.category, []).append(result)

    ordered = sorted(results, key=lambda r: (r.rule.severity.rank, r.rule.category, r.rule.id))
    return AuditResult(
        host=document.host,
        results=tuple(ordered),
        overall_score=score(results),
        categories=tuple(_category_score(name, items) for name, items in sorted(by_category.items())),
        warnings=document.warnings,
        expired_exceptions=expired,
        unused_exceptions=unused,
        generated_at=(now or datetime.now(UTC)).isoformat(timespec="seconds"),
        catalogue_size=len(platform_rules),
    )
