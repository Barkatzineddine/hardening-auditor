from __future__ import annotations

from typing import Any

import pytest

from hardening_auditor.conditions import ConditionError, evaluate, facts_used, validate
from hardening_auditor.models import Outcome


def leaf(fact: str, op: str, value: Any = None, **extra: Any) -> dict[str, Any]:
    condition: dict[str, Any] = {"fact": fact, "op": op, **extra}
    if op not in {"exists", "absent"}:
        condition["value"] = value
    return condition


def outcome(condition: dict[str, Any], facts: dict[str, Any]) -> Outcome:
    validate(condition)
    return evaluate(condition, facts)[0]


@pytest.mark.parametrize(
    ("op", "actual", "expected", "result"),
    [
        ("eq", 14, 14, Outcome.PASS),
        ("eq", "14", 14, Outcome.PASS),
        ("eq", "Block", "block", Outcome.PASS),
        ("eq", True, True, Outcome.PASS),
        ("eq", 1, True, Outcome.PASS),
        ("eq", "false", False, Outcome.PASS),
        ("eq", "maybe", True, Outcome.FAIL),
        ("eq", 0, 1, Outcome.FAIL),
        ("ne", "domain_controller", "domain_controller", Outcome.FAIL),
        ("ne", "server", "domain_controller", Outcome.PASS),
        ("gt", 5, 4, Outcome.PASS),
        ("gte", 14, 14, Outcome.PASS),
        ("gte", 7, 14, Outcome.FAIL),
        ("lt", 3, 4, Outcome.PASS),
        ("lte", 365, 365, Outcome.PASS),
        ("lte", 99999, 365, Outcome.FAIL),
        ("in", "SHA512", ["SHA512", "YESCRYPT"], Outcome.PASS),
        ("in", "md5", ["SHA512", "YESCRYPT"], Outcome.FAIL),
        ("not_in", "md5", ["SHA512"], Outcome.PASS),
        ("contains", ["a", "b"], "B", Outcome.PASS),
        ("contains", "rw,nodev", "nodev", Outcome.PASS),
        ("not_contains", ["spooler", "w32time"], "spooler", Outcome.FAIL),
        ("contains_all", ["rw", "nodev", "nosuid"], ["nodev", "nosuid"], Outcome.PASS),
        ("contains_all", ["rw", "nodev"], ["nodev", "noexec"], Outcome.FAIL),
        ("none_of", ["aes256-ctr", "aes256-cbc"], ["aes256-cbc"], Outcome.FAIL),
        ("none_of", ["aes256-ctr"], ["aes256-cbc"], Outcome.PASS),
        ("subset_of", ["root"], ["root"], Outcome.PASS),
        ("subset_of", ["root", "toor"], ["root"], Outcome.FAIL),
        ("max_items", [], 0, Outcome.PASS),
        ("max_items", ["a", "b", "c", "d"], 3, Outcome.FAIL),
        ("regex", "VERBOSE", "^(info|verbose)$", Outcome.PASS),
        ("not_regex", "permit", "^no$", Outcome.PASS),
        ("mode_at_most", "0640", "0644", Outcome.PASS),
        ("mode_at_most", "0000", "0640", Outcome.PASS),
        ("mode_at_most", "0666", "0644", Outcome.FAIL),
        ("mode_at_most", "4755", "0755", Outcome.FAIL),
    ],
)
def test_operators(op: str, actual: Any, expected: Any, result: Outcome) -> None:
    assert outcome(leaf("f", op, expected), {"f": actual}) is result


def test_presence_operators() -> None:
    assert outcome(leaf("f", "exists"), {"f": 0}) is Outcome.PASS
    assert outcome(leaf("f", "exists"), {"f": None}) is Outcome.FAIL
    assert outcome(leaf("f", "absent"), {}) is Outcome.PASS


def test_non_numeric_comparison_is_unknown() -> None:
    result, details = evaluate(leaf("f", "gte", 14), {"f": "fourteen"})
    assert result is Outcome.UNKNOWN
    assert "cannot compare" in details[0].note


def test_missing_fact_policies() -> None:
    assert outcome(leaf("f", "eq", 1), {}) is Outcome.UNKNOWN
    assert outcome(leaf("f", "eq", 1, missing="fail"), {}) is Outcome.FAIL
    assert outcome(leaf("f", "eq", 1, missing="pass"), {"f": None}) is Outcome.PASS


def test_default_is_used_when_fact_missing() -> None:
    result, details = evaluate(leaf("f", "eq", 5, default=3), {})
    assert result is Outcome.FAIL
    assert details[0].actual == 3
    assert "default" in details[0].note
    assert outcome(leaf("f", "eq", 1, default=1), {"f": None}) is Outcome.PASS


@pytest.mark.parametrize(
    ("children", "kind", "result"),
    [
        ([Outcome.PASS, Outcome.PASS], "all", Outcome.PASS),
        ([Outcome.PASS, Outcome.FAIL], "all", Outcome.FAIL),
        ([Outcome.PASS, Outcome.UNKNOWN], "all", Outcome.UNKNOWN),
        ([Outcome.FAIL, Outcome.UNKNOWN], "all", Outcome.FAIL),
        ([Outcome.FAIL, Outcome.FAIL], "any", Outcome.FAIL),
        ([Outcome.FAIL, Outcome.PASS], "any", Outcome.PASS),
        ([Outcome.UNKNOWN, Outcome.PASS], "any", Outcome.PASS),
        ([Outcome.UNKNOWN, Outcome.FAIL], "any", Outcome.UNKNOWN),
    ],
)
def test_kleene_logic(children: list[Outcome], kind: str, result: Outcome) -> None:
    facts: dict[str, Any] = {}
    conditions = []
    for index, child in enumerate(children):
        name = f"f{index}"
        if child is not Outcome.UNKNOWN:
            facts[name] = 1 if child is Outcome.PASS else 0
        conditions.append(leaf(name, "eq", 1))
    assert outcome({kind: conditions}, facts) is result


def test_not_inverts_but_keeps_unknown() -> None:
    assert outcome({"not": leaf("f", "eq", 1)}, {"f": 1}) is Outcome.FAIL
    assert outcome({"not": leaf("f", "eq", 1)}, {"f": 0}) is Outcome.PASS
    assert outcome({"not": leaf("f", "eq", 1)}, {}) is Outcome.UNKNOWN


def test_details_cover_every_leaf() -> None:
    condition = {"all": [leaf("a", "eq", 1), {"any": [leaf("b", "eq", 1), leaf("c", "eq", 1)]}]}
    _, details = evaluate(condition, {"a": 1, "b": 0, "c": 1})
    assert [d.fact for d in details] == ["a", "b", "c"]
    assert facts_used(condition) == {"a", "b", "c"}
    assert facts_used({"not": leaf("d", "exists")}) == {"d"}


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        ({}, "non-empty mapping"),
        ([], "non-empty mapping"),
        ({"all": [], "any": []}, "only key"),
        ({"all": []}, "non-empty list"),
        ({"fact": "f", "op": "eq", "value": 1, "extra": 1}, "unknown key"),
        ({"fact": "", "op": "eq", "value": 1}, "'fact' must be"),
        ({"fact": "f", "op": "approx", "value": 1}, "unknown operator"),
        ({"fact": "f", "op": "exists", "value": 1}, "takes no value"),
        ({"fact": "f", "op": "eq"}, "needs a value"),
        ({"fact": "f", "op": "in", "value": "a"}, "needs a list"),
        ({"fact": "f", "op": "regex", "value": "("}, "invalid regex"),
        ({"fact": "f", "op": "mode_at_most", "value": "0999"}, "octal"),
        ({"fact": "f", "op": "eq", "value": 1, "missing": "skip"}, "'missing'"),
        ({"not": {"fact": "f", "op": "nope", "value": 1}}, "unknown operator"),
    ],
)
def test_validation_errors(condition: Any, message: str) -> None:
    with pytest.raises(ConditionError, match=message):
        validate(condition)
