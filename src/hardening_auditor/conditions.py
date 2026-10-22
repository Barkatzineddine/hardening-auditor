"""Check logic: validation and three-valued evaluation of rule conditions.

A condition is either a leaf::

    {fact: smb.server.require_signing, op: eq, value: 1, default: 0, missing: fail}

or a combination of conditions: ``{all: [...]}``, ``{any: [...]}`` or ``{not: {...}}``.

A leaf whose fact was not collected uses ``default`` when the rule gives one (the documented
operating-system default, e.g. a registry value that is absent), otherwise ``missing``
(``unknown`` by default). Combinations follow Kleene logic, so ``any`` passes as soon as one
branch passes even when another branch could not be evaluated.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .models import ConditionDetail, Outcome


class ConditionError(ValueError):
    """A condition in the catalogue is malformed."""


_MISSING = object()


def _is_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int | float):
        return True
    if isinstance(value, str):
        try:
            float(value)
        except ValueError:
            return False
        return True
    return False


def _as_number(value: Any) -> float:
    if not _is_number(value):
        raise TypeError(f"{value!r} is not a number")
    return float(value)


def _equals(actual: Any, expected: Any) -> bool:
    """Lenient equality: numbers compare numerically, strings case-insensitively."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        # Collectors sometimes report booleans as 0/1 or "true"/"false".
        left, right = _truthy(actual), _truthy(expected)
        return left is not None and left == right
    if _is_number(actual) and _is_number(expected):
        return _as_number(actual) == _as_number(expected)
    return str(actual).casefold() == str(expected).casefold()


def _truthy(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value).casefold()
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list | tuple):
        return list(value)
    return [value]


def _member(item: Any, collection: Sequence[Any]) -> bool:
    return any(_equals(item, candidate) for candidate in collection)


def _mode_at_most(actual: Any, maximum: Any) -> bool:
    """True when the permission bits of ``actual`` are a subset of ``maximum`` (octal strings)."""
    return int(str(actual), 8) & ~int(str(maximum), 8) & 0o7777 == 0


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str):
        return str(expected).casefold() in actual.casefold()
    return _member(expected, _as_list(actual))


Operator = Callable[[Any, Any], bool]

OPERATORS: dict[str, Operator] = {
    "eq": _equals,
    "ne": lambda a, e: not _equals(a, e),
    "gt": lambda a, e: _as_number(a) > _as_number(e),
    "gte": lambda a, e: _as_number(a) >= _as_number(e),
    "lt": lambda a, e: _as_number(a) < _as_number(e),
    "lte": lambda a, e: _as_number(a) <= _as_number(e),
    "in": _member,
    "not_in": lambda a, e: not _member(a, e),
    "contains": _contains,
    "not_contains": lambda a, e: not _contains(a, e),
    "contains_all": lambda a, e: all(_member(item, _as_list(a)) for item in e),
    "none_of": lambda a, e: not any(_member(item, e) for item in _as_list(a)),
    "subset_of": lambda a, e: all(_member(item, e) for item in _as_list(a)),
    "max_items": lambda a, e: len(_as_list(a)) <= int(e),
    "regex": lambda a, e: re.search(str(e), str(a), re.IGNORECASE) is not None,
    "not_regex": lambda a, e: re.search(str(e), str(a), re.IGNORECASE) is None,
    "mode_at_most": _mode_at_most,
}

# Operators that test presence and take no value.
PRESENCE_OPERATORS = frozenset({"exists", "absent"})
LIST_VALUE_OPERATORS = frozenset({"in", "not_in", "contains_all", "none_of", "subset_of"})
MISSING_POLICIES = frozenset({"pass", "fail", "unknown"})
_LEAF_KEYS = frozenset({"fact", "op", "value", "default", "missing"})


def validate(condition: Any, where: str = "check") -> None:
    """Raise ConditionError if ``condition`` does not follow the grammar."""
    if not isinstance(condition, Mapping) or not condition:
        raise ConditionError(f"{where}: a condition must be a non-empty mapping")
    combinators = [key for key in ("all", "any", "not") if key in condition]
    if combinators:
        if len(condition) != 1:
            raise ConditionError(f"{where}: '{combinators[0]}' must be the only key of its mapping")
        key = combinators[0]
        if key == "not":
            validate(condition["not"], f"{where}.not")
            return
        children = condition[key]
        if not isinstance(children, list) or not children:
            raise ConditionError(f"{where}.{key}: expected a non-empty list of conditions")
        for index, child in enumerate(children):
            validate(child, f"{where}.{key}[{index}]")
        return

    unknown_keys = set(condition) - _LEAF_KEYS
    if unknown_keys:
        raise ConditionError(f"{where}: unknown key(s) {sorted(unknown_keys)}")
    fact, op = condition.get("fact"), condition.get("op")
    if not isinstance(fact, str) or not fact:
        raise ConditionError(f"{where}: 'fact' must be a non-empty string")
    if op not in OPERATORS and op not in PRESENCE_OPERATORS:
        raise ConditionError(f"{where}: unknown operator {op!r}")
    if op in PRESENCE_OPERATORS:
        if "value" in condition:
            raise ConditionError(f"{where}: '{op}' takes no value")
    elif "value" not in condition:
        raise ConditionError(f"{where}: operator '{op}' needs a value")
    value = condition.get("value")
    if op in LIST_VALUE_OPERATORS and not isinstance(value, list):
        raise ConditionError(f"{where}: operator '{op}' needs a list value")
    if op in {"regex", "not_regex"}:
        try:
            re.compile(str(value))
        except re.error as exc:
            raise ConditionError(f"{where}: invalid regex: {exc}") from exc
    if op == "mode_at_most":
        try:
            int(str(value), 8)
        except ValueError as exc:
            raise ConditionError(f"{where}: mode_at_most needs an octal string such as '0644'") from exc
    missing = condition.get("missing", "unknown")
    if missing not in MISSING_POLICIES:
        raise ConditionError(f"{where}: 'missing' must be one of {sorted(MISSING_POLICIES)}")


def facts_used(condition: Mapping[str, Any]) -> set[str]:
    """Every fact name a condition reads."""
    if "all" in condition or "any" in condition:
        children = condition.get("all") or condition.get("any") or []
        return set().union(*(facts_used(child) for child in children))
    if "not" in condition:
        return facts_used(condition["not"])
    return {str(condition["fact"])}


def _evaluate_leaf(condition: Mapping[str, Any], facts: Mapping[str, Any]) -> ConditionDetail:
    fact, op = str(condition["fact"]), str(condition["op"])
    expected = condition.get("value")
    actual = facts.get(fact, _MISSING)
    if actual is None:
        actual = _MISSING

    if op in PRESENCE_OPERATORS:
        present = actual is not _MISSING
        passed = present if op == "exists" else not present
        return ConditionDetail(
            fact, op, None, None if actual is _MISSING else actual, Outcome.PASS if passed else Outcome.FAIL
        )

    note = ""
    if actual is _MISSING:
        if "default" in condition:
            actual = condition["default"]
            note = "not set, using the documented default"
        else:
            policy = Outcome(condition.get("missing", "unknown"))
            note = "fact not collected" if policy is Outcome.UNKNOWN else "not set"
            return ConditionDetail(fact, op, expected, None, policy, note)

    try:
        passed = OPERATORS[op](actual, expected)
    except (TypeError, ValueError) as exc:
        return ConditionDetail(fact, op, expected, actual, Outcome.UNKNOWN, f"cannot compare: {exc}")
    return ConditionDetail(fact, op, expected, actual, Outcome.PASS if passed else Outcome.FAIL, note)


def evaluate(condition: Mapping[str, Any], facts: Mapping[str, Any]) -> tuple[Outcome, list[ConditionDetail]]:
    """Evaluate a validated condition against collected facts."""
    if "not" in condition:
        outcome, inner = evaluate(condition["not"], facts)
        flipped = {Outcome.PASS: Outcome.FAIL, Outcome.FAIL: Outcome.PASS}.get(outcome, outcome)
        return flipped, inner
    if "all" in condition or "any" in condition:
        is_all = "all" in condition
        outcomes: list[Outcome] = []
        details: list[ConditionDetail] = []
        for child in condition["all" if is_all else "any"]:
            outcome, child_details = evaluate(child, facts)
            outcomes.append(outcome)
            details.extend(child_details)
        decisive, other = (Outcome.FAIL, Outcome.PASS) if is_all else (Outcome.PASS, Outcome.FAIL)
        if decisive in outcomes:
            return decisive, details
        if Outcome.UNKNOWN in outcomes:
            return Outcome.UNKNOWN, details
        return other, details
    detail = _evaluate_leaf(condition, facts)
    return detail.outcome, [detail]
