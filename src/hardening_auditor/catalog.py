"""Loading and validation of the YAML rule catalogue (one file per control)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from . import conditions
from .models import References, Remediation, Rule, Severity
from .references import ANSSI_MEASURES

PLATFORMS = frozenset({"windows", "linux"})
RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")
_REQUIRED = (
    "id",
    "title",
    "platform",
    "category",
    "severity",
    "rationale",
    "references",
    "check",
    "remediation",
)
_ALLOWED = frozenset((*_REQUIRED, "applies_if"))


class CatalogError(ValueError):
    """A rule file is invalid. The message names the file and the problem."""


def default_rules_dir() -> Path:
    """The catalogue shipped with the package."""
    return Path(str(resources.files("hardening_auditor") / "rules"))


def _text(data: Mapping[str, Any], key: str, where: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{where}: '{key}' must be a non-empty string")
    return value.strip()


def _optional_text(data: Mapping[str, Any], key: str, where: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise CatalogError(f"{where}: '{key}' must be a string")
    return value.strip() or None


def parse_rule(data: Any, source: str = "<memory>") -> Rule:
    """Build a Rule from a parsed YAML document, validating every field."""
    if not isinstance(data, Mapping):
        raise CatalogError(f"{source}: a rule file must contain a mapping")
    missing = [key for key in _REQUIRED if key not in data]
    if missing:
        raise CatalogError(f"{source}: missing field(s) {missing}")
    unknown = set(data) - _ALLOWED
    if unknown:
        raise CatalogError(f"{source}: unknown field(s) {sorted(unknown)}")

    rule_id = _text(data, "id", source)
    if not RULE_ID.match(rule_id):
        raise CatalogError(f"{source}: id {rule_id!r} must look like WIN-NET-001")
    platform = _text(data, "platform", source)
    if platform not in PLATFORMS:
        raise CatalogError(f"{source}: platform must be one of {sorted(PLATFORMS)}")
    try:
        severity = Severity(_text(data, "severity", source))
    except ValueError as exc:
        raise CatalogError(f"{source}: severity must be one of {[s.value for s in Severity]}") from exc

    refs = data["references"]
    if not isinstance(refs, Mapping) or not refs:
        raise CatalogError(f"{source}: 'references' must map cis/anssi/other to lists")
    if set(refs) - {"cis", "anssi", "other"}:
        raise CatalogError(f"{source}: references accept only cis, anssi and other")
    anssi = tuple(refs.get("anssi") or ())
    if any(not isinstance(m, int) or m not in ANSSI_MEASURES for m in anssi):
        raise CatalogError(f"{source}: anssi references must be measure numbers between 1 and 42")
    references = References(
        cis=tuple(str(item) for item in refs.get("cis") or ()),
        anssi=anssi,
        other=tuple(str(item) for item in refs.get("other") or ()),
    )
    if not references.cis and not references.anssi:
        raise CatalogError(f"{source}: cite at least one CIS or ANSSI reference")

    remediation_data = data["remediation"]
    if not isinstance(remediation_data, Mapping):
        raise CatalogError(f"{source}: 'remediation' must be a mapping")
    if set(remediation_data) - {"summary", "command", "gpo", "impact"}:
        raise CatalogError(f"{source}: remediation accepts summary, command, gpo and impact")
    remediation = Remediation(
        summary=_text(remediation_data, "summary", f"{source} remediation"),
        command=_optional_text(remediation_data, "command", f"{source} remediation"),
        gpo=_optional_text(remediation_data, "gpo", f"{source} remediation"),
        impact=_optional_text(remediation_data, "impact", f"{source} remediation"),
    )

    try:
        conditions.validate(data["check"], "check")
        if data.get("applies_if") is not None:
            conditions.validate(data["applies_if"], "applies_if")
    except conditions.ConditionError as exc:
        raise CatalogError(f"{source}: {exc}") from exc

    return Rule(
        id=rule_id,
        title=_text(data, "title", source),
        platform=platform,
        category=_text(data, "category", source),
        severity=severity,
        rationale=" ".join(_text(data, "rationale", source).split()),
        references=references,
        check=dict(data["check"]),
        applies_if=dict(data["applies_if"]) if data.get("applies_if") else None,
        remediation=remediation,
        source=source,
    )


def load_rule_file(path: Path) -> Rule:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CatalogError(f"{path}: invalid YAML: {exc}") from exc
    rule = parse_rule(data, str(path))
    if path.stem != rule.id:
        raise CatalogError(f"{path}: file name must match the rule id ({rule.id}.yml)")
    return rule


def load_catalog(directories: Iterable[Path] | None = None, platform: str | None = None) -> list[Rule]:
    """Load every ``*.yml`` rule under the given directories (the built-in catalogue by default)."""
    rules: dict[str, Rule] = {}
    for directory in directories or [default_rules_dir()]:
        if not directory.is_dir():
            raise CatalogError(f"{directory}: rules directory not found")
        for path in sorted(directory.rglob("*.yml")):
            rule = load_rule_file(path)
            if rule.id in rules:
                raise CatalogError(f"{path}: duplicate rule id {rule.id} (also in {rules[rule.id].source})")
            rules[rule.id] = rule
    selected = [rule for rule in rules.values() if platform is None or rule.platform == platform]
    return sorted(selected, key=lambda rule: rule.id)
