from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from hardening_auditor.catalog import CatalogError, default_rules_dir, load_catalog, parse_rule
from hardening_auditor.conditions import facts_used
from hardening_auditor.models import Rule

VALID: dict[str, Any] = {
    "id": "WIN-TEST-001",
    "title": "Test control",
    "platform": "windows",
    "category": "Tests",
    "severity": "low",
    "rationale": "Because.",
    "references": {"cis": ["Ensure something"], "anssi": [10]},
    "check": {"fact": "a", "op": "eq", "value": 1},
    "remediation": {"summary": "Fix it."},
}


def test_builtin_catalogue_size_and_balance(catalog: list[Rule]) -> None:
    platforms = Counter(rule.platform for rule in catalog)
    assert len(catalog) >= 60
    assert platforms["windows"] >= 30
    assert platforms["linux"] >= 30


def test_every_rule_is_documented(catalog: list[Rule]) -> None:
    for rule in catalog:
        assert rule.references.cis or rule.references.anssi, rule.id
        assert rule.remediation.summary, rule.id
        assert rule.rationale.endswith("."), rule.id
        assert rule.id.startswith({"windows": "WIN-", "linux": "LNX-"}[rule.platform]), rule.id


def test_rule_ids_are_unique_and_match_file_names(catalog: list[Rule]) -> None:
    assert len({rule.id for rule in catalog}) == len(catalog)
    for rule in catalog:
        assert Path(rule.source).stem == rule.id


def test_platform_filter() -> None:
    linux = load_catalog(platform="linux")
    assert linux
    assert all(rule.platform == "linux" for rule in linux)


def test_rules_only_use_facts_the_collectors_emit(catalog: list[Rule]) -> None:
    """Every fact a rule reads must appear in a collector, so a typo cannot hide a control."""
    root = Path(__file__).resolve().parents[1] / "collectors"
    sources = {
        "windows": (root / "windows" / "Invoke-HardeningCollector.ps1").read_text(encoding="utf-8"),
        "linux": (root / "linux" / "collect.sh").read_text(encoding="utf-8"),
    }
    for rule in catalog:
        conditions = [rule.check] + ([rule.applies_if] if rule.applies_if else [])
        for condition in conditions:
            for fact in facts_used(condition):
                leaf = fact.rsplit(".", 1)[-1]
                assert leaf in sources[rule.platform], f"{rule.id}: {fact} is not collected"


def test_parse_valid_rule() -> None:
    rule = parse_rule(VALID)
    assert rule.id == "WIN-TEST-001"
    assert rule.applies_if is None
    assert rule.references.anssi == (10,)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"id": "win-test"}, "must look like"),
        ({"platform": "macos"}, "platform"),
        ({"severity": "urgent"}, "severity"),
        ({"title": ""}, "'title'"),
        ({"references": {}}, "references"),
        ({"references": {"nist": ["x"]}}, "only cis, anssi"),
        ({"references": {"anssi": [99]}}, "between 1 and 42"),
        ({"references": {"other": ["x"]}}, "at least one CIS or ANSSI"),
        ({"remediation": "fix"}, "'remediation' must be a mapping"),
        ({"remediation": {"summary": "x", "url": "y"}}, "remediation accepts"),
        ({"remediation": {"summary": "x", "command": 3}}, "'command' must be a string"),
        ({"check": {"fact": "a", "op": "nope", "value": 1}}, "unknown operator"),
        ({"applies_if": {"all": []}}, "non-empty list"),
        ({"owner": "me"}, "unknown field"),
    ],
)
def test_invalid_rules(change: dict[str, Any], message: str) -> None:
    with pytest.raises(CatalogError, match=message):
        parse_rule({**VALID, **change})


def test_missing_fields_and_wrong_type() -> None:
    with pytest.raises(CatalogError, match="missing field"):
        parse_rule({"id": "WIN-TEST-001"})
    with pytest.raises(CatalogError, match="must contain a mapping"):
        parse_rule(["not", "a", "mapping"])


def _write(directory: Path, name: str, data: Any) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_custom_rules_directory(tmp_path: Path) -> None:
    _write(tmp_path / "custom", "WIN-TEST-001.yml", VALID)
    rules = load_catalog([default_rules_dir(), tmp_path / "custom"])
    assert "WIN-TEST-001" in {rule.id for rule in rules}


def test_file_name_must_match_id(tmp_path: Path) -> None:
    _write(tmp_path, "WIN-OTHER-001.yml", VALID)
    with pytest.raises(CatalogError, match="file name must match"):
        load_catalog([tmp_path])


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path / "a", "WIN-TEST-001.yml", VALID)
    _write(tmp_path / "b", "WIN-TEST-001.yml", VALID)
    with pytest.raises(CatalogError, match="duplicate rule id"):
        load_catalog([tmp_path])


def test_invalid_yaml_and_missing_directory(tmp_path: Path) -> None:
    (tmp_path / "WIN-TEST-001.yml").write_text("id: [unclosed", encoding="utf-8")
    with pytest.raises(CatalogError, match="invalid YAML"):
        load_catalog([tmp_path])
    with pytest.raises(CatalogError, match="not found"):
        load_catalog([tmp_path / "missing"])
