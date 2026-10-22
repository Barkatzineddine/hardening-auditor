from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hardening_auditor.catalog import load_catalog
from hardening_auditor.facts import parse_facts
from hardening_auditor.models import FactsDocument, Rule

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_data(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return data


def fixture_document(name: str) -> FactsDocument:
    return parse_facts(fixture_data(name), name)


@pytest.fixture(scope="session")
def catalog() -> list[Rule]:
    return load_catalog()
