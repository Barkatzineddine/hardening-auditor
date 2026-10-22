"""Reading the JSON document produced by a collector."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .catalog import PLATFORMS
from .models import FactsDocument, HostInfo

SCHEMA_VERSION = 1


class FactsError(ValueError):
    """The collector output cannot be used."""


def read_json(path: Path) -> Any:
    """Read JSON written by any collector (Windows PowerShell 5.1 adds a UTF-8 BOM)."""
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FactsError(f"{path}: cannot read JSON: {exc}") from exc


def parse_facts(data: Any, source: str = "<memory>") -> FactsDocument:
    if not isinstance(data, Mapping):
        raise FactsError(f"{source}: expected a JSON object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise FactsError(f"{source}: unsupported schema_version {data.get('schema_version')!r}")
    host, facts = data.get("host"), data.get("facts")
    if not isinstance(host, Mapping) or not isinstance(facts, Mapping):
        raise FactsError(f"{source}: 'host' and 'facts' must be objects")
    hostname, family = host.get("hostname"), host.get("os_family")
    if not isinstance(hostname, str) or not hostname:
        raise FactsError(f"{source}: host.hostname is required")
    if family not in PLATFORMS:
        raise FactsError(f"{source}: host.os_family must be one of {sorted(PLATFORMS)}")
    elevated = host.get("elevated")
    warnings = data.get("warnings") or []
    if not isinstance(warnings, list):
        raise FactsError(f"{source}: 'warnings' must be a list")
    return FactsDocument(
        host=HostInfo(
            hostname=hostname,
            os_family=str(family),
            os_name=str(host.get("os_name") or ""),
            os_version=str(host.get("os_version") or ""),
            collected_at=str(host.get("collected_at") or ""),
            elevated=elevated if isinstance(elevated, bool) else None,
        ),
        facts=dict(facts),
        collector=dict(data.get("collector") or {}),
        warnings=tuple(str(item) for item in warnings),
    )


def load_facts(path: Path) -> FactsDocument:
    return parse_facts(read_json(path), str(path))
