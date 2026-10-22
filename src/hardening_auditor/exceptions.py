"""Accepted-risk exceptions: a failed control tolerated with a justification and an expiry date.

Example ``exceptions.yml``::

    exceptions:
      - rule: LNX-SSH-001
        hosts: ["bastion-*"]
        justification: Break-glass access while the PAM bastion is being deployed.
        approved_by: RSSI
        ticket: SEC-142
        expires: 2027-03-31
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from .catalog import RULE_ID
from .models import AcceptedRisk

_FIELDS = frozenset({"rule", "hosts", "justification", "approved_by", "ticket", "expires"})


class ExceptionsError(ValueError):
    """The exceptions file is invalid."""


def parse_exceptions(data: Any, source: str = "<memory>") -> list[AcceptedRisk]:
    if data is None:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("exceptions"), list):
        raise ExceptionsError(f"{source}: expected a top-level 'exceptions' list")
    accepted: list[AcceptedRisk] = []
    for index, entry in enumerate(data["exceptions"]):
        where = f"{source}: exceptions[{index}]"
        if not isinstance(entry, dict):
            raise ExceptionsError(f"{where}: must be a mapping")
        unknown = set(entry) - _FIELDS
        if unknown:
            raise ExceptionsError(f"{where}: unknown field(s) {sorted(unknown)}")
        rule_id = entry.get("rule")
        if not isinstance(rule_id, str) or not RULE_ID.match(rule_id):
            raise ExceptionsError(f"{where}: 'rule' must be a rule id such as WIN-NET-001")
        justification = entry.get("justification")
        if not isinstance(justification, str) or len(justification.strip()) < 10:
            raise ExceptionsError(f"{where}: a justification of at least 10 characters is required")
        expires = entry.get("expires")
        if not isinstance(expires, date):
            raise ExceptionsError(f"{where}: 'expires' must be a date (YYYY-MM-DD)")
        hosts = entry.get("hosts", ["*"])
        if isinstance(hosts, str):
            hosts = [hosts]
        if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) and h for h in hosts):
            raise ExceptionsError(f"{where}: 'hosts' must be a list of host name patterns")
        accepted.append(
            AcceptedRisk(
                rule_id=rule_id,
                justification=" ".join(justification.split()),
                expires=expires,
                approved_by=str(entry.get("approved_by") or ""),
                ticket=str(entry.get("ticket") or ""),
                hosts=tuple(hosts),
            )
        )
    return accepted


def load_exceptions(path: Path) -> list[AcceptedRisk]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ExceptionsError(f"{path}: cannot read exceptions: {exc}") from exc
    return parse_exceptions(data, str(path))


def matches_host(risk: AcceptedRisk, hostname: str) -> bool:
    return any(fnmatch.fnmatchcase(hostname.casefold(), pattern.casefold()) for pattern in risk.hosts)


def for_host(risks: Iterable[AcceptedRisk], hostname: str) -> list[AcceptedRisk]:
    return [risk for risk in risks if matches_host(risk, hostname)]


def is_active(risk: AcceptedRisk, today: date) -> bool:
    return risk.expires >= today
