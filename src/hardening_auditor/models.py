"""Core data types shared by the catalogue, the engine and the reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        """Weight of a control of this severity in the compliance score."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]

    @property
    def rank(self) -> int:
        """Sort key: the most severe first."""
        return -self.weight


class Status(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ACCEPTED = "accepted"  # failed, but covered by a valid exception
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"  # a required fact was not collected


class Outcome(StrEnum):
    """Three-valued result of a condition (Kleene logic)."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Remediation:
    summary: str
    command: str | None = None
    gpo: str | None = None
    impact: str | None = None


@dataclass(frozen=True, slots=True)
class References:
    cis: tuple[str, ...] = ()
    anssi: tuple[int, ...] = ()
    other: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    platform: str
    category: str
    severity: Severity
    rationale: str
    references: References
    check: dict[str, Any]
    remediation: Remediation
    applies_if: dict[str, Any] | None = None
    source: str = ""


@dataclass(frozen=True, slots=True)
class HostInfo:
    hostname: str
    os_family: str
    os_name: str = ""
    os_version: str = ""
    collected_at: str = ""
    elevated: bool | None = None


@dataclass(frozen=True, slots=True)
class FactsDocument:
    host: HostInfo
    facts: dict[str, Any]
    collector: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConditionDetail:
    """How one leaf condition was evaluated, kept for the report."""

    fact: str
    op: str
    expected: Any
    actual: Any
    outcome: Outcome
    note: str = ""


@dataclass(frozen=True, slots=True)
class AcceptedRisk:
    """An accepted risk: a failed control that the organisation decided to tolerate."""

    rule_id: str
    justification: str
    expires: date
    approved_by: str = ""
    ticket: str = ""
    hosts: tuple[str, ...] = ("*",)


@dataclass(frozen=True, slots=True)
class RuleResult:
    rule: Rule
    status: Status
    details: tuple[ConditionDetail, ...] = ()
    reason: str = ""
    exception: AcceptedRisk | None = None


@dataclass(frozen=True, slots=True)
class CategoryScore:
    name: str
    score: float | None
    passed: int
    failed: int
    accepted: int
    not_applicable: int
    unknown: int


@dataclass(frozen=True, slots=True)
class AuditResult:
    host: HostInfo
    results: tuple[RuleResult, ...]
    overall_score: float | None
    categories: tuple[CategoryScore, ...]
    warnings: tuple[str, ...] = ()
    expired_exceptions: tuple[AcceptedRisk, ...] = ()
    unused_exceptions: tuple[AcceptedRisk, ...] = ()
    generated_at: str = ""
    catalogue_size: int = 0
