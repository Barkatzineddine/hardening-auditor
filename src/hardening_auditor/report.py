"""Report writers: JSON (SIEM, diff), NDJSON (one event per control), CSV and a self-contained HTML page."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from importlib import resources
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from . import __version__
from .engine import format_value
from .models import AcceptedRisk, AuditResult, RuleResult, Severity, Status
from .references import ANSSI_GUIDE, anssi_label

RESULTS_SCHEMA_VERSION = 1


def _risk_dict(risk: AcceptedRisk) -> dict[str, Any]:
    return {
        "rule": risk.rule_id,
        "hosts": list(risk.hosts),
        "justification": risk.justification,
        "approved_by": risk.approved_by,
        "ticket": risk.ticket,
        "expires": risk.expires.isoformat(),
    }


def _result_dict(result: RuleResult) -> dict[str, Any]:
    rule = result.rule
    return {
        "id": rule.id,
        "title": rule.title,
        "platform": rule.platform,
        "category": rule.category,
        "severity": rule.severity.value,
        "status": result.status.value,
        "reason": result.reason,
        "rationale": rule.rationale,
        "references": {
            "cis": list(rule.references.cis),
            "anssi": [{"measure": m, "title": anssi_label(m)} for m in rule.references.anssi],
            "other": list(rule.references.other),
        },
        "remediation": {
            "summary": rule.remediation.summary,
            "command": rule.remediation.command,
            "gpo": rule.remediation.gpo,
            "impact": rule.remediation.impact,
        },
        "details": [
            {
                "fact": d.fact,
                "op": d.op,
                "expected": d.expected,
                "actual": d.actual,
                "outcome": d.outcome.value,
                "note": d.note,
            }
            for d in result.details
        ],
        "exception": _risk_dict(result.exception) if result.exception else None,
    }


def summary_counts(audit: AuditResult) -> dict[str, int]:
    counts = {status.value: 0 for status in Status}
    for result in audit.results:
        counts[result.status.value] += 1
    return counts


def to_dict(audit: AuditResult) -> dict[str, Any]:
    host = audit.host
    return {
        "schema_version": RESULTS_SCHEMA_VERSION,
        "tool": {"name": "hardening-auditor", "version": __version__},
        "generated_at": audit.generated_at,
        "host": {
            "hostname": host.hostname,
            "os_family": host.os_family,
            "os_name": host.os_name,
            "os_version": host.os_version,
            "collected_at": host.collected_at,
            "elevated": host.elevated,
        },
        "score": {
            "overall": audit.overall_score,
            "categories": [
                {
                    "name": c.name,
                    "score": c.score,
                    "pass": c.passed,
                    "fail": c.failed,
                    "accepted": c.accepted,
                    "not_applicable": c.not_applicable,
                    "unknown": c.unknown,
                }
                for c in audit.categories
            ],
        },
        "summary": summary_counts(audit),
        "results": [_result_dict(r) for r in audit.results],
        "warnings": list(audit.warnings),
        "exceptions": {
            "expired": [_risk_dict(r) for r in audit.expired_exceptions],
            "unused": [_risk_dict(r) for r in audit.unused_exceptions],
        },
    }


def to_json(audit: AuditResult) -> str:
    return json.dumps(to_dict(audit), indent=2, ensure_ascii=False) + "\n"


def to_ndjson(audit: AuditResult) -> str:
    """One flat event per control, for SIEM ingestion (Wazuh, Elastic, Splunk...)."""
    lines = []
    for result in audit.results:
        event = {
            "timestamp": audit.generated_at,
            "event_type": "hardening_audit",
            "host": audit.host.hostname,
            "os_family": audit.host.os_family,
            "rule_id": result.rule.id,
            "title": result.rule.title,
            "category": result.rule.category,
            "severity": result.rule.severity.value,
            "status": result.status.value,
            "reason": result.reason,
            "cis": list(result.rule.references.cis),
            "anssi": list(result.rule.references.anssi),
            "host_score": audit.overall_score,
        }
        lines.append(json.dumps(event, ensure_ascii=False))
    return "\n".join(lines) + "\n"


CSV_COLUMNS = (
    "hostname",
    "rule_id",
    "title",
    "category",
    "severity",
    "status",
    "observed",
    "cis",
    "anssi",
    "remediation",
    "exception_justification",
    "exception_expires",
)


def _csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection (CWE-1236)."""
    return "'" + value if value[:1] in {"=", "+", "-", "@", "\t", "\r"} else value


def to_csv(audit: AuditResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for result in audit.results:
        rule = result.rule
        row = [
            audit.host.hostname,
            rule.id,
            rule.title,
            rule.category,
            rule.severity.value,
            result.status.value,
            result.reason,
            " | ".join(rule.references.cis),
            " ".join(str(m) for m in rule.references.anssi),
            rule.remediation.summary,
            result.exception.justification if result.exception else "",
            result.exception.expires.isoformat() if result.exception else "",
        ]
        writer.writerow([_csv_safe(str(cell)) for cell in row])
    return buffer.getvalue()


def _asset(name: str) -> str:
    return (resources.files("hardening_auditor") / "templates" / name).read_text(encoding="utf-8")


def _csp_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("hardening_auditor", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["value"] = format_value
    env.filters["anssi"] = anssi_label
    return env


def to_html(audit: AuditResult) -> str:
    """A single offline HTML file: no external resources, and a CSP that blocks every network request."""
    style, script = _asset("report.css"), _asset("report.js")
    failed = [r for r in audit.results if r.status is Status.FAIL]
    accepted = [r for r in audit.results if r.status is Status.ACCEPTED]
    unknown = [r for r in audit.results if r.status is Status.UNKNOWN]
    severity_counts = {s.value: sum(1 for r in failed if r.rule.severity is s) for s in Severity}
    template = _environment().get_template("report.html.j2")
    return template.render(
        audit=audit,
        version=__version__,
        counts=summary_counts(audit),
        failed=failed,
        accepted=accepted,
        unknown=unknown,
        severity_counts=severity_counts,
        severities=[s.value for s in Severity],
        statuses=[s.value for s in Status],
        categories=[c.name for c in audit.categories],
        anssi_guide=ANSSI_GUIDE,
        style=style,
        script=script,
        csp=f"default-src 'none'; style-src {_csp_hash(style)}; script-src {_csp_hash(script)}; "
        "img-src data:; base-uri 'none'; form-action 'none'",
    )
