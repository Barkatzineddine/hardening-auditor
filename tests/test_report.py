from __future__ import annotations

import base64
import csv
import hashlib
import html as html_lib
import io
import json
import re
from datetime import date

from hardening_auditor import report
from hardening_auditor.engine import audit
from hardening_auditor.facts import parse_facts
from hardening_auditor.models import AcceptedRisk, AuditResult, Rule
from tests.conftest import fixture_data, fixture_document

TODAY = date(2026, 10, 20)


def _audit(catalog: list[Rule], name: str = "windows-noncompliant") -> AuditResult:
    risks = [AcceptedRisk("WIN-SVC-001", "Print server for the accounting floor.", date(2027, 1, 31), "RSSI")]
    return audit(fixture_document(name), catalog, risks, today=TODAY)


def test_json_report_structure(catalog: list[Rule]) -> None:
    data = json.loads(report.to_json(_audit(catalog)))
    assert data["schema_version"] == 1
    assert data["host"]["hostname"] == "SRV-LEGACY02"
    assert data["summary"]["fail"] == 34
    assert data["summary"]["accepted"] == 1
    accepted = next(r for r in data["results"] if r["status"] == "accepted")
    assert accepted["exception"]["approved_by"] == "RSSI"
    smb = next(r for r in data["results"] if r["id"] == "WIN-NET-001")
    assert smb["references"]["anssi"][0]["measure"] == 21
    assert smb["details"][0] == {
        "fact": "smb.server.require_signing",
        "op": "eq",
        "expected": 1,
        "actual": 0,
        "outcome": "fail",
        "note": "",
    }


def test_ndjson_has_one_event_per_control(catalog: list[Rule]) -> None:
    result = _audit(catalog)
    lines = report.to_ndjson(result).splitlines()
    assert len(lines) == len(result.results)
    event = json.loads(lines[0])
    assert event["event_type"] == "hardening_audit"
    assert event["host"] == "SRV-LEGACY02"


def test_csv_report_and_formula_injection(catalog: list[Rule]) -> None:
    data = fixture_data("linux-noncompliant")
    data["host"]["hostname"] = "=HYPERLINK(evil)"
    result = audit(parse_facts(data), catalog, today=TODAY)
    rows = list(csv.reader(io.StringIO(report.to_csv(result))))
    assert tuple(rows[0]) == report.CSV_COLUMNS
    assert len(rows) == len(result.results) + 1
    assert rows[1][0] == "'=HYPERLINK(evil)"


def _hash(content: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(content.encode()).digest()).decode() + "'"


def test_html_report_is_offline_and_escaped(catalog: list[Rule]) -> None:
    data = fixture_data("windows-noncompliant")
    data["host"]["hostname"] = "<script>alert(1)</script>"
    data["facts"]["network.netbios.enabled_adapters"] = ['<img src=x onerror="alert(1)">']
    html = report.to_html(audit(parse_facts(data), catalog, today=TODAY))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html
    # Only inline resources, each allowed by its hash; no network access is permitted.
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    assert csp is not None
    policy = html_lib.unescape(csp.group(1))
    assert "default-src 'none'" in policy
    script = re.search(r"<script>(.*?)</script>\s*</body>", html, re.DOTALL)
    style = re.search(r"<style>(.*?)</style>", html, re.DOTALL)
    assert script is not None and style is not None
    assert _hash(script.group(1)) in policy
    assert _hash(style.group(1)) in policy
    assert not re.search(r'(src|href)="https?:', html)


def test_html_report_sections(catalog: list[Rule]) -> None:
    html = report.to_html(_audit(catalog))
    assert "Failed controls" in html
    assert 'id="accepted-title"' in html
    assert "Print server for the accounting floor." in html
    assert html.count('class="finding"') == 34
    clean = report.to_html(audit(fixture_document("linux-compliant"), catalog, today=TODAY))
    assert "No failed control." in clean
    assert 'id="accepted-title"' not in clean


def test_html_warns_about_unprivileged_collection(catalog: list[Rule]) -> None:
    data = fixture_data("linux-compliant")
    data["host"]["elevated"] = False
    data["warnings"] = ["Not running as root"]
    html = report.to_html(audit(parse_facts(data), catalog, today=TODAY))
    assert "did not run with administrator/root rights" in html
    assert "Collector: Not running as root" in html


def test_html_lists_unused_exceptions(catalog: list[Rule]) -> None:
    risks = [AcceptedRisk("LNX-SSH-001", "Bastion while PAM is rolled out.", date(2027, 1, 31))]
    html = report.to_html(audit(fixture_document("linux-compliant"), catalog, risks, today=TODAY))
    assert "<b>LNX-SSH-001</b> is no longer needed" in html
