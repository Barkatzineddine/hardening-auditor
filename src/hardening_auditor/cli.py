"""Command-line interface: ``hardening-auditor audit | compare | rules | validate``."""

from __future__ import annotations

import argparse
import io
import json
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Any, TextIO

from . import __version__, compare, report
from .catalog import CatalogError, default_rules_dir, load_catalog
from .engine import audit
from .exceptions import ExceptionsError, load_exceptions
from .facts import FactsError, parse_facts, read_json
from .models import AcceptedRisk, AuditResult, Rule, Severity, Status

EXIT_OK, EXIT_ERROR, EXIT_GATE = 0, 1, 2


class UsageError(Exception):
    """A problem with the inputs, reported without a traceback."""


def _rules(args: argparse.Namespace) -> list[Rule]:
    directories: list[Path] = [] if args.no_default_rules else [default_rules_dir()]
    directories += args.rules or []
    if not directories:
        raise UsageError("--no-default-rules needs at least one --rules directory")
    return load_catalog(directories)


def _risks(args: argparse.Namespace) -> list[AcceptedRisk]:
    return load_exceptions(args.exceptions) if args.exceptions else []


def _audit_file(path: Path, rules: list[Rule], risks: list[AcceptedRisk]) -> AuditResult:
    return audit(parse_facts(read_json(path), str(path)), rules, risks)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _print_summary(result: AuditResult, out: TextIO) -> None:
    counts = report.summary_counts(result)
    host = result.host
    score = "n/a" if result.overall_score is None else f"{result.overall_score}/100"
    print(f"Host     {host.hostname} ({host.os_name or host.os_family})", file=out)
    print(
        f"Score    {score}   pass {counts['pass']}  fail {counts['fail']}  accepted {counts['accepted']}"
        f"  unknown {counts['unknown']}  n/a {counts['not_applicable']}",
        file=out,
    )
    if host.elevated is False:
        print("Warning  collected without administrator/root rights: some controls are unknown", file=out)
    failed = [r for r in result.results if r.status is Status.FAIL]
    if failed:
        print("\nFailed controls:", file=out)
        for r in failed:
            print(f"  {r.rule.severity.value.upper():<8} {r.rule.id:<14} {r.rule.title}", file=out)
    for risk in result.expired_exceptions:
        print(f"\nWarning  exception for {risk.rule_id} expired on {risk.expires}", file=out)
    for risk in result.unused_exceptions:
        print(f"\nNote     exception for {risk.rule_id} is no longer needed on this host", file=out)


def cmd_audit(args: argparse.Namespace) -> int:
    result = _audit_file(args.facts, _rules(args), _risks(args))
    outputs: dict[str, Path | None] = {
        "html": args.html,
        "json": args.json,
        "ndjson": args.ndjson,
        "csv": args.csv,
    }
    if args.out_dir:
        stem = result.host.hostname.lower()
        for fmt, suffix in (("html", "html"), ("json", "json"), ("csv", "csv")):
            outputs[fmt] = outputs[fmt] or args.out_dir / f"{stem}-report.{suffix}"
    writers = {
        "html": report.to_html,
        "json": report.to_json,
        "ndjson": report.to_ndjson,
        "csv": report.to_csv,
    }
    for fmt, path in outputs.items():
        if path is not None:
            _write(path, writers[fmt](result))
    if not args.quiet:
        _print_summary(result, sys.stdout)
        for fmt, path in outputs.items():
            if path is not None:
                print(f"Wrote    {fmt.upper():<6} {path}")

    gate_failures: list[str] = []
    if args.fail_under is not None and (result.overall_score or 0) < args.fail_under:
        gate_failures.append(f"score {result.overall_score} is below {args.fail_under}")
    if args.fail_on:
        threshold = Severity(args.fail_on).weight
        blocking = [
            r for r in result.results if r.status is Status.FAIL and r.rule.severity.weight >= threshold
        ]
        if blocking:
            gate_failures.append(f"{len(blocking)} failed control(s) of severity {args.fail_on} or higher")
    unknown = sum(1 for r in result.results if r.status is Status.UNKNOWN)
    if args.max_unknown is not None and unknown > args.max_unknown:
        names = ", ".join(r.rule.id for r in result.results if r.status is Status.UNKNOWN)
        gate_failures.append(f"{unknown} control(s) could not be evaluated (max {args.max_unknown}): {names}")
    for failure in gate_failures:
        print(f"Gate failed: {failure}", file=sys.stderr)
    return EXIT_GATE if gate_failures else EXIT_OK


def _as_report(path: Path, rules: list[Rule], risks: list[AcceptedRisk]) -> dict[str, Any]:
    """Accept either a report JSON or raw collector facts (evaluated with the current catalogue)."""
    data = read_json(path)
    if isinstance(data, dict) and "facts" in data:
        return report.to_dict(audit(parse_facts(data, str(path)), rules, risks))
    if not isinstance(data, dict):
        raise UsageError(f"{path}: expected a JSON object")
    return data


def cmd_compare(args: argparse.Namespace) -> int:
    rules, risks = _rules(args), _risks(args)
    result = compare.compare(_as_report(args.before, rules, risks), _as_report(args.after, rules, risks))
    render = {"text": compare.to_text, "markdown": compare.to_markdown, "json": compare.to_json}[args.format]
    sys.stdout.write(render(result))
    if args.fail_on_regression and result.regressed:
        print(f"Gate failed: {len(result.regressed)} regression(s)", file=sys.stderr)
        return EXIT_GATE
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    rules = [r for r in _rules(args) if args.platform is None or r.platform == args.platform]
    if args.format == "json":
        data = [
            {
                "id": r.id,
                "title": r.title,
                "platform": r.platform,
                "category": r.category,
                "severity": r.severity.value,
                "cis": list(r.references.cis),
                "anssi": list(r.references.anssi),
            }
            for r in rules
        ]
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return EXIT_OK
    for r in rules:
        print(f"{r.id:<14} {r.severity.value:<8} {r.platform:<8} {r.category:<24} {r.title}")
    print(f"\n{len(rules)} controls")
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    rules = _rules(args)
    by_platform = {p: sum(1 for r in rules if r.platform == p) for p in sorted({r.platform for r in rules})}
    print(f"Catalogue OK: {len(rules)} rules " + ", ".join(f"{p} {n}" for p, n in by_platform.items()))
    if args.exceptions:
        risks = _risks(args)
        known = {r.id for r in rules}
        unknown_ids = sorted({risk.rule_id for risk in risks} - known)
        if unknown_ids:
            raise UsageError(f"{args.exceptions}: exceptions reference unknown rules {unknown_ids}")
        expired = [risk for risk in risks if risk.expires < date.today()]
        print(f"Exceptions OK: {len(risks)} entries, {len(expired)} expired")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardening-auditor",
        description="Evaluate collector output against CIS Benchmark and ANSSI hygiene controls.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def catalogue_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--rules", type=Path, action="append", metavar="DIR", help="extra rules directory")
        p.add_argument("--no-default-rules", action="store_true", help="do not load the built-in catalogue")
        p.add_argument("--exceptions", type=Path, metavar="FILE", help="accepted-risk exceptions (YAML)")

    p_audit = sub.add_parser("audit", help="evaluate a collector JSON file and write reports")
    p_audit.add_argument("facts", type=Path, help="JSON produced by a collector")
    catalogue_options(p_audit)
    p_audit.add_argument("--html", type=Path, metavar="FILE")
    p_audit.add_argument("--json", type=Path, metavar="FILE")
    p_audit.add_argument("--ndjson", type=Path, metavar="FILE", help="one event per control, for a SIEM")
    p_audit.add_argument("--csv", type=Path, metavar="FILE")
    p_audit.add_argument("--out-dir", type=Path, metavar="DIR", help="write HTML, JSON and CSV reports here")
    p_audit.add_argument("--fail-under", type=float, metavar="SCORE", help="exit 2 if the score is lower")
    p_audit.add_argument("--fail-on", choices=[s.value for s in Severity], help="exit 2 on a failed control")
    p_audit.add_argument("--max-unknown", type=int, metavar="N", help="exit 2 if more controls are unknown")
    p_audit.add_argument("-q", "--quiet", action="store_true")
    p_audit.set_defaults(func=cmd_audit)

    p_cmp = sub.add_parser("compare", help="show progress between two audits (reports or collector files)")
    p_cmp.add_argument("before", type=Path)
    p_cmp.add_argument("after", type=Path)
    catalogue_options(p_cmp)
    p_cmp.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    p_cmp.add_argument("--fail-on-regression", action="store_true", help="exit 2 if a control regressed")
    p_cmp.set_defaults(func=cmd_compare)

    p_rules = sub.add_parser("rules", help="list the controls of the catalogue")
    catalogue_options(p_rules)
    p_rules.add_argument("--platform", choices=["windows", "linux"])
    p_rules.add_argument("--format", choices=["table", "json"], default="table")
    p_rules.set_defaults(func=cmd_rules)

    p_val = sub.add_parser("validate", help="validate the catalogue and an exceptions file")
    catalogue_options(p_val)
    p_val.set_defaults(func=cmd_validate)
    return parser


def _utf8_output() -> None:
    """Write UTF-8 when output is redirected on Windows, where the default code page is cp1252."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper) and stream.encoding.lower().replace("-", "") != "utf8":
            stream.reconfigure(encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    _utf8_output()
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (CatalogError, FactsError, ExceptionsError, compare.CompareError, UsageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
