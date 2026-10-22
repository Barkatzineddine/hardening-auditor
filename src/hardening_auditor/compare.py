"""Progress between two audits of the same host: score delta, fixed controls and regressions."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .models import Severity

_SEVERITY_RANK = {s.value: s.rank for s in Severity}


class CompareError(ValueError):
    """The inputs cannot be compared."""


@dataclass(frozen=True, slots=True)
class Change:
    rule_id: str
    title: str
    severity: str
    before: str | None
    after: str | None


@dataclass(frozen=True, slots=True)
class Comparison:
    host_before: str
    host_after: str
    generated_before: str
    generated_after: str
    score_before: float | None
    score_after: float | None
    categories: list[tuple[str, float | None, float | None]] = field(default_factory=list)
    fixed: list[Change] = field(default_factory=list)
    regressed: list[Change] = field(default_factory=list)
    other_changes: list[Change] = field(default_factory=list)
    still_failing: int = 0

    @property
    def delta(self) -> float | None:
        if self.score_before is None or self.score_after is None:
            return None
        return round(self.score_after - self.score_before, 1)


def _index(results: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {str(item["id"]): item for item in results.get("results", [])}


def _sort(changes: list[Change]) -> list[Change]:
    return sorted(changes, key=lambda c: (_SEVERITY_RANK.get(c.severity, 0), c.rule_id))


def compare(before: Mapping[str, Any], after: Mapping[str, Any]) -> Comparison:
    """Compare two results documents (the JSON report format)."""
    for name, doc in (("first", before), ("second", after)):
        if not isinstance(doc.get("results"), list) or "score" not in doc:
            raise CompareError(f"the {name} file is not an audit report")
    old, new = _index(before), _index(after)
    fixed: list[Change] = []
    regressed: list[Change] = []
    other: list[Change] = []
    still_failing = 0
    for rule_id in sorted(old.keys() | new.keys()):
        a, b = old.get(rule_id), new.get(rule_id)
        ref = b or a
        assert ref is not None  # noqa: S101 - the key comes from one of the two indexes
        status_a = str(a["status"]) if a else None
        status_b = str(b["status"]) if b else None
        if status_a == status_b:
            still_failing += status_a == "fail"
            continue
        change = Change(rule_id, str(ref["title"]), str(ref["severity"]), status_a, status_b)
        if status_b == "pass" and status_a in {"fail", "accepted", "unknown"}:
            fixed.append(change)
        elif status_b == "fail" and status_a != "fail":
            regressed.append(change)
        else:
            other.append(change)

    cats_a = {c["name"]: c.get("score") for c in before["score"].get("categories", [])}
    cats_b = {c["name"]: c.get("score") for c in after["score"].get("categories", [])}
    categories = [
        (name, cats_a.get(name), cats_b.get(name)) for name in sorted(cats_a.keys() | cats_b.keys())
    ]
    return Comparison(
        host_before=str(before.get("host", {}).get("hostname", "")),
        host_after=str(after.get("host", {}).get("hostname", "")),
        generated_before=str(before.get("generated_at", "")),
        generated_after=str(after.get("generated_at", "")),
        score_before=before["score"].get("overall"),
        score_after=after["score"].get("overall"),
        categories=categories,
        fixed=_sort(fixed),
        regressed=_sort(regressed),
        other_changes=_sort(other),
        still_failing=still_failing,
    )


def _fmt(score: float | None) -> str:
    return "n/a" if score is None else f"{score:.1f}"


def _fmt_delta(before: float | None, after: float | None) -> str:
    if before is None or after is None:
        return ""
    delta = after - before
    return f"{delta:+.1f}" if delta else "="


def to_text(comparison: Comparison) -> str:
    c = comparison
    delta = _fmt_delta(c.score_before, c.score_after)
    host = c.host_after if c.host_before == c.host_after else f"{c.host_before} -> {c.host_after}"
    lines = [
        f"Host: {host}",
        f"Audits: {c.generated_before} -> {c.generated_after}",
        f"Score: {_fmt(c.score_before)} -> {_fmt(c.score_after)} ({delta})",
        "",
        "By category:",
    ]
    width = max((len(name) for name, _, _ in c.categories), default=10)
    for name, a, b in c.categories:
        lines.append(f"  {name:<{width}}  {_fmt(a):>5} -> {_fmt(b):>5}  {_fmt_delta(a, b)}")
    for title, changes in (
        ("Fixed", c.fixed),
        ("Regressions", c.regressed),
        ("Other changes", c.other_changes),
    ):
        lines += ["", f"{title} ({len(changes)}):"]
        lines += [
            f"  [{ch.severity:<8}] {ch.rule_id}  {ch.title}  ({ch.before} -> {ch.after})" for ch in changes
        ]
        if not changes:
            lines.append("  none")
    lines += ["", f"Still failing: {c.still_failing}"]
    return "\n".join(lines) + "\n"


def to_markdown(comparison: Comparison) -> str:
    c = comparison
    delta = _fmt_delta(c.score_before, c.score_after)
    lines = [
        f"## Hardening progress: {c.host_after}",
        "",
        f"**Score:** {_fmt(c.score_before)} → {_fmt(c.score_after)} ({delta})",
        "",
        "| Category | Before | After | Change |",
        "|---|---:|---:|---:|",
    ]
    lines += [f"| {n} | {_fmt(a)} | {_fmt(b)} | {_fmt_delta(a, b)} |" for n, a, b in c.categories]
    for title, changes in (
        ("Fixed", c.fixed),
        ("Regressions", c.regressed),
        ("Other changes", c.other_changes),
    ):
        lines += ["", f"### {title} ({len(changes)})", ""]
        lines += [
            f"- **{ch.rule_id}** {ch.title} — {ch.severity}, {ch.before} → {ch.after}" for ch in changes
        ]
        if not changes:
            lines.append("_none_")
    lines += ["", f"Still failing: **{c.still_failing}**"]
    return "\n".join(lines) + "\n"


def to_json(comparison: Comparison) -> str:
    c = comparison

    def changes(items: list[Change]) -> list[dict[str, Any]]:
        return [
            {
                "id": ch.rule_id,
                "title": ch.title,
                "severity": ch.severity,
                "before": ch.before,
                "after": ch.after,
            }
            for ch in items
        ]

    data = {
        "host": c.host_after,
        "before": {"generated_at": c.generated_before, "score": c.score_before},
        "after": {"generated_at": c.generated_after, "score": c.score_after},
        "delta": c.delta,
        "categories": [{"name": n, "before": a, "after": b} for n, a, b in c.categories],
        "fixed": changes(c.fixed),
        "regressed": changes(c.regressed),
        "other_changes": changes(c.other_changes),
        "still_failing": c.still_failing,
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
