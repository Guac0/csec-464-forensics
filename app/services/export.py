"""Case export: a Markdown report of an investigation, optionally as a verifiable ZIP bundle.

Scope: one evidence item (its runs, notes, AI answers and activity) or everything (all evidence
plus global notes). Sections: summary, evidence and integrity, notes, runs (exact commands,
evidence snapshot, findings, dumped files), AI analysis (labelled as leads, with provenance) and
the activity log (changes and key reads; per-request entries are left out).

Everything that came from evidence or users is escaped, or put in fenced blocks whose fence is
longer than any backtick run inside, so recovered strings cannot inject Markdown or HTML. Order is
deterministic (by id), so two exports of the same data differ only in the generation time.

The bundle (:func:`build_bundle`) adds per-run CSV + raw tool output and a ``manifest.json`` with
the SHA-256 of every file. Dumped files are included only on request, and then the whole ZIP is
AES-encrypted with FT_ARTIFACT_ZIP_PASSWORD (they may be malware).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.ai.citations import NOT_FOUND, UNSUPPORTED, citation_status
from app.ai.prompts import prompt_version
from app.config import get_settings
from app.models import (
    AIMessage,
    AuditEvent,
    Case,
    DerivedArtifact,
    Evidence,
    IntegrityCheck,
    Note,
    ResultRow,
    Run,
)
from app.services import audit, integrity, results
from app.tools.executor import sha256_file

logger = logging.getLogger(__name__)

AI_LABEL = "AI-generated lead — not evidence. Verify against the cited rows."


# --------------------------------------------------------------------------------- escaping

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~=])")


def esc(value: Any) -> str:
    """Inline text: every Markdown-significant character backslash-escaped, newlines flattened."""
    if value is None:
        return "—"
    text = str(value).replace("\r", " ").replace("\n", " ")
    return _MD_SPECIAL.sub(r"\\\1", text) if text else "—"


def code(value: Any) -> str:
    """Inline code span that survives backticks in the value."""
    text = "" if value is None else str(value).replace("\n", " ")
    if not text:
        return "—"
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def fenced(value: Any, lang: str = "text") -> str:
    """Block of verbatim text; the fence is longer than any backtick run in the content."""
    text = "" if value is None else str(value)
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"


def _ts(value: datetime | str | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bytes(n: int | None) -> str:
    if n is None:
        return "—"
    value, unit = float(n), "B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            break
        value /= 1024
    return f"{n} bytes" if unit == "B" else f"{value:.1f} {unit} ({n} bytes)"


def _table(headers: list[str], rows: Iterable[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return lines


def _app_version() -> str:
    try:
        return metadata.version("forensics-tool")
    except metadata.PackageNotFoundError:
        return "unknown"


# --------------------------------------------------------------------------------- data


@dataclass
class Scope:
    evidence: list[Evidence]
    single: Evidence | None  # one image; None with case None = whole investigation
    case: Case | None = None  # a case: its images

    @property
    def evidence_ids(self) -> list[int]:
        return [e.id for e in self.evidence]

    @property
    def title(self) -> str:
        if self.case is not None:
            return f"Case export: {self.case.name}"
        return f"Evidence export: {self.single.rel_path}" if self.single else "Investigation export"

    @property
    def label(self) -> str:
        if self.case is not None:
            return f"case {self.case.name}"
        return self.single.rel_path if self.single else "all evidence"

    @property
    def slug(self) -> str:
        if self.case is not None:
            return "case-" + re.sub(r"[^A-Za-z0-9._-]+", "_", self.case.name).strip("_")
        if self.single is None:
            return "investigation"
        return "evidence-" + re.sub(r"[^A-Za-z0-9._-]+", "_", self.single.rel_path).strip("_")


def get_scope(session: Session, evidence_id: int | None, case_id: int | None = None) -> Scope:
    if case_id is not None:
        from app.services.cases import get_case, member_evidence

        case = get_case(session, case_id)
        return Scope([ev for ev, _ in member_evidence(session, case_id)], None, case)
    if evidence_id is None:
        return Scope(list(session.scalars(select(Evidence).order_by(Evidence.id))), None)
    ev = session.get(Evidence, evidence_id)
    if ev is None:
        raise LookupError(f"evidence {evidence_id} not found")
    return Scope([ev], ev)


def _runs(session: Session, evidence_id: int) -> list[Run]:
    return list(session.scalars(select(Run).where(Run.evidence_id == evidence_id).order_by(Run.id)))


# --------------------------------------------------------------------------------- report


def build_report(
    session: Session,
    evidence_id: int | None = None,
    *,
    case_id: int | None = None,
    generated_at: datetime | None = None,
    bundle_files: list[dict[str, Any]] | None = None,
) -> str:
    """The Markdown report for one evidence item (``evidence_id``), one case (``case_id``) or
    everything (neither)."""
    session.expire_all()  # always report the current database state (the worker writes too)
    scope = get_scope(session, evidence_id, case_id)
    generated = _ts(generated_at or datetime.now(UTC))
    chain = audit.verify_chain(session)
    out: list[str] = [f"# {esc(scope.title)}", ""]
    out += _summary(session, scope, generated, chain)
    out += _contents(session, scope)
    if scope.case is not None:
        out += _case_section(session, scope.case)
    for ev in scope.evidence:
        out += _evidence_section(session, ev, multi=scope.single is None)
        if scope.single is not None:
            out += _leads_section(session, ev)
    if scope.single is None and scope.case is None:
        for case in _all_cases(session):
            out += _case_section(session, case)
    out += _activity_section(session, scope)
    if bundle_files is not None:
        out += _bundle_section(bundle_files)
    out += [
        "## About this report",
        "",
        "- Tool output tables are not reproduced here; each run lists its exact command, the "
        "SHA-256 of the evidence it ran against and of its raw output. The ZIP bundle contains "
        "every run's rows (CSV) and raw output, with a manifest of SHA-256 hashes.",
        f"- Sections marked “{esc(AI_LABEL)}” were written by an AI model and are leads for "
        "an analyst, not findings.",
        "- Text taken from evidence is escaped or shown in code blocks exactly as recovered.",
        "",
    ]
    return "\n".join(out).rstrip() + "\n"


def _summary(session: Session, scope: Scope, generated: str, chain: Any) -> list[str]:
    settings = get_settings()
    n_runs = sum(len(_runs(session, i)) for i in scope.evidence_ids)
    tool_versions = sorted(
        {r.tool_version for i in scope.evidence_ids for r in _runs(session, i) if r.tool_version}
    )
    chain_text = (
        f"verified, {chain.events} events, head #{chain.head_seq} `{chain.head_hash}`"
        if chain.ok
        else f"**FAILED** ({esc(chain.error)}) at event #{chain.bad_seq}"
    )
    rows = [
        ["Generated (UTC)", generated],
        ["Scope", esc(scope.label)],
        ["Evidence items", str(len(scope.evidence))],
        ["Runs", str(n_runs)],
        ["Application version", esc(_app_version())],
        ["Tool versions", esc(", ".join(tool_versions) or "—")],
        ["AI prompt version (current)", code(prompt_version())],
        ["Integrity mode", code(settings.integrity_mode)],
        ["Audit log", chain_text],
    ]
    return ["## Summary", "", *_table(["", ""], rows), ""]


def _contents(session: Session, scope: Scope) -> list[str]:
    lines = ["## Contents", ""]
    if scope.case is not None:
        lines.append(f"- Case {scope.case.id}: {esc(scope.case.name)}")
    for ev in scope.evidence:
        lines.append(f"- Evidence {ev.id}: {esc(ev.rel_path)}")
        if scope.single is not None and _cases_of(session, ev.id):
            lines.append("- Leads from linked evidence")
    if scope.single is None and scope.case is None:
        lines += [f"- Case {c.id}: {esc(c.name)}" for c in _all_cases(session)]
    lines += ["- Activity log", ""]
    return lines


# --------------------------------------------------------------------------------- cases


def _all_cases(session: Session) -> list[Case]:
    return list(session.scalars(select(Case).order_by(Case.id)))


def _cases_of(session: Session, evidence_id: int) -> list[tuple[Case, str]]:
    from app.services.cases import cases_for_evidence

    return cases_for_evidence(session, evidence_id)


def _shared_lines(session: Session, items: list[Any], labels: dict[int, str]) -> list[str]:
    """Shared items in their latest state, clearly attributed to the image they came from."""
    from app.services import sharing

    out: list[str] = []
    for item in items:
        r = sharing.resolve(session, item)
        src = r.source.rel_path if r.source else f"evidence {item.source_evidence_id}"
        label = labels.get(item.source_evidence_id)
        state = {"ok": "current", "changed": "CHANGED since shared", "gone": "SOURCE GONE"}[
            r.status
        ]
        out += [
            f"#### {esc(r.kind_label)}: {esc(r.title)}",
            "",
            *_table(
                ["", ""],
                [
                    ["From", esc(src) + (f" ({esc(label)})" if label else "")],
                    ["Source", code(item.source_key)],
                    ["Shared", f"{_ts(item.shared_at)} by {esc(item.shared_by)}"],
                    ["State", state + (f" — {esc(r.status_text)}" if r.status_text else "")],
                    ["Comment", esc(item.comment) if item.comment else "—"],
                ],
            ),
            "",
        ]
        if item.kind.value == "ai_answer":
            out += [f"> {esc(AI_LABEL)}", ""]
        if r.text:
            out += [fenced(r.text), ""]
    return out


def _case_section(session: Session, case: Case) -> list[str]:
    from app.services import sharing
    from app.services.cases import labels, member_evidence

    members = member_evidence(session, case.id)
    out = [f"## Case {case.id}: {esc(case.name)}", ""]
    if case.description:
        out += [fenced(case.description), ""]
    out += ["### Images in this case", ""]
    if members:
        out += _table(
            ["Evidence", "Image", "Label"],
            [[str(ev.id), esc(ev.rel_path), esc(label) or "—"] for ev, label in members],
        )
    else:
        out.append("No images.")
    out.append("")
    out += _notes_section_case(session, case.id)
    out += _indicators_section(session, case.id, members)
    out += _comparisons_section(session, case.id)
    items = sharing.list_items(session, case.id)
    out += ["### Shared in this case", ""]
    if not items:
        return [*out, "Nothing shared.", ""]
    out += [
        "Items an analyst shared from one image with the others. They point to their source "
        "and are shown as the source is now.",
        "",
    ]
    return out + _shared_lines(session, items, labels(session, case.id))


def _indicators_section(session: Session, case_id: int, members: list[Any]) -> list[str]:
    from app.services import indicators

    inds = indicators.list_indicators(session, case_id)
    out = ["### Indicators", ""]
    if not inds:
        return [*out, "No indicators.", ""]
    counts = indicators.hit_counts(session, case_id)
    out += _table(
        ["Type", "Indicator", "Match", "Hits per image", "Checked against all runs"],
        [
            [
                esc(i.type.value),
                code(i.value),
                esc(i.match_mode.value + (f", column {i.column}" if i.column else "")),
                esc(
                    ", ".join(
                        f"{label or ev.rel_path}: {counts.get(i.id, {}).get(ev.id, 0)}"
                        for ev, label in members
                    )
                    or "—"
                ),
                _ts(i.checked_at) if i.checked_at else "no (new runs only)",
            ]
            for i in inds
        ],
    )
    out.append("")
    return out + _hit_lines(indicators.hits(session, case_id))


REPORT_COMPARE_ROWS = 20


def _comparisons_section(session: Session, case_id: int) -> list[str]:
    """Saved comparisons, recomputed with current data (first rows of each difference)."""
    from app.services import compare

    saved = compare.list_saved(session, case_id)
    if not saved:
        return []
    out = ["### Comparisons", ""]
    for s in saved:
        ev_a, ev_b = session.get(Evidence, s.evidence_a_id), session.get(Evidence, s.evidence_b_id)
        out += [f"#### {esc(s.title)}", ""]
        rows = [
            ["Plugin", code(s.plugin)],
            ["A", f"{esc(ev_a.rel_path if ev_a else s.evidence_a_id)}, run {s.run_a_id}"],
            ["B", f"{esc(ev_b.rel_path if ev_b else s.evidence_b_id)}, run {s.run_b_id}"],
            ["Rows identified by", esc(", ".join(s.keys))],
            ["Ignored columns", esc(", ".join(s.ignore) or "—")],
            ["Saved", f"{_ts(s.created_at)} by {esc(s.created_by)}"],
            ["Counts when saved", esc(_counts(s.counts))],
        ]
        cmp = compare.recompute(session, s)
        rows.append(
            ["Counts now", esc(_counts(cmp.counts)) if not isinstance(cmp, str) else esc(cmp)]
        )
        if s.comment:
            rows.append(["Comment", esc(s.comment)])
        out += [*_table(["", ""], rows), ""]
        if isinstance(cmp, str):
            continue
        data_a = compare.rows(session, cmp.run_a.id, cmp.only_a[:REPORT_COMPARE_ROWS])
        data_b = compare.rows(session, cmp.run_b.id, cmp.only_b[:REPORT_COMPARE_ROWS])
        listing = (
            [
                ["only in A", code(f"R{cmp.run_a.id}:{i}"), code(_keyvals(data_a.get(i), cmp.keys))]
                for i in cmp.only_a[:REPORT_COMPARE_ROWS]
            ]
            + [
                ["only in B", code(f"R{cmp.run_b.id}:{i}"), code(_keyvals(data_b.get(i), cmp.keys))]
                for i in cmp.only_b[:REPORT_COMPARE_ROWS]
            ]
            + [
                [
                    "changed",
                    code(f"R{cmp.run_a.id}:{a} / R{cmp.run_b.id}:{b}"),
                    esc(", ".join(cols)),
                ]
                for a, b, cols in cmp.changed[:REPORT_COMPARE_ROWS]
            ]
        )
        if listing:
            out += [*_table(["Difference", "Row", "Identity / changed columns"], listing), ""]
            if max(len(cmp.only_a), len(cmp.only_b), len(cmp.changed)) > REPORT_COMPARE_ROWS:
                out += [f"First {REPORT_COMPARE_ROWS} of each kind; the full list is on the "
                        "comparison page (CSV download).", ""]  # fmt: skip
    return out


def _counts(counts: dict[str, int]) -> str:
    return (
        f"only in A {counts.get('only_a', 0)}, only in B {counts.get('only_b', 0)}, "
        f"changed {counts.get('changed', 0)}, same {counts.get('same', 0)}"
    )


def _keyvals(data: dict[str, Any] | None, keys: list[str]) -> str:
    data = data or {}
    return ", ".join(f"{k}={data.get(k)}" for k in keys)


def _hit_lines(hits: list[Any]) -> list[str]:
    if not hits:
        return ["No hits.", ""]
    return [
        *_table(
            ["Indicator", "Image", "Row", "Column", "Value"],
            [
                [
                    code(h.indicator.value),
                    esc(h.evidence.rel_path),
                    code(f"R{h.run.id}:{h.hit.row_idx}"),
                    esc(h.hit.column),
                    code(h.hit.cell),
                ]
                for h in hits
            ],
        ),
        "",
    ]


def _notes_section_case(session: Session, case_id: int) -> list[str]:
    notes = list(session.scalars(select(Note).where(Note.case_id == case_id).order_by(Note.id)))
    out = ["### Case notes", ""]
    if not notes:
        return [*out, "No notes.", ""]
    for n in notes:
        out += [f"Note {n.id} ({_ts(n.created_at)}):", "", fenced(n.body), ""]
    return out


def _leads_section(session: Session, ev: Evidence) -> list[str]:
    """Per-image report: what OTHER images in this image's cases shared, clearly separated."""
    from app.services import sharing
    from app.services.cases import labels

    cases = _cases_of(session, ev.id)
    if not cases:
        return []
    out = [
        "## Leads from linked evidence",
        "",
        f"Shared by an analyst from other images in the cases {esc(ev.rel_path)} belongs to. "
        "They are NOT findings on this image: each points to its source image.",
        "",
    ]
    from app.services import indicators

    for case, label in cases:
        items = sharing.list_items(session, case.id, exclude_evidence_id=ev.id)
        title = f"### Case {case.id}: {esc(case.name)}"
        out += [title + (f" (this image: {esc(label)})" if label else ""), ""]
        if indicators.list_indicators(session, case.id):
            out += [
                "Rows of THIS image matching the case's indicator watchlist:",
                "",
                *_hit_lines(indicators.hits(session, case.id, evidence_id=ev.id)),
            ]
        if not items:
            out += ["Nothing shared from other images.", ""]
            continue
        out += _shared_lines(session, items, labels(session, case.id))
    return out


def _evidence_section(session: Session, ev: Evidence, multi: bool) -> list[str]:
    out = [f"## Evidence {ev.id}: {esc(ev.rel_path)}", ""]
    state = integrity.status(ev)
    out += _table(
        ["", ""],
        [
            ["File", code(ev.rel_path)],
            ["Size", _bytes(ev.size_bytes)],
            ["Registered", _ts(ev.created_at)],
            ["Description", esc(ev.description or "—")],
            ["OS info", esc(_flat(ev.os_info))],
            ["Integrity", _integrity_cell(ev, state)],
            ["Last hashed", _ts(ev.hashed_at)],
        ],
    )
    out += ["", "**Hashes**", ""]
    out += _table(
        ["Algorithm", "Computed", "Expected (acquisition)", "Match"],
        [
            [
                label,
                code(getattr(ev, algo)),
                code(getattr(ev, f"expected_{algo}")),
                _match(getattr(ev, algo), getattr(ev, f"expected_{algo}")),
            ]
            for algo, label in (("sha256", "SHA-256"), ("md5", "MD5"), ("sha1", "SHA-1"))
        ],
    )
    if ev.mismatch_ack_at:
        out += [
            "",
            f"Mismatch acknowledged {_ts(ev.mismatch_ack_at)}: {esc(ev.mismatch_ack_reason)}",
        ]
    checks = list(
        session.scalars(
            select(IntegrityCheck)
            .where(IntegrityCheck.evidence_id == ev.id)
            .order_by(IntegrityCheck.id)
        )
    )
    out += ["", "**Integrity history**", ""]
    if checks:
        out += _table(
            ["When (UTC)", "Kind", "Result", "SHA-256", "Run", "Detail"],
            [
                [
                    _ts(c.created_at),
                    esc(c.kind),
                    esc(c.result),
                    code(c.sha256),
                    str(c.run_id) if c.run_id else "—",
                    esc(c.detail or "—"),
                ]
                for c in checks
            ],
        )
    else:
        out.append("No hash computations recorded.")
    out.append("")
    out += _notes_section(session, ev.id, f"### Notes on {esc(ev.rel_path)}")
    out += _runs_section(session, ev)
    out += _ai_section(session, ev)
    return out


def _integrity_cell(ev: Evidence, state: str) -> str:
    problem = integrity.describe_problem(ev)
    return f"**{esc(state)}**" + (f" — {esc(problem)}" if problem else "")


def _flat(info: dict[str, Any] | None) -> str:
    if not info:
        return "—"
    return ", ".join(
        f"{k}=({len(v)} fields)" if isinstance(v, dict | list) else f"{k}={v}"
        for k, v in info.items()
    )


def _match(computed: str | None, expected: str | None) -> str:
    if not expected:
        return "—"
    if not computed:
        return "not hashed"
    return "yes" if computed.lower() == expected.lower() else "**NO**"


def _notes_section(session: Session, evidence_id: int | None, heading: str) -> list[str]:
    stmt = select(Note).order_by(Note.id)
    stmt = stmt.where(
        Note.evidence_id.is_(None) if evidence_id is None else Note.evidence_id == evidence_id
    )
    notes = list(session.scalars(stmt))
    out = [heading, ""]
    if not notes:
        return [*out, "No notes.", ""]
    for n in notes:
        changed = (
            n.updated_at and n.created_at and (n.updated_at - n.created_at).total_seconds() > 1
        )
        edited = f", edited {_ts(n.updated_at)}" if changed else ""
        out += [f"Note {n.id} ({_ts(n.created_at)}{edited}):", "", fenced(n.body), ""]
    return out


def _runs_section(session: Session, ev: Evidence) -> list[str]:
    runs = _runs(session, ev.id)
    out = [f"### Runs on {esc(ev.rel_path)}", ""]
    if not runs:
        return [*out, "No runs.", ""]
    out += _table(
        ["Run", "Plugin", "Args", "Origin", "Status", "Rows", "Finished (UTC)"],
        [
            [
                str(r.id),
                code(r.plugin),
                code(json.dumps(r.args or {}, sort_keys=True)),
                esc(r.origin.value),
                esc(r.status.value) + (" (deleted)" if r.deleted_at else ""),
                str(r.row_count),
                _ts(r.finished_at),
            ]
            for r in runs
        ],
    )
    out.append("")
    for r in runs:
        out += _run_detail(session, r)
    return out


def _run_detail(session: Session, r: Run) -> list[str]:
    out = [f"#### Run {r.id}: {esc(r.plugin)}", ""]
    rows = [
        ["Status", esc(r.status.value) + (f" — {esc(r.error)}" if r.error else "")],
        ["Tool", esc(f"{r.tool} {r.tool_version or ''}".strip())],
        ["Evidence at run time", _snapshot(r)],
        ["Raw output SHA-256", code(r.stdout_sha256)],
        ["Started / finished (UTC)", f"{_ts(r.started_at)} / {_ts(r.finished_at)}"],
        ["Rows", str(r.row_count)],
    ]
    if r.deleted_at is not None:
        rows.insert(
            1,
            [
                "Deleted",
                f"{_ts(r.deleted_at)} — {esc(r.delete_reason)} (rows, raw output and dumped "
                "files removed; hashes above are what they were)",
            ],
        )
    if r.rerun_of_id:
        rows.append(["Re-run of", f"run {r.rerun_of_id}"])
    if r.parent_run_id:
        rows.append(["Queued by", f"hook {code(r.triggered_by_hook)} after run {r.parent_run_id}"])
    if r.integrity_warning:
        rows.append(["Integrity warning", esc(r.integrity_warning)])
    out += _table(["", ""], rows)
    out += ["", "Exact command:", "", fenced(" ".join(r.argv or []) or "(not started)", "sh"), ""]
    if r.findings:
        out += ["Automated findings (post-run hooks; heuristics to verify):", ""]
        for f in r.findings:
            cites = ", ".join(f"R{r.id}:{i}" for i in f.get("rows") or [])
            out.append(
                f"- **{esc(f.get('severity'))}** {esc(f.get('title'))}"
                + (f" — {esc(f.get('detail'))}" if f.get("detail") else "")
                + (f" (rows {esc(cites)})" if cites else "")
                + f" _(hook {esc(f.get('hook'))})_"
            )
        out.append("")
    failed = [h for h in r.hook_results or [] if h.get("status") != "ok"]
    if failed:
        out += [
            "Post-processing errors: "
            + "; ".join(f"{esc(h.get('hook'))}: {esc(h.get('error'))}" for h in failed),
            "",
        ]
    tags = results_tags(session, r.id)
    if tags:
        out += ["Flagged rows: " + ", ".join(f"{esc(t)} ×{n}" for t, n in tags), ""]
    artifacts = list(
        session.scalars(
            select(DerivedArtifact)
            .where(DerivedArtifact.run_id == r.id)
            .order_by(DerivedArtifact.filename)
        )
    )
    if artifacts:
        out += ["Dumped files (may be malware):", ""]
        out += _table(
            ["File", "Type", "Size", "SHA-256", "MD5", "SHA-1", "Row"],
            [
                [
                    code(a.filename),
                    esc(a.file_type),
                    _bytes(a.size_bytes),
                    code(a.sha256),
                    code(a.md5),
                    code(a.sha1),
                    f"R{r.id}:{a.source_row_idx}" if a.source_row_idx is not None else "—",
                ]
                for a in artifacts
            ],
        )
        out.append("")
    return out


def _snapshot(r: Run) -> str:
    if not r.evidence_sha256:
        return "—"
    return f"SHA-256 {code(r.evidence_sha256)}, {_bytes(r.evidence_size_bytes)}"


def results_tags(session: Session, run_id: int) -> list[tuple[str, int]]:
    from app.services.runs import annotation_tags

    return annotation_tags(session, run_id)


def _ai_section(session: Session, ev: Evidence) -> list[str]:
    msgs = list(
        session.scalars(
            select(AIMessage).where(AIMessage.evidence_id == ev.id).order_by(AIMessage.id)
        )
    )
    out = [f"### AI analysis of {esc(ev.rel_path)}", ""]
    answers = [m for m in msgs if m.role == "assistant"]
    if not answers:
        return [*out, "No AI questions asked.", ""]
    questions = {m.id: m for m in msgs if m.role == "user"}
    # AI agent tasks: the goal message is not right before the answer (steps run in between).
    from app.models import AITask

    task_goal = {
        t.answer_message_id: t.user_message_id
        for t in session.scalars(
            select(AITask).where(AITask.answer_message_id.in_([m.id for m in answers]))
        )
    }
    for m in answers:
        q = questions.get(task_goal.get(m.id, m.id - 1))
        params = dict(m.params or {})
        out += [f"#### AI answer {m.id} ({_ts(m.created_at)})", "", f"> **{esc(AI_LABEL)}**", ""]
        if q is not None:
            out += ["Question:", "", fenced(q.content), ""]
        if m.error:
            out += [f"Request failed: {esc(m.error)}", ""]
        else:
            if m.truncated:
                out += [
                    "**Answer cut off by the token limit (FT_AI_MAX_TOKENS); may be incomplete.**",
                    "",
                ]
            out += ["Answer:", "", fenced(m.content), ""]
        if m.reasoning:
            out += [
                "Model reasoning (hidden from the answer; the model's own notes, not evidence):",
                "",
                fenced(m.reasoning),
                "",
            ]
        citations = m.citations or []
        details = [
            [
                "Model (requested / returned)",
                f"{code(m.model_requested)} / {code(m.model_returned)}",
            ],  # noqa: E501
            ["Prompt version", code(params.pop("prompt_version", None))],
            ["Parameters", code(json.dumps(params, sort_keys=True))],
            ["Provider", code(m.provider_base_url)],
            ["Citations", _citations_summary(citations)],
            ["Prompt SHA-256", code(_sha256_json(m.request_messages))],
        ]
        if m.usage:
            details.append(["Usage", code(json.dumps(m.usage, sort_keys=True))])
        out += _table(["", ""], details)
        suggestions = m.suggestions or []
        if suggestions:
            out += ["", "Suggested queries:", ""]
            for s in suggestions:
                state = "valid" if s.get("valid") else f"rejected: {s.get('error')}"
                out.append(
                    f"- {code(s.get('plugin'))} {code(json.dumps(s.get('args') or {}))} "
                    f"({esc(state)}) — {esc(s.get('reason'))}"
                )
        out.append("")
    return out


def _citations_summary(citations: list[dict[str, Any]]) -> str:
    """'N' plus invalid rows and value-level support problems (see app.ai.citations)."""
    status = {c["key"]: citation_status(c) for c in citations}
    invalid = [k for k, s in status.items() if s == NOT_FOUND]
    parts = []
    if invalid:
        parts.append(f"{len(invalid)} invalid: {esc(', '.join(invalid))}")
    unsupported = [
        f"{c['key']} ({', '.join(str(v) for v in c.get('unsupported_values') or [])})"
        for c in citations
        if status[c["key"]] == UNSUPPORTED
    ]
    if unsupported:
        parts.append(
            f"{len(unsupported)} cited row(s) don't support the stated values: "
            + esc("; ".join(unsupported))
        )
    return f"{len(citations)} ({'; '.join(parts)})" if parts else str(len(citations))


def _sha256_json(value: Any) -> str | None:
    if value is None:
        return None
    data = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _activity_section(session: Session, scope: Scope) -> list[str]:
    stmt = select(AuditEvent).where(AuditEvent.category != audit.REQUEST).order_by(AuditEvent.seq)
    if scope.single is not None:
        stmt = stmt.where(AuditEvent.evidence_id == scope.single.id)
    elif scope.case is not None:
        stmt = stmt.where(
            or_(
                AuditEvent.evidence_id.in_(scope.evidence_ids),
                (AuditEvent.object_type == "case") & (AuditEvent.object_id == scope.case.id),
            )
        )
    events = list(session.scalars(stmt))
    out = [
        "## Activity log",
        "",
        "Changes and key reads"
        + (" for this evidence" if scope.single else "")
        + (" for this case and its images" if scope.case else "")
        + "; page and API requests are not included. Event numbers are the audit log's "
        "sequence numbers (gaps here are other evidence or requests, not deletions).",
        "",
    ]
    if not events:
        return [*out, "No events.", ""]
    out += _table(
        ["#", "Time (UTC)", "Origin", "Category", "Action", "Summary"],
        [
            [str(e.seq), e.ts, esc(e.origin), esc(e.category), code(e.action), esc(e.summary)]
            for e in events
        ],
    )
    return [*out, ""]


def _bundle_section(files: list[dict[str, Any]]) -> list[str]:
    out = ["## Files in this bundle", "", "SHA-256 of every file is also in `manifest.json`.", ""]
    out += _table(
        ["File", "Size", "SHA-256"],
        [[code(f["path"]), _bytes(f["size"]), code(f["sha256"])] for f in files],
    )
    return [*out, ""]


# --------------------------------------------------------------------------------- bundle


@dataclass
class BundleResult:
    path: Path
    filename: str
    encrypted: bool
    files: list[dict[str, Any]]
    report_sha256: str


def build_bundle(
    session: Session,
    evidence_id: int | None = None,
    *,
    case_id: int | None = None,
    include_dumped: bool = False,
    generated_at: datetime | None = None,
) -> BundleResult:
    """ZIP with report.md, per-run rows.csv + raw-output.jsonl, optionally dumped files, and
    manifest.json. Written to a temp file in <data_dir>/tmp (the caller deletes it)."""
    settings = get_settings()
    scope = get_scope(session, evidence_id, case_id)
    generated_at = generated_at or datetime.now(UTC)
    files: list[tuple[str, Path | bytes]] = []
    notes: list[str] = []
    for ev in scope.evidence:
        for r in _runs(session, ev.id):
            base = f"evidence-{ev.id}/run-{r.id}-{r.plugin.rsplit('.', 1)[-1].lower()}"
            if r.deleted_at is not None:
                notes.append(f"{base}: run data was deleted ({r.delete_reason})")
                continue
            if session.scalar(select(ResultRow.id).where(ResultRow.run_id == r.id).limit(1)):
                csv_text = "".join(
                    results.export_rows(session, r, results.RowView(), "csv")
                ).encode("utf-8")
                files.append((f"{base}/rows.csv", csv_text))
            raw = settings.data_dir / r.stdout_path if r.stdout_path else None
            if raw is not None and raw.is_file():
                if r.stdout_sha256 and sha256_file(raw) != r.stdout_sha256:
                    notes.append(f"{base}/raw-output.jsonl: SKIPPED, hash differs from the run")
                else:
                    files.append((f"{base}/raw-output.jsonl", raw))
            if include_dumped:
                from app.services.artifacts import ArtifactIntegrityError, _verified_path

                for a in session.scalars(
                    select(DerivedArtifact)
                    .where(DerivedArtifact.run_id == r.id)
                    .order_by(DerivedArtifact.filename)
                ):
                    try:
                        files.append((f"{base}/dumped/{a.filename}", _verified_path(a)))
                    except (ArtifactIntegrityError, ValueError) as exc:
                        notes.append(f"{base}/dumped/{a.filename}: SKIPPED, {exc}")

    listing = [
        {"path": name, "size": _len(content), "sha256": _sha256(content)} for name, content in files
    ]
    report = build_report(
        session, evidence_id, case_id=case_id, generated_at=generated_at, bundle_files=listing
    )
    if notes:
        report += "\n## Bundle warnings\n\n" + "\n".join(f"- {esc(n)}" for n in notes) + "\n"
    report_bytes = report.encode("utf-8")
    report_sha = hashlib.sha256(report_bytes).hexdigest()
    chain = audit.verify_chain(session)
    manifest = {
        "generated_at": _ts(generated_at),
        "scope": scope.label,
        "application_version": _app_version(),
        "prompt_version": prompt_version(),
        "audit_chain": {"ok": chain.ok, "head_seq": chain.head_seq, "head_hash": chain.head_hash},
        "includes_dumped_files": include_dumped,
        "files": [{"path": "report.md", "size": len(report_bytes), "sha256": report_sha}] + listing,
        "warnings": notes,
    }
    tmp_dir = settings.data_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="export-", suffix=".zip", dir=tmp_dir)
    os.close(fd)
    if include_dumped:
        import pyzipper

        zf: Any = pyzipper.AESZipFile(
            tmp_name, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        )
        zf.setpassword(settings.artifact_zip_password.encode("utf-8"))
    else:
        zf = zipfile.ZipFile(tmp_name, "w", compression=zipfile.ZIP_DEFLATED)
    with zf:
        zf.writestr("report.md", report_bytes)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
        for name, content in files:
            if isinstance(content, Path):
                zf.write(content, name)
            else:
                zf.writestr(name, content)
    stamp = _ts(generated_at).replace(":", "").replace("-", "")
    return BundleResult(
        path=Path(tmp_name),
        filename=f"{scope.slug}-{stamp}.zip",
        encrypted=include_dumped,
        files=manifest["files"],
        report_sha256=report_sha,
    )


def _len(content: Path | bytes) -> int:
    return content.stat().st_size if isinstance(content, Path) else len(content)


def _sha256(content: Path | bytes) -> str:
    return (
        sha256_file(content) if isinstance(content, Path) else hashlib.sha256(content).hexdigest()
    )


def record_export(
    session: Session,
    evidence_id: int | None,
    fmt: str,
    *,
    include_dumped: bool = False,
    report_sha256: str,
    files: int = 1,
    case_id: int | None = None,
) -> None:
    """Audit the export (category key_read) and commit. (The action name ``case.export``
    predates cases; it covers image, case and whole-investigation exports.)"""
    what = (
        f"case {case_id}"
        if case_id
        else f"evidence {evidence_id}"
        if evidence_id
        else "investigation"
    )
    audit.record(
        session,
        "case.export",
        category=audit.KEY_READ,
        object_type="case" if case_id else "evidence" if evidence_id else None,
        object_id=case_id or evidence_id,
        evidence_id=evidence_id,
        summary=f"Exported {what} "
        f"({'ZIP bundle' if fmt == 'zip' else 'Markdown report'}"
        + (", with dumped files, encrypted" if include_dumped else "")
        + ")",
        details={
            "format": fmt,
            "include_dumped": include_dumped,
            "report_sha256": report_sha256,
            "files": files,
            "case_id": case_id,
        },
    )
    session.commit()
