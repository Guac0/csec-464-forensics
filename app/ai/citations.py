"""Citation extraction and validation for AI output.

Citation format: ``[R12:34]`` (run 12, row 34), or several in one bracket: ``[R1:2, R1:3]``.

Validation has two levels:

1. existence: the cited row is in the database (``valid``);
2. support: typed values the answer states in the same sentence as the citation (IPs, paths,
   file names with an extension, hex addresses, quoted/backticked strings and *labelled*
   numbers such as ``PID 1234``) appear in the cited row(s) (``support``).

Bare numbers ("3 processes") are deliberately not checked: they are usually counts or times.
A sentence that cites several rows is checked against all of them together.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from app.models import ResultRow

_KEY = r"R\d+:\d+"
_BRACKET_RE = re.compile(rf"\[\s*({_KEY}(?:\s*[,;]\s*{_KEY})*)\s*\]")
_KEY_RE = re.compile(r"R(\d+):(\d+)")


def parse_key(key: str) -> tuple[int, int] | None:
    """'R12:34' -> (12, 34); None if not a citation key."""
    m = _KEY_RE.fullmatch(key.strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


def extract_citations(text: str) -> list[str]:
    """Ordered, de-duplicated citation keys found in bracketed citations."""
    seen: dict[str, None] = {}
    for bracket in _BRACKET_RE.finditer(text or ""):
        for m in _KEY_RE.finditer(bracket.group(1)):
            seen.setdefault(f"R{int(m.group(1))}:{int(m.group(2))}", None)
    return list(seen)


def citation_url(run_id: int, row_idx: int) -> str:
    """UI link for a cited row (see CONTRACTS.md)."""
    return f"/runs/{run_id}?row={row_idx}#row-{run_id}-{row_idx}"


# Citation support states (stored in each citation dict as ``support``).
SUPPORTED = "supported"
UNSUPPORTED = "unsupported"
UNCHECKED = "unchecked"  # the sentence(s) state no checkable value
NOT_FOUND = "not_found"  # the cited row does not exist

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]*\d)")
_IPV6 = re.compile(r"(?<![\w:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")
_WIN_PATH = re.compile(r"(?:[A-Za-z]:\\|\\\\?)[^\s\"'`<>|,;()\[\]]+(?:\\[^\s\"'`<>|,;()\[\]]+)*")
_HEX = re.compile(r"(?<![\w])0x([0-9A-Fa-f]{2,16})(?![\w])")
_QUOTED = re.compile(r"`([^`\n]{2,200})`|\"([^\"\n]{2,200})\"|\u201c([^\u201d\n]{2,200})\u201d")
_TRAILING = ".,;:!?)]}'\""
# Volatility path forms that name the same file: \Device\HarddiskVolume3\x, C:\x, \??\C:\x,
# \SystemRoot\x (= \Windows\x).
_PATH_PREFIX = re.compile(r"^(?:\\\?\?\\|\\\\\?\\)?(?:[a-z]:|\\device\\harddiskvolume\d+)", re.I)

# Tunables owned by the forensics team: ``<content root>/citations.py`` (forensics/citations.py)
# may define FILE_EXTENSIONS, NUMBER_LABELS, TRUNCATED_NAME_LENGTH; these are the defaults.
DEFAULT_FILE_EXTENSIONS = (
    "exe dll sys scr bat cmd ps1 vbs js cpl ocx com msi lnk dmp bin dat tmp log txt zip db".split()
)
DEFAULT_NUMBER_LABELS = (
    "PPID", "PID", "TID", "port", "parent process id", "parent id", "process id", "thread id",
)  # fmt: skip
DEFAULT_TRUNCATED_NAME_LENGTH = 14  # pslist's ImageFileName is truncated by Windows to 14 chars


@dataclass(frozen=True)
class _Rules:
    file_name: re.Pattern[str]
    labelled_number: re.Pattern[str]
    truncated_name: int


@lru_cache(maxsize=8)
def _compile(exts: tuple[str, ...], labels: tuple[str, ...], truncated: int) -> _Rules:
    ext = "|".join(re.escape(e.lstrip(".")) for e in exts if e.strip()) or "exe"
    # Longest labels first so "parent process id" wins over "id"-like shorter ones.
    words = sorted((lab for lab in labels if lab.strip()), key=len, reverse=True) or ["PID"]
    label = "|".join(r"\s+".join(map(re.escape, w.split())) for w in words)
    return _Rules(
        file_name=re.compile(rf"(?<![\w\\/.-])([\w.-]+\.(?:{ext}))(?![\w-])", re.IGNORECASE),
        labelled_number=re.compile(
            rf"\b({label})s?\s*(?:[:=#]|of|is|was)?\s*(\d+)\b", re.IGNORECASE
        ),
        truncated_name=int(truncated),
    )


def _rules() -> _Rules:
    from app.tools import content

    module = content.current().citations
    return _compile(
        tuple(getattr(module, "FILE_EXTENSIONS", DEFAULT_FILE_EXTENSIONS)),
        tuple(getattr(module, "NUMBER_LABELS", DEFAULT_NUMBER_LABELS)),
        getattr(module, "TRUNCATED_NAME_LENGTH", DEFAULT_TRUNCATED_NAME_LENGTH),
    )


def _norm_text(value: str) -> str:
    return " ".join(value.split()).casefold()


def _norm_path(value: str) -> str:
    text = re.sub(r"\\+", r"\\", value.replace("/", "\\").strip()).casefold()
    text = _PATH_PREFIX.sub("", text)
    if text.startswith("\\systemroot\\"):
        text = "\\windows" + text[len("\\systemroot") :]
    return text.rstrip("\\")


def _canon_ip(value: str) -> str | None:
    text = value.strip("[]")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        text = ".".join(str(int(p)) for p in text.split("."))
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def extract_values(text: str) -> list[tuple[str, str]]:
    """Checkable ``(kind, value)`` pairs stated in ``text`` (citation brackets removed first).

    Kinds: ip, path, file, hex, number (labelled only), text (quoted/backticked).
    """
    text = _BRACKET_RE.sub(" ", text or "")
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.casefold())
        if value and key not in seen:
            seen.add(key)
            found.append((kind, value))

    paths = [m.group(0).rstrip(_TRAILING) for m in _WIN_PATH.finditer(text)]
    paths = [p for p in paths if p.count("\\") >= 2 or re.match(r"[A-Za-z]:\\.", p)]
    for p in paths:
        add("path", p)
    rules = _rules()
    for m in rules.file_name.finditer(text):
        name = m.group(1)
        if not any(_norm_path(p).endswith("\\" + name.casefold()) for p in paths):
            add("file", name)
    for m in _IPV4.finditer(text):
        if _canon_ip(m.group(1)):
            add("ip", m.group(1))
    for m in _IPV6.finditer(text):
        if m.group(1).count(":") >= 2 and _canon_ip(m.group(1)):
            add("ip", m.group(1))
    for m in _HEX.finditer(text):
        add("hex", "0x" + m.group(1))
    for m in rules.labelled_number.finditer(text):
        add("number", m.group(2))
    for m in _QUOTED.finditer(text):
        quoted = next(g for g in m.groups() if g is not None).strip()
        typed = {v.casefold() for k, v in found if k != "text"}
        if quoted and quoted.casefold() not in typed:
            add("text", quoted)
    return found


def _cells(data: Any) -> Iterable[Any]:
    """Scalar cell values of a row (nested children/lists included)."""
    if isinstance(data, dict):
        for value in data.values():
            yield from _cells(value)
    elif isinstance(data, (list, tuple)):
        for value in data:
            yield from _cells(value)
    elif data is not None and not isinstance(data, bool):
        yield data


class _RowIndex:
    """Normalised views of the cells of one or more rows, for value lookups."""

    def __init__(self, rows: Iterable[dict[str, Any]]) -> None:
        self.ints: set[int] = set()
        self.texts: list[str] = []
        self.paths: list[str] = []
        self.ips: set[str] = set()
        for row in rows:
            for cell in _cells(row):
                if isinstance(cell, int):
                    self.ints.add(cell)
                text = str(cell).strip()
                if not text:
                    continue
                if re.fullmatch(r"-?\d+", text):
                    self.ints.add(int(text))
                elif re.fullmatch(r"0x[0-9a-fA-F]+", text):
                    self.ints.add(int(text, 16))
                self.texts.append(_norm_text(text))
                if "\\" in text or "/" in text:
                    self.paths.append(_norm_path(text))
                for m in _IPV4.finditer(text):
                    if ip := _canon_ip(m.group(1)):
                        self.ips.add(ip)
                if ":" in text and (ip := _canon_ip(text)):
                    self.ips.add(ip)

    def supports(self, kind: str, value: str) -> bool:
        if kind == "number":
            return int(value) in self.ints
        if kind == "hex":
            return int(value, 16) in self.ints or any(value.casefold() in t for t in self.texts)
        if kind == "ip":
            return _canon_ip(value) in self.ips
        if kind == "path":
            claim = _norm_path(value)
            return any(
                claim in cell or (cell.count("\\") >= 2 and claim.endswith(cell))
                for cell in self.paths
            )
        needle = _norm_text(value)
        if kind == "file":
            trunc = _rules().truncated_name
            return any(
                needle in cell
                or (len(cell) >= trunc and " " not in cell and needle.startswith(cell))
                for cell in self.texts
            )
        return any(needle in cell for cell in self.texts)


def citation_status(citation: dict[str, Any]) -> str:
    """One of SUPPORTED, UNSUPPORTED, UNCHECKED or NOT_FOUND."""
    if not citation.get("valid"):
        return NOT_FOUND
    return str(citation.get("support") or UNCHECKED)


def _describe(kind: str, value: str) -> str:
    return f"PID/port {value}" if kind == "number" else value


def validate_citations(session: Session, text: str) -> list[dict[str, Any]]:
    """Check that every cited row exists and supports the values stated next to it.

    Each citation dict: ``key``, ``run_id``, ``row_idx``, ``valid`` (row exists), ``url``,
    ``support`` (see the constants above), ``checked`` (values checked against it) and
    ``unsupported_values`` (values not found in the cited rows of their sentence).
    """
    keys = extract_citations(text)
    pairs = [p for k in keys if (p := parse_key(k)) is not None]
    rows: dict[tuple[int, int], dict[str, Any]] = {}
    # Tree plugins (pstree): a row's direct parent and children are part of what it shows
    # ("services.exe runs under wininit.exe [R1:4]"), so they count as support too.
    tree: dict[tuple[int, int], list[dict[str, Any]]] = {}
    if pairs:
        stmt = select(
            ResultRow.run_id, ResultRow.row_idx, ResultRow.parent_idx, ResultRow.data
        ).where(tuple_(ResultRow.run_id, ResultRow.row_idx).in_(pairs))
        parents: dict[tuple[int, int], tuple[int, int]] = {}
        for r, i, parent, data in session.execute(stmt).all():
            rows[(r, i)] = data or {}
            tree[(r, i)] = []
            if parent is not None:
                parents[(r, i)] = (r, parent)
        neighbours = select(
            ResultRow.run_id, ResultRow.row_idx, ResultRow.parent_idx, ResultRow.data
        ).where(
            tuple_(ResultRow.run_id, ResultRow.row_idx).in_(list(parents.values()) or [(-1, -1)])
            | tuple_(ResultRow.run_id, ResultRow.parent_idx).in_(list(rows) or [(-1, -1)])
        )
        for r, i, parent, data in session.execute(neighbours).all():
            for key, parent_key in parents.items():
                if parent_key == (r, i):
                    tree[key].append(data or {})
            if parent is not None and (r, parent) in tree:
                tree[(r, parent)].append(data or {})

    checked: dict[tuple[int, int], list[str]] = {p: [] for p in pairs}
    unsupported: dict[tuple[int, int], list[str]] = {p: [] for p in pairs}
    for sentence in _SENTENCE_SPLIT.split(text or ""):
        cited = [p for k in extract_citations(sentence) if (p := parse_key(k)) in rows]
        if not cited:
            continue
        values = extract_values(sentence)
        if not values:
            continue
        index = _RowIndex([rows[p] for p in cited] + [n for p in cited for n in tree[p]])
        missing = [_describe(k, v) for k, v in values if not index.supports(k, v)]
        for p in cited:
            for k, v in values:
                if _describe(k, v) not in checked[p]:
                    checked[p].append(_describe(k, v))
            unsupported[p] += [m for m in missing if m not in unsupported[p]]

    out = []
    for r, i in pairs:
        exists = (r, i) in rows
        if not exists:
            support = NOT_FOUND
        elif unsupported[(r, i)]:
            support = UNSUPPORTED
        elif checked[(r, i)]:
            support = SUPPORTED
        else:
            support = UNCHECKED
        out.append(
            {
                "key": f"R{r}:{i}",
                "run_id": r,
                "row_idx": i,
                "valid": exists,
                "url": citation_url(r, i),
                "support": support,
                "checked": checked[(r, i)],
                "unsupported_values": unsupported[(r, i)],
            }
        )
    return out
