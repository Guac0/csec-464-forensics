"""Status report of the forensics content (``forensics/``): one place for every content check.

Used by ``python -m forensics check`` (app/tools/content_cli.py), the read-only ``/content``
page (app/web/content_pages.py) and tests/test_forensics_content.py.

- ``errors``: things that are broken (skipped at runtime, fail CI).
- ``todo``: things that work but are still EXAMPLE / TODO(forensics) or missing (informational).

Works on the current content root (``content.current()``), so tests can point it at
``tests/content``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.tools import content, hooks

MARKERS = ("TODO(forensics)", "EXAMPLE")
TOOL = "volatility3"


@dataclass
class PluginStatus:
    name: str
    file: str  # e.g. forensics/plugins/windows/pslist.py
    example: bool  # file still has EXAMPLE / TODO(forensics) markers
    args: list[str] = field(default_factory=list)
    presets: int = 0
    auto_enumerate: bool = False
    writes_files: bool = False
    baseline: list[int] = field(default_factory=list)  # baseline orders
    next_steps: int = 0
    compare_keys: list[str] = field(default_factory=list)
    hooks: list[str] = field(default_factory=list)
    ai_rows: str = ""  # "", "settings", "settings + function"
    fixture: str = ""  # relative path, "" if none
    eval_cases: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class FileStatus:
    path: str
    present: bool
    example: bool


@dataclass
class ContentReport:
    root: str
    plugins: list[PluginStatus] = field(default_factory=list)
    prompts: list[FileStatus] = field(default_factory=list)
    citations: FileStatus | None = None
    eval_cases: list[str] = field(default_factory=list)
    baselines: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    todo: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _has_markers(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return any(m in text for m in MARKERS)


def fixture_columns(path: Path) -> set[str]:
    """Columns found in a captured ``vol -r jsonl`` file (raises on unparseable output)."""
    from app.tools.volatility.runner import VolatilityRunner

    return {k for row in VolatilityRunner().parse_output(path) for k in row.data}


def build_report() -> ContentReport:
    from app.ai import prompts
    from app.tools.guide import check_guide
    from app.tools.volatility.runner import VolatilityRunner, catalog_problems

    loaded = content.current()
    root_dir = content.root_dir()
    report = ContentReport(root=loaded.root)
    runner = VolatilityRunner()

    # Files that failed to load at all (no plugin to attach them to).
    for where, errs in sorted(loaded.problems.items()):
        report.errors += [f"{where}: {e}" for e in errs]

    invalid = catalog_problems(loaded.plugins)
    _, guide_problems = check_guide(runner)
    for p in guide_problems:
        report.errors.append(f"guide {p.where}: {p.plugin}: {p.problem}")
    for module, err in sorted(hooks.load_errors().items()):
        report.errors.append(f"hook module {module}: {err}")

    fixtures_dir = root_dir / "fixtures"
    cases_by_plugin: dict[str, list[str]] = {}
    cases_dir = root_dir / "evals" / "cases"
    try:
        from evals.cases import CaseError, load_cases
    except ImportError:  # evals/ is dev tooling, not in the Docker image
        load_cases = None
        report.todo.append("evaluation cases not checked here (evals/ is not installed)")
    if cases_dir.is_dir() and load_cases is not None:
        try:
            cases = load_cases(cases_dir=cases_dir)
        except CaseError as exc:
            report.errors.append(f"eval cases: {exc}")
            cases = []
        for case in cases:
            report.eval_cases.append(case.id)
            for run in (*case.runs, *case.available_runs):
                cases_by_plugin.setdefault(run.plugin, []).append(case.id)
            if _has_markers(case.path):
                report.todo.append(f"eval case {case.id} is an EXAMPLE")
    if not report.eval_cases and load_cases is not None:
        report.todo.append("no evaluation cases")
    baselines = root_dir / "evals" / "baselines"
    report.baselines = (
        sorted(p.stem for p in baselines.glob("*.json")) if baselines.is_dir() else []
    )
    if not report.baselines:
        report.todo.append("no saved evaluation baseline (python -m evals.run --save-baseline)")

    for spec in loaded.plugins:
        module = loaded.modules[spec.name]
        path = root_dir / "plugins" / (module.replace(".", "/") + ".py")
        status = PluginStatus(
            name=spec.name,
            file=_rel(path),
            example=_has_markers(path),
            args=[a.name for a in spec.args],
            presets=len(spec.presets),
            auto_enumerate=spec.auto_enumerate,
            writes_files=spec.may_write_files,
            compare_keys=list(spec.compare_keys),
            next_steps=len(loaded.next.get(spec.name, ())),
            hooks=[h.name for h in hooks.hooks_for(TOOL, spec.name)],
            eval_cases=sorted(set(cases_by_plugin.get(spec.name, []))),
        )
        status.baseline = [
            n for n, s in enumerate(loaded.baseline, start=1) if s.plugin == spec.name
        ]
        rules = loaded.ai.get(spec.name)
        if rules:
            status.ai_rows = "settings + function" if rules.select else "settings"
        status.errors += invalid.get(spec.name, [])
        if module != content.expected_module(spec.name):
            expected = content.expected_module(spec.name).replace(".", "/")
            status.errors.append(f"file should be plugins/{expected}.py")

        fixture = fixtures_dir / (module.replace(".", "/") + ".jsonl")
        if fixture.is_file():
            status.fixture = _rel(fixture)
            try:
                columns = fixture_columns(fixture)
            except Exception as exc:  # noqa: BLE001
                status.errors.append(f"fixture {fixture.name} does not parse: {exc}")
                columns = None
            if columns is not None:
                if not columns:
                    status.errors.append(f"fixture {fixture.name} has no rows")
                named = {
                    "compare_keys": set(spec.compare_keys),
                    "compare_ignore": set(spec.compare_ignore),
                    "ai_context columns": set(rules.settings.columns) if rules else set(),
                }
                for what, cols in named.items():
                    missing = sorted(cols - columns)
                    if columns and missing:
                        status.errors.append(f"{what} {missing} not in its fixture output")
        report.errors += [f"{status.file} ({spec.name}): {e}" for e in status.errors]
        if status.example:
            report.todo.append(f"{status.file}: still has EXAMPLE / TODO(forensics) notes")
        if not status.fixture:
            report.todo.append(f"{spec.name}: no captured output in fixtures/")
        report.plugins.append(status)

    # Fixtures without a plugin file.
    known = {loaded.modules[s.name] for s in loaded.plugins}
    if fixtures_dir.is_dir():
        for path in sorted(fixtures_dir.rglob("*.jsonl")):
            rel = ".".join(path.relative_to(fixtures_dir).with_suffix("").parts)
            if rel not in known:
                report.errors.append(
                    f"{_rel(path)}: no plugin file plugins/{rel.replace('.', '/')}.py"
                )

    # Stray plugin files outside an OS folder.
    for path in sorted((root_dir / "plugins").glob("*.py")):
        if not path.name.startswith("_"):
            report.errors.append(
                f"{_rel(path)}: plugin files belong in an OS folder (plugins/windows/)"
            )

    for name in prompts.GUIDANCE_FILES:
        path = root_dir / "prompts" / f"{name}.md"
        status = FileStatus(_rel(path), bool(prompts.guidance(name)), _has_markers(path))
        report.prompts.append(status)
        if not status.present:
            report.errors.append(f"{status.path}: missing or empty")
        elif status.example:
            report.todo.append(f"{status.path}: still an EXAMPLE")
    question = prompts.run_summary_question(5, "windows.x.X")
    if "R5" not in question or "windows.x.X" not in question:
        report.errors.append("prompts/run_summary.md: must contain {run_id} and {plugin}")

    path = root_dir / "citations.py"
    report.citations = FileStatus(_rel(path), loaded.citations is not None, _has_markers(path))
    if loaded.citations is None:
        report.errors.append(f"{_rel(path)}: missing")
    else:
        mod = loaded.citations
        if not all(isinstance(e, str) and e for e in getattr(mod, "FILE_EXTENSIONS", [""])):
            report.errors.append("citations.py: FILE_EXTENSIONS must be a list of non-empty text")
        if not all(isinstance(w, str) and w for w in getattr(mod, "NUMBER_LABELS", [""])):
            report.errors.append("citations.py: NUMBER_LABELS must be a list of non-empty text")
        trunc = getattr(mod, "TRUNCATED_NAME_LENGTH", None)
        if not isinstance(trunc, int) or trunc <= 0:
            report.errors.append("citations.py: TRUNCATED_NAME_LENGTH must be a positive number")
        if report.citations.example:
            report.todo.append(f"{report.citations.path}: not reviewed yet (TODO)")
    return report


def to_text(report: ContentReport) -> str:
    lines = [f"Forensics content check ({report.root})", ""]
    lines.append(f"Plugins: {len(report.plugins)}")
    for p in report.plugins:
        flags = []
        if p.example:
            flags.append("EXAMPLE")
        if p.auto_enumerate:
            flags.append("auto")
        if p.baseline:
            flags.append(f"baseline #{','.join(map(str, p.baseline))}")
        if p.next_steps:
            flags.append(f"{p.next_steps} next")
        if p.hooks:
            flags.append(f"{len(p.hooks)} hook(s)")
        if p.fixture:
            flags.append("fixture")
        if p.ai_rows:
            flags.append(f"AI rows: {p.ai_rows}")
        mark = "FAIL" if p.errors else "ok  "
        lines.append(f"  {mark} {p.name}  [{', '.join(flags)}]")
    lines += ["", f"Evaluation cases: {len(report.eval_cases)}; baselines: "
              f"{', '.join(report.baselines) or 'none'}"]  # fmt: skip
    lines += ["", f"Errors ({len(report.errors)}):"]
    lines += [f"  - {e}" for e in report.errors] or ["  none"]
    lines += ["", f"Still to do ({len(report.todo)}):"]
    lines += [f"  - {t}" for t in report.todo] or ["  nothing"]
    return "\n".join(lines) + "\n"
