"""Post-run hook engine: registry/discovery, staging semantics, error isolation, re-runs,
follow-up guards, worker/API/UI integration and AI context."""

from __future__ import annotations

import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.jobs import worker as worker_mod
from app.jobs.worker import Worker
from app.models import Evidence, ResultRow, Run, RunOrigin, RunStatus
from app.services import evidence as evidence_service
from app.services import runs as runs_service
from app.tools import hooks
from app.tools.base import ToolRequest
from app.tools.hooks import HookContext, HookSpec
from tests.test_backend_fakes import FakeRunner, install_fake_runner, make_fake_execute

PSLIST = "windows.pslist.PsList"
INFO = "windows.info.Info"


# ------------------------------------------------------------------------------- fixtures


@pytest.fixture
def registry() -> Iterator[None]:
    """Real hooks loaded; any hooks a test registers are removed afterwards."""
    hooks.load_hooks()
    saved = dict(hooks._registry)
    yield
    hooks._registry.clear()
    hooks._registry.update(saved)


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    return install_fake_runner(monkeypatch)


@pytest.fixture
def evidence(session: Session) -> Evidence:
    (ev,) = evidence_service.scan_evidence(session)
    return ev


def make_run(
    session: Session,
    evidence: Evidence,
    plugin: str = PSLIST,
    rows: list[dict[str, Any]] | None = None,
    args: dict[str, Any] | None = None,
    status: RunStatus = RunStatus.SUCCEEDED,
) -> Run:
    rows = rows if rows is not None else [{"PID": 4, "Name": "System"}, {"PID": 8, "Name": "x"}]
    run = Run(
        evidence_id=evidence.id,
        plugin=plugin,
        args=args or {},
        status=status,
        row_count=len(rows),
    )
    session.add(run)
    session.flush()
    session.add_all(ResultRow(run_id=run.id, row_idx=i, data=data) for i, data in enumerate(rows))
    session.commit()
    return run


def add_hook(func, *plugins: str, name: str | None = None) -> HookSpec:  # noqa: ANN001
    return hooks.register(
        HookSpec(name=name or func.__name__, func=func, plugins=plugins or (PSLIST,))
    )


def annotations(session: Session, run: Run) -> dict[int, Any]:
    session.expire_all()
    return {
        r.row_idx: r.annotations
        for r in session.scalars(select(ResultRow).where(ResultRow.run_id == run.id))
        if r.annotations
    }


# ------------------------------------------------------------------------------- registry


def test_decorator_registers_and_matches(registry: None) -> None:
    @hooks.post_run(PSLIST, "windows.psscan.PsScan", version="3")
    def my_hook(ctx: HookContext) -> None:
        """Flags things."""

    spec = next(h for h in hooks.registered_hooks() if h.func is my_hook)
    assert spec.name == "test_hooks.my_hook"
    assert spec.version == "3" and spec.description == "Flags things."
    assert spec.matches("volatility3", PSLIST) and not spec.matches("volatility3", INFO)
    assert not spec.matches("other-tool", PSLIST)

    @hooks.post_run("*")
    def everything(ctx: HookContext) -> None: ...

    names = [h.name for h in hooks.hooks_for("volatility3", INFO)]
    assert "test_hooks.everything" in names and "test_hooks.my_hook" not in names
    assert names == sorted(names)


def test_duplicate_name_rejected(registry: None) -> None:
    add_hook(lambda ctx: None, name="dup")
    with pytest.raises(ValueError, match="duplicate"):
        hooks.register(HookSpec(name="dup", func=print, plugins=(PSLIST,)))
    with pytest.raises(ValueError):
        hooks.post_run()


def test_discovery_loads_package_and_reports_broken_modules(
    registry: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pkg = tmp_path / "myhooks"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "good.py").write_text(
        textwrap.dedent(
            """
            from app.tools.hooks import post_run

            @post_run("windows.pslist.PsList")
            def discovered(ctx):
                pass
            """
        )
    )
    (pkg / "broken.py").write_text("raise RuntimeError('boom at import')\n")
    (pkg / "_private.py").write_text("raise RuntimeError('must not be imported')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(hooks, "HOOK_PACKAGES", ("myhooks",))
    try:
        errors = hooks.load_hooks(force=True)
        assert "good.discovered" in {h.name for h in hooks.registered_hooks()}
        assert list(errors) == ["myhooks.broken"] and "boom at import" in errors["myhooks.broken"]
    finally:
        for mod in [m for m in sys.modules if m.startswith("myhooks")]:
            del sys.modules[mod]
        hooks._loaded = False


def test_example_windows_info_hook_is_discovered(registry: None) -> None:
    assert "windows.info.record_os_info" in [h.name for h in hooks.hooks_for("volatility3", INFO)]
    assert hooks.load_errors() == {}


# ------------------------------------------------------------------------------- running


def test_hook_outputs_are_applied(registry: None, session: Session, evidence: Evidence) -> None:
    def flagger(ctx: HookContext) -> None:
        rows = list(ctx.rows())
        assert [r.data["PID"] for r in rows] == [4, 8]
        ctx.annotate(1, "odd", severity="medium", note="why")
        ctx.annotate(1, "second", severity="low")
        ctx.add_finding("One odd process", detail="check it", severity="medium", rows=[1])
        ctx.update_evidence_metadata(os="windows", build=19041)

    add_hook(flagger)
    run = make_run(session, evidence)
    results = hooks.run_hooks(session, run.id)

    assert results[0]["status"] == "ok" and results[0]["hook"] == "flagger"
    assert results[0]["annotated_rows"] == 1 and results[0]["findings"] == 1
    assert results[0]["metadata_keys"] == ["build", "os"]
    ann = annotations(session, run)
    assert list(ann) == [1]
    assert [a["tag"] for a in ann[1]] == ["odd", "second"]
    assert ann[1][0] == {"hook": "flagger", "tag": "odd", "severity": "medium", "note": "why"}
    session.refresh(run)
    assert run.status == RunStatus.SUCCEEDED
    assert run.findings == [
        {
            "hook": "flagger",
            "title": "One odd process",
            "detail": "check it",
            "severity": "medium",
            "rows": [1],
        }
    ]
    assert run.hook_results == results
    session.refresh(evidence)
    assert evidence.os_info == {"os": "windows", "build": 19041}


def test_failing_hook_is_isolated(registry: None, session: Session, evidence: Evidence) -> None:
    def a_breaks(ctx: HookContext) -> None:
        ctx.annotate(0, "staged-before-crash")
        ctx.add_finding("never applied")
        raise KeyError("Missing column")

    def b_works(ctx: HookContext) -> None:
        ctx.annotate(0, "ok")

    add_hook(a_breaks)
    add_hook(b_works)
    run = make_run(session, evidence)
    results = hooks.run_hooks(session, run.id)

    by_name = {r["hook"]: r for r in results}
    assert by_name["a_breaks"]["status"] == "error"
    assert "KeyError" in by_name["a_breaks"]["error"] and "a_breaks" in by_name["a_breaks"]["error"]
    assert by_name["b_works"]["status"] == "ok"
    assert [a["tag"] for a in annotations(session, run)[0]] == ["ok"]  # nothing from a_breaks
    session.refresh(run)
    assert run.status == RunStatus.SUCCEEDED and run.findings is None


@pytest.mark.parametrize(
    "bad_call",
    [
        lambda ctx: ctx.annotate(99, "x"),
        lambda ctx: ctx.annotate(0, ""),
        lambda ctx: ctx.annotate(0, "x", severity="critical"),
        lambda ctx: ctx.add_finding("x", rows=[5]),
        lambda ctx: ctx.add_finding("  "),
        lambda ctx: ctx.update_evidence_metadata(bad=object()),
        lambda ctx: list(ctx.rows(run_id=12345)),
    ],
)
def test_invalid_staging_calls_fail_the_hook(
    registry: None, session: Session, evidence: Evidence, bad_call
) -> None:  # noqa: ANN001
    add_hook(bad_call, name="bad")
    run = make_run(session, evidence)
    (result,) = hooks.run_hooks(session, run.id)
    assert result["status"] == "error"


def test_rerun_replaces_previous_outputs(
    registry: None, session: Session, evidence: Evidence
) -> None:
    calls = {"n": 0}

    def counter(ctx: HookContext) -> None:
        calls["n"] += 1
        ctx.annotate(0, f"pass{calls['n']}")
        ctx.add_finding(f"pass {calls['n']}")

    add_hook(counter)
    run = make_run(session, evidence)
    hooks.run_hooks(session, run.id)
    hooks.run_hooks(session, run.id)
    assert [a["tag"] for a in annotations(session, run)[0]] == ["pass2"]
    session.refresh(run)
    assert [f["title"] for f in run.findings] == ["pass 2"]
    assert len(run.hook_results) == 1


def test_no_matching_hooks_clears_and_returns_empty(
    registry: None, session: Session, evidence: Evidence
) -> None:
    run = make_run(session, evidence, plugin="windows.pstree.PsTree")
    assert hooks.run_hooks(session, run.id) == []


def test_run_must_have_succeeded_and_hooks_can_be_disabled(
    registry: None, session: Session, evidence: Evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_hook(lambda ctx: ctx.annotate(0, "x"), name="x")
    failed = make_run(session, evidence, status=RunStatus.FAILED)
    with pytest.raises(ValueError, match="not succeeded"):
        hooks.run_hooks(session, failed.id)
    with pytest.raises(LookupError):
        hooks.run_hooks(session, 999)
    monkeypatch.setenv("FT_HOOKS_ENABLED", "false")
    get_settings.cache_clear()
    run = make_run(session, evidence)
    assert hooks.run_hooks(session, run.id) == []
    assert annotations(session, run) == {}


def test_cross_run_reads(registry: None, session: Session, evidence: Evidence) -> None:
    other = make_run(session, evidence, plugin=INFO, rows=[{"Variable": "A", "Value": "1"}])
    seen: dict[str, Any] = {}

    def reader(ctx: HookContext) -> None:
        info = ctx.latest_run(INFO)
        seen["info"] = info
        seen["rows"] = [r.data for r in ctx.rows(info.id)]
        seen["missing"] = ctx.latest_run("windows.nope.Nope")

    add_hook(reader)
    run = make_run(session, evidence)
    hooks.run_hooks(session, run.id)
    assert seen["info"].id == other.id and seen["rows"] == [{"Variable": "A", "Value": "1"}]
    assert seen["missing"] is None


# ------------------------------------------------------------------------------- follow-ups


def test_follow_ups_are_queued_with_provenance_and_deduplicated(
    registry: None, session: Session, evidence: Evidence, fake_runner: FakeRunner
) -> None:
    def chain(ctx: HookContext) -> None:
        ctx.queue_follow_up(PSLIST, {"pid": [8]}, reason="look closer")
        ctx.queue_follow_up("windows.not.Allowed", {})
        ctx.queue_follow_up(PSLIST, {"bogus": 1})

    add_hook(chain, PSLIST)
    run = make_run(session, evidence)
    (result,) = hooks.run_hooks(session, run.id)

    assert result["status"] == "ok"
    (child_id,) = result["follow_ups_queued"]
    child = session.get(Run, child_id)
    assert child.status == RunStatus.QUEUED and child.origin == RunOrigin.HOOK
    assert child.args == {"pid": [8]} and child.parent_run_id == run.id
    assert child.triggered_by_hook == "chain" and child.chain_depth == 1
    skipped = [s["skipped"] for s in result["follow_ups_skipped"]]
    assert len(skipped) == 2 and all(s.startswith("not allowed") for s in skipped)

    # Re-running hooks does not queue the same follow-up twice.
    (again,) = hooks.run_hooks(session, run.id)
    assert again["follow_ups_queued"] == []
    assert again["follow_ups_skipped"][0]["skipped"] == f"duplicate of run {child_id}"


def test_follow_up_chain_depth_limit(
    registry: None,
    session: Session,
    evidence: Evidence,
    fake_runner: FakeRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FT_HOOK_MAX_CHAIN_DEPTH", "1")
    get_settings.cache_clear()

    def chain(ctx: HookContext) -> None:
        ctx.queue_follow_up(PSLIST, {"pid": [ctx.chain_depth + 100]})

    add_hook(chain, PSLIST)
    root = make_run(session, evidence)
    (r1,) = hooks.run_hooks(session, root.id)
    child = session.get(Run, r1["follow_ups_queued"][0])
    # Simulate the child finishing: its hooks must not queue a grandchild (depth 2 > 1).
    child.status = RunStatus.SUCCEEDED
    session.commit()
    (r2,) = hooks.run_hooks(session, child.id)
    assert r2["follow_ups_queued"] == []
    assert "max chain depth 1" in r2["follow_ups_skipped"][0]["skipped"]


def test_follow_up_budget_and_kill_switch(
    registry: None,
    session: Session,
    evidence: Evidence,
    fake_runner: FakeRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FT_HOOK_MAX_FOLLOWUPS_PER_RUN", "2")
    get_settings.cache_clear()

    def many(ctx: HookContext) -> None:
        for pid in range(5):
            ctx.queue_follow_up(PSLIST, {"pid": [pid]})

    add_hook(many, PSLIST)
    run = make_run(session, evidence)
    (result,) = hooks.run_hooks(session, run.id)
    assert len(result["follow_ups_queued"]) == 2
    assert len(result["follow_ups_skipped"]) == 3

    monkeypatch.setenv("FT_HOOK_FOLLOWUPS_ENABLED", "false")
    get_settings.cache_clear()
    other = make_run(session, evidence, args={"pid": [77]})
    (off,) = hooks.run_hooks(session, other.id)
    assert off["follow_ups_queued"] == [] and "disabled" in off["follow_ups_skipped"][0]["skipped"]


# ------------------------------------------------------------------------------- worker


def test_worker_runs_hooks_after_success(
    registry: None,
    session: Session,
    evidence: Evidence,
    fake_runner: FakeRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def flag_system(ctx: HookContext) -> None:
        for row in ctx.rows():
            if row.data.get("PID") == 4:
                ctx.annotate(row.row_idx, "system")

    def broken(ctx: HookContext) -> None:
        raise RuntimeError("bug in hook")

    add_hook(flag_system)
    add_hook(broken)
    monkeypatch.setattr(worker_mod, "execute", make_fake_execute([{"PID": 4}, {"PID": 5}]))
    run = runs_service.create_run(session, evidence.id, ToolRequest(PSLIST))
    worker = Worker(poll_interval=0.02)
    worker.start()
    try:
        import time

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            session.expire_all()
            run = session.get(Run, run.id)
            if run.hook_results is not None:
                break
            time.sleep(0.02)
    finally:
        worker.stop()
    assert run.status == RunStatus.SUCCEEDED
    assert {h["hook"]: h["status"] for h in run.hook_results} == {
        "broken": "error",
        "flag_system": "ok",
    }
    assert list(annotations(session, run)) == [0]


# ------------------------------------------------------------------------------- example hook


def test_example_windows_info_hook(registry: None, session: Session, evidence: Evidence) -> None:
    rows = [
        {"Variable": "NTBuildLab", "Value": "19041.1.amd64fre.vb_release.191206-1406"},
        {"Variable": "NtMajorVersion", "Value": "10"},
        {"Variable": "NtMinorVersion", "Value": "0"},
        {"Variable": "KeNumberProcessors", "Value": "2"},
    ]
    run = make_run(session, evidence, plugin=INFO, rows=rows)
    results = hooks.run_hooks(session, run.id)
    assert {r["hook"]: r["status"] for r in results}["windows.info.record_os_info"] == "ok"
    session.refresh(evidence)
    assert evidence.os_info["os"] == "windows"
    assert evidence.os_info["nt_version"] == "10.0"
    assert evidence.os_info["processors"] == "2"
    assert evidence.os_info["windows_info"]["NtMajorVersion"] == "10"


# ------------------------------------------------------------------------------- API / UI


def test_api_hooks_rerun_rows_filter_and_reserved_origin(
    registry: None, client: TestClient, session: Session, evidence: Evidence
) -> None:
    add_hook(lambda ctx: ctx.annotate(1, "odd", severity="high"), name="api_hook")
    run = make_run(session, evidence)

    listed = client.get("/api/hooks").json()
    assert "api_hook" in [h["name"] for h in listed["hooks"]]
    assert listed["load_errors"] == {}

    body = client.post(f"/api/runs/{run.id}/hooks/rerun").json()
    assert body["hook_results"][0]["status"] == "ok"
    rows = client.get(f"/api/runs/{run.id}/rows", params={"annotated": True}).json()
    assert rows["total"] == 1 and rows["rows"][0]["annotations"][0]["tag"] == "odd"
    assert client.get(f"/api/runs/{run.id}/rows", params={"tag": "odd"}).json()["total"] == 1
    assert client.get(f"/api/runs/{run.id}/rows", params={"tag": "nope"}).json()["total"] == 0

    failed = make_run(session, evidence, status=RunStatus.FAILED)
    assert client.post(f"/api/runs/{failed.id}/hooks/rerun").status_code == 409
    assert client.post("/api/runs/999/hooks/rerun").status_code == 404
    r = client.post(
        "/api/runs", json={"evidence_id": evidence.id, "plugin": PSLIST, "origin": "hook"}
    )
    assert r.status_code == 422


def test_run_page_shows_post_processing(
    registry: None, client: TestClient, session: Session, evidence: Evidence
) -> None:
    def ok(ctx: HookContext) -> None:
        ctx.annotate(1, "odd<tag>", severity="high", note="<b>note</b>")
        ctx.add_finding("Odd <process>", detail="d", severity="medium", rows=[1])

    def bad(ctx: HookContext) -> None:
        raise ValueError("kaput")

    add_hook(ok)
    add_hook(bad)
    run = make_run(session, evidence)
    hooks.run_hooks(session, run.id)

    page = client.get(f"/runs/{run.id}").text
    assert "Post-processing" in page and "1 post-processing hook(s) failed" in page
    assert "Odd &lt;process&gt;" in page and f"R{run.id}:1" in page  # escaped + cited
    assert "kaput" in page
    assert 'class="annotated sev-high"' in page and "odd&lt;tag&gt;" in page
    assert "<b>note</b>" not in page

    filtered = client.get(f"/runs/{run.id}", params={"tag": "*"}).text
    assert "with any annotation" in filtered and f'id="row-{run.id}-0"' not in filtered

    r = client.post(f"/ui/runs/{run.id}/hooks/rerun")
    assert r.status_code == 200 and "Post-processing re-run: 2 hook(s), 1 failed." in r.text

    evidence_runs = client.get(f"/ui/evidence/{evidence.id}/runs", headers={"HX-Request": "true"})
    assert "1 finding" in evidence_runs.text and "hook error" in evidence_runs.text


def test_ai_context_includes_findings_flags_and_late_flagged_rows(
    registry: None, session: Session, evidence: Evidence
) -> None:
    from app.ai.context import build_context

    rows = [{"PID": i} for i in range(80)]

    def late(ctx: HookContext) -> None:
        ctx.annotate(75, "late-flag", severity="high", note="hidden deep")
        ctx.add_finding("Deep finding", severity="high", rows=[75])

    add_hook(late)
    run = make_run(session, evidence, rows=rows)
    hooks.run_hooks(session, run.id)
    text, refs = build_context(session, evidence.id, max_rows_per_run=10)
    assert "automated findings" in text and "[high] Deep finding" in text
    assert f"[R{run.id}:75]" in text and "late-flag (high): hidden deep" in text
    assert "plus 1 later flagged rows" in text
    assert f"R{run.id}:75" in refs["row_refs_included"]


def test_settings_defaults(settings: Settings) -> None:
    assert settings.hooks_enabled and settings.hook_followups_enabled
    assert settings.hook_max_chain_depth == 2 and settings.hook_max_followups_per_run == 10
