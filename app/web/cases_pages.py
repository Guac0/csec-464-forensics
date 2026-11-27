"""Temporary UI: case pages and sharing actions (see app/services/cases.py, sharing.py)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Evidence, SharedItem
from app.services import cases as cases_svc
from app.services import sharing
from app.web.pages import (
    FormDep,
    SessionDep,
    list_scoped_notes,
    redirect,
    render,
    same_origin_post,
)

router = APIRouter(include_in_schema=False)


def _int(value: str | None) -> int | None:
    value = (value or "").strip()
    return int(value) if value.isdigit() else None


def _safe_next(value: str | None, fallback: str) -> str:
    """Only same-site relative paths (no open redirects)."""
    value = (value or "").strip()
    if value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return fallback


def _case_or_404(session: Session, case_id: int):  # noqa: ANN202
    try:
        return cases_svc.get_case(session, case_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


def _case_page(
    request: Request, session: Session, case_id: int, error: str | None = None, status: int = 200
) -> HTMLResponse:
    case = _case_or_404(session, case_id)
    members = cases_svc.member_evidence(session, case_id)
    member_ids = {ev.id for ev, _ in members}
    others = [
        ev
        for ev in session.scalars(select(Evidence).order_by(Evidence.rel_path))
        if ev.id not in member_ids
    ]
    from app.services import indicators

    return render(
        request,
        "case.html",
        status_code=status,
        case=case,
        members=members,
        indicators=indicators.list_indicators(session, case_id),
        hit_counts=indicators.hit_counts(session, case_id),
        unchecked=indicators.unchecked_count(session, case_id),
        check_job=indicators.job_state(case_id),
        indicator_types=[t.value for t in indicators.IndicatorType],
        comparisons=_saved_comparisons(session, case_id),
        other_evidence=others,
        shared=sharing.resolved_for_case(session, case_id),
        notes=list_scoped_notes(session, None, case_id),
        note_case_id=case_id,
        evidence_id=None,
        case_labels=cases_svc.labels(session, case_id),
        error=error,
        active_case_id=case_id,
        case_q=f"?case={case_id}",
    )


def _saved_comparisons(session: Session, case_id: int) -> list[tuple[Any, str]]:
    """(saved comparison, its page URL)."""
    from app.services import compare

    return [(s, compare.url(case_id, s)) for s in compare.list_saved(session, case_id)]


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_page(request: Request, case_id: int, session: SessionDep) -> HTMLResponse:
    return _case_page(request, session, case_id)


@router.post("/ui/cases", dependencies=[Depends(same_origin_post)])
def ui_case_create(form: FormDep, session: SessionDep) -> Response:
    try:
        case = cases_svc.create_case(session, form.get("name") or "", form.get("description") or "")
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return redirect(f"/cases/{case.id}")


@router.post("/ui/cases/{case_id}/edit", dependencies=[Depends(same_origin_post)])
def ui_case_edit(request: Request, case_id: int, form: FormDep, session: SessionDep) -> Response:
    try:
        cases_svc.update_case(session, case_id, form.get("name"), form.get("description"))
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        session.rollback()
        return _case_page(request, session, case_id, error=str(exc), status=422)
    return redirect(f"/cases/{case_id}")


@router.post("/ui/cases/{case_id}/delete", dependencies=[Depends(same_origin_post)])
def ui_case_delete(request: Request, case_id: int, session: SessionDep) -> Response:
    try:
        cases_svc.delete_case(session, case_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        session.rollback()
        return _case_page(request, session, case_id, error=f"Cannot delete: {exc}", status=409)
    return redirect("/")


@router.post("/ui/cases/{case_id}/members", dependencies=[Depends(same_origin_post)])
def ui_member_add(request: Request, case_id: int, form: FormDep, session: SessionDep) -> Response:
    evidence_id = _int(form.get("evidence_id"))
    if evidence_id is None:
        return _case_page(request, session, case_id, error="Choose an image.", status=422)
    try:
        cases_svc.add_evidence(session, case_id, evidence_id, form.get("label") or "")
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        session.rollback()
        return _case_page(request, session, case_id, error=str(exc), status=409)
    return redirect(f"/cases/{case_id}#images")


@router.post(
    "/ui/cases/{case_id}/members/{evidence_id}/label", dependencies=[Depends(same_origin_post)]
)
def ui_member_label(
    request: Request, case_id: int, evidence_id: int, form: FormDep, session: SessionDep
) -> Response:
    try:
        cases_svc.set_label(session, case_id, evidence_id, form.get("label") or "")
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        session.rollback()
        return _case_page(request, session, case_id, error=str(exc), status=422)
    return redirect(f"/cases/{case_id}#images")


@router.post(
    "/ui/cases/{case_id}/members/{evidence_id}/remove", dependencies=[Depends(same_origin_post)]
)
def ui_member_remove(case_id: int, evidence_id: int, session: SessionDep) -> Response:
    try:
        cases_svc.remove_evidence(session, case_id, evidence_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return redirect(f"/cases/{case_id}#images")


@router.post("/ui/share", dependencies=[Depends(same_origin_post)])
def ui_share(request: Request, form: FormDep, session: SessionDep) -> Response:
    """Share a row / finding / note / AI answer to a case (from the share dialog)."""
    case_id = _int(form.get("case_id"))
    back = _safe_next(form.get("next"), "/")
    if case_id is None:
        raise HTTPException(422, "choose a case")
    try:
        sharing.share(
            session,
            case_id,
            form.get("kind") or "",
            comment=form.get("comment") or "",
            run_id=_int(form.get("run_id")),
            row_idx=_int(form.get("row_idx")),
            finding_index=_int(form.get("finding_index")),
            note_id=_int(form.get("note_id")),
            ai_message_id=_int(form.get("ai_message_id")),
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        session.rollback()
        raise HTTPException(409, str(exc)) from exc
    return redirect(back)


@router.post("/ui/shared/{item_id}/remove", dependencies=[Depends(same_origin_post)])
def ui_unshare(item_id: int, form: FormDep, session: SessionDep) -> Response:
    item = session.get(SharedItem, item_id)
    if item is None:
        raise HTTPException(404, "shared item not found")
    case_id = item.case_id
    sharing.unshare(session, item_id, reason=(form.get("reason") or "").strip())
    return redirect(_safe_next(form.get("next"), f"/cases/{case_id}#shared"))


# --------------------------------------------------------------------------------- indicators


@router.post("/ui/indicators", dependencies=[Depends(same_origin_post)])
def ui_indicator_add(request: Request, form: FormDep, session: SessionDep) -> Response:
    """Add an indicator to a case (from the case page or the "indicator from row" dialog)."""
    from app.services import indicators

    case_id = _int(form.get("case_id"))
    if case_id is None:
        raise HTTPException(422, "choose a case")
    back = _safe_next(form.get("next"), f"/cases/{case_id}#indicators")
    column = (form.get("column") or "").strip() if form.get("only_column") else ""
    try:
        indicators.add_indicator(
            session,
            case_id,
            form.get("type") or "",
            form.get("value") or "",
            mode=form.get("match_mode") or "exact",
            column=column,
            comment=form.get("comment") or "",
            source_key=(form.get("source_key") or "").strip(),
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        session.rollback()
        if back.startswith(f"/cases/{case_id}"):
            return _case_page(
                request, session, case_id, error=f"Indicator not added: {exc}", status=422
            )
        raise HTTPException(422, f"Indicator not added: {exc}") from exc
    return redirect(back)


@router.post("/ui/indicators/{indicator_id}/remove", dependencies=[Depends(same_origin_post)])
def ui_indicator_remove(indicator_id: int, session: SessionDep) -> Response:
    from app.services import indicators

    try:
        case_id = indicators.remove_indicator(session, indicator_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return redirect(f"/cases/{case_id}#indicators")


@router.post("/ui/cases/{case_id}/indicators/check", dependencies=[Depends(same_origin_post)])
def ui_indicator_check(request: Request, case_id: int, session: SessionDep) -> Response:
    from app.services import indicators
    from app.web.pages import is_htmx

    _case_or_404(session, case_id)
    started = indicators.start_case_check(case_id)
    if not is_htmx(request):
        return redirect(f"/cases/{case_id}#indicators")
    return render(
        request,
        "_indicator_check.html",
        case_id=case_id,
        job=indicators.job_state(case_id) | ({} if started else {"busy": True}),
    )


@router.get("/ui/cases/{case_id}/indicators/check-status", response_class=HTMLResponse)
def ui_indicator_check_status(request: Request, case_id: int) -> HTMLResponse:
    from app.services import indicators

    return render(
        request, "_indicator_check.html", case_id=case_id, job=indicators.job_state(case_id)
    )


@router.get("/ui/indicators/from-row", response_class=HTMLResponse)
def ui_indicator_from_row(
    request: Request, session: SessionDep, run_id: int, row_idx: int
) -> HTMLResponse:
    """Body of the "make an indicator from this row" dialog: the row's values with a guessed
    type each."""
    from app.models import ResultRow, Run
    from app.services import indicators
    from app.web.pages import request_case_id

    run = session.get(Run, run_id)
    row = session.scalar(
        select(ResultRow).where(ResultRow.run_id == run_id, ResultRow.row_idx == row_idx)
    )
    if run is None or row is None:
        raise HTTPException(404, "row not found")
    image_cases = cases_svc.cases_for_evidence(session, run.evidence_id)
    active = request_case_id(request)
    targets = [(c, label) for c, label in image_cases if c.id == active] or image_cases
    cells = [
        (column, str(value), indicators.guess_type(str(value)).value)
        for column, value in (row.data or {}).items()
        if column != "__children"
        and value is not None
        and not isinstance(value, (dict, list, bool))
        and str(value).strip()
    ]
    return render(
        request,
        "_indicator_from_row.html",
        run=run,
        row_idx=row_idx,
        cells=cells,
        targets=targets,
        types=[t.value for t in indicators.IndicatorType],
    )


# --------------------------------------------------------------------------------- comparison


def _compare_inputs(request: Request, session: Session, case_id: int) -> dict[str, Any]:
    """Resolve the comparison page's query parameters into runs + settings (or a form state)."""
    from app.services import compare

    q = request.query_params
    members = cases_svc.member_evidence(session, case_id)
    member_ids = {ev.id for ev, _ in members}
    state: dict[str, Any] = {
        "members": members,
        "a": _int(q.get("a")),
        "b": _int(q.get("b")),
        "plugin": (q.get("plugin") or "").strip(),
        "cmp": None,
        "error": None,
    }
    run_a_id, run_b_id = _int(q.get("run_a")), _int(q.get("run_b"))
    try:
        if run_a_id and run_b_id:
            run_a, run_b = compare.get_run(session, run_a_id), compare.get_run(session, run_b_id)
            state.update(a=run_a.evidence_id, b=run_b.evidence_id, plugin=run_a.plugin)
        elif state["a"] and state["b"] and state["plugin"]:
            runs_a = compare.runs_for(session, state["a"], state["plugin"])
            runs_b = compare.runs_for(session, state["b"], state["plugin"])
            if not runs_a or not runs_b:
                raise compare.CompareError(
                    f"{state['plugin']} has no finished run on both images; run it on each first"
                )
            run_a, run_b = runs_a[0], runs_b[0]
        else:
            if state["a"] and state["b"]:
                state["plugins"] = compare.comparable_plugins(session, state["a"], state["b"])
            return state
        if run_a.evidence_id not in member_ids or run_b.evidence_id not in member_ids:
            raise compare.CompareError("both images must be in this case")
        if q.get("custom"):
            cmp = compare.compare(session, run_a, run_b, q.getlist("keys"), q.getlist("ignore"))
        else:
            cmp = compare.compare(session, run_a, run_b)
    except (LookupError, compare.CompareError) as exc:
        state["error"] = str(exc)
        if state["a"] and state["b"]:
            state["plugins"] = compare.comparable_plugins(session, state["a"], state["b"])
        return state
    state.update(
        cmp=cmp,
        runs_a=compare.runs_for(session, cmp.run_a.evidence_id, cmp.run_a.plugin),
        runs_b=compare.runs_for(session, cmp.run_b.evidence_id, cmp.run_b.plugin),
        common=compare.common_columns(cmp.run_a, cmp.run_b),
        plugins=compare.comparable_plugins(session, cmp.run_a.evidence_id, cmp.run_b.evidence_id),
    )
    return state


@router.get("/cases/{case_id}/compare", response_class=HTMLResponse)
def compare_page(request: Request, case_id: int, session: SessionDep) -> HTMLResponse:
    """Before/after comparison of one plugin's results on two images of the case."""
    from app.services import compare

    case = _case_or_404(session, case_id)
    state = _compare_inputs(request, session, case_id)
    cmp = state["cmp"]
    ctx: dict[str, Any] = {}
    if cmp is not None:
        lim = compare.DISPLAY_LIMIT
        ctx = {
            "data_a": compare.rows(
                session, cmp.run_a.id, cmp.only_a[:lim] + [a for a, _, _ in cmp.changed[:lim]]
            ),
            "data_b": compare.rows(
                session, cmp.run_b.id, cmp.only_b[:lim] + [b for _, b, _ in cmp.changed[:lim]]
            ),
            "limit": lim,
            "csv_url": compare.url(case_id, cmp).replace("/compare?", "/compare.csv?", 1),
            "keys_json": json.dumps(cmp.keys),
            "ignore_json": json.dumps(cmp.ignored),
            "ev_a": session.get(Evidence, cmp.run_a.evidence_id),
            "ev_b": session.get(Evidence, cmp.run_b.evidence_id),
        }
    return render(
        request,
        "compare.html",
        case=case,
        labels=cases_svc.labels(session, case_id),
        active_case_id=case_id,
        case_q=f"?case={case_id}",
        **state,
        **ctx,
    )


@router.get("/cases/{case_id}/compare.csv")
def compare_csv(request: Request, case_id: int, session: SessionDep) -> Response:
    from app.services import audit, compare

    _case_or_404(session, case_id)
    state = _compare_inputs(request, session, case_id)
    cmp = state["cmp"]
    if cmp is None:
        raise HTTPException(422, state["error"] or "choose two images and a plugin")
    body = compare.to_csv(session, cmp)
    audit.record(
        session,
        "comparison.export",
        category=audit.KEY_READ,
        object_type="case",
        object_id=case_id,
        summary=f"Downloaded comparison of runs {cmp.run_a.id} and {cmp.run_b.id} as CSV",
        details={"run_a": cmp.run_a.id, "run_b": cmp.run_b.id, "counts": cmp.counts},
    )
    session.commit()
    name = f"compare-run{cmp.run_a.id}-run{cmp.run_b.id}.csv"
    return Response(
        body,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/ui/cases/{case_id}/comparisons", dependencies=[Depends(same_origin_post)])
def ui_comparison_save(case_id: int, form: FormDep, session: SessionDep) -> Response:
    from app.services import compare

    _case_or_404(session, case_id)
    try:
        run_a = compare.get_run(session, _int(form.get("run_a")))
        run_b = compare.get_run(session, _int(form.get("run_b")))
        keys = json.loads(form.get("keys_json") or "[]")
        ignore = json.loads(form.get("ignore_json") or "[]")
        compare.check_scope(session, case_id, run_a, run_b)
        cmp = compare.compare(session, run_a, run_b, keys, ignore)
        compare.save(session, case_id, cmp, form.get("title") or "", form.get("comment") or "")
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except (ValueError, compare.CompareError) as exc:
        session.rollback()
        raise HTTPException(422, str(exc)) from exc
    return redirect(f"/cases/{case_id}#comparisons")


@router.post("/ui/comparisons/{comparison_id}/delete", dependencies=[Depends(same_origin_post)])
def ui_comparison_delete(comparison_id: int, session: SessionDep) -> Response:
    from app.services import compare

    try:
        case_id = compare.delete_saved(session, comparison_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return redirect(f"/cases/{case_id}#comparisons")
