"""Temporary UI: case pages and sharing actions (see app/services/cases.py, sharing.py)."""

from __future__ import annotations

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
