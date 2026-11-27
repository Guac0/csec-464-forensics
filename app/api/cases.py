"""JSON API: cases, their images (with labels) and items shared between a case's images."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import SharedKind
from app.services import cases as cases_service
from app.services import sharing

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api/cases", tags=["cases"])


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    created_at: datetime


class CaseIn(BaseModel):
    name: str
    description: str = ""


class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class MemberIn(BaseModel):
    evidence_id: int
    label: str = ""


class LabelIn(BaseModel):
    label: str = ""


class ShareIn(BaseModel):
    kind: SharedKind
    comment: str = Field(default="", max_length=2000)
    run_id: int | None = None
    row_idx: int | None = None
    finding_index: int | None = None
    note_id: int | None = None
    ai_message_id: int | None = None


def _err(exc: Exception) -> HTTPException:
    if isinstance(exc, LookupError):
        return HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    return HTTPException(status.HTTP_409_CONFLICT, str(exc))


@router.get("", response_model=list[CaseOut])
def list_cases(session: SessionDep) -> list[Any]:
    return cases_service.list_cases(session)


@router.post("", response_model=CaseOut, status_code=201)
def create_case(body: CaseIn, session: SessionDep) -> Any:
    try:
        return cases_service.create_case(session, body.name, body.description)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/{case_id}")
def get_case(case_id: int, session: SessionDep) -> dict[str, Any]:
    """The case with its images (and labels) and its shared items in their LATEST state."""
    try:
        case = cases_service.get_case(session, case_id)
    except LookupError as exc:
        raise _err(exc) from exc
    return {
        **CaseOut.model_validate(case).model_dump(),
        "members": [
            {"evidence_id": ev.id, "rel_path": ev.rel_path, "label": label}
            for ev, label in cases_service.member_evidence(session, case_id)
        ],
        "shared": [_resolved(r) for r in sharing.resolved_for_case(session, case_id)],
    }


@router.patch("/{case_id}", response_model=CaseOut)
def update_case(case_id: int, body: CaseUpdate, session: SessionDep) -> Any:
    try:
        return cases_service.update_case(session, case_id, body.name, body.description)
    except (LookupError, ValueError) as exc:
        raise _err(exc) from exc


@router.delete("/{case_id}", status_code=204)
def delete_case(case_id: int, session: SessionDep) -> Response:
    """Only empty cases (no images, notes or shared items) can be deleted."""
    try:
        cases_service.delete_case(session, case_id)
    except (LookupError, ValueError) as exc:
        raise _err(exc) from exc
    return Response(status_code=204)


@router.post("/{case_id}/evidence", status_code=201)
def add_evidence(case_id: int, body: MemberIn, session: SessionDep) -> dict[str, Any]:
    try:
        m = cases_service.add_evidence(session, case_id, body.evidence_id, body.label)
    except (LookupError, ValueError) as exc:
        raise _err(exc) from exc
    return {"case_id": m.case_id, "evidence_id": m.evidence_id, "label": m.label}


@router.patch("/{case_id}/evidence/{evidence_id}")
def set_label(case_id: int, evidence_id: int, body: LabelIn, session: SessionDep) -> dict[str, Any]:
    try:
        m = cases_service.set_label(session, case_id, evidence_id, body.label)
    except (LookupError, ValueError) as exc:
        raise _err(exc) from exc
    return {"case_id": m.case_id, "evidence_id": m.evidence_id, "label": m.label}


@router.delete("/{case_id}/evidence/{evidence_id}")
def remove_evidence(case_id: int, evidence_id: int, session: SessionDep) -> dict[str, Any]:
    """Remove an image from the case; items shared from it in this case are un-shared."""
    try:
        unshared = cases_service.remove_evidence(session, case_id, evidence_id)
    except LookupError as exc:
        raise _err(exc) from exc
    return {"unshared_items": unshared}


def _resolved(r: sharing.Resolved) -> dict[str, Any]:
    i = r.item
    return {
        "id": i.id,
        "case_id": i.case_id,
        "kind": i.kind.value,
        "source_evidence_id": i.source_evidence_id,
        "source_key": i.source_key,
        "title": i.title,
        "comment": i.comment,
        "shared_by": i.shared_by,
        "shared_at": i.shared_at.isoformat(),
        "status": r.status,
        "status_text": r.status_text,
        "current_text": r.text,
        "link": r.link,
    }


@router.get("/{case_id}/shared")
def list_shared(
    case_id: int, session: SessionDep, exclude_evidence_id: int | None = None
) -> list[dict[str, Any]]:
    """Shared items in their latest state; ``exclude_evidence_id`` = what OTHER images shared."""
    try:
        cases_service.get_case(session, case_id)
    except LookupError as exc:
        raise _err(exc) from exc
    return [_resolved(r) for r in sharing.resolved_for_case(session, case_id, exclude_evidence_id)]


@router.post("/{case_id}/shared", status_code=201)
def share(case_id: int, body: ShareIn, session: SessionDep) -> dict[str, Any]:
    """Share a row, hook finding, image note or AI answer from a member image to this case."""
    try:
        item = sharing.share(
            session,
            case_id,
            body.kind,
            comment=body.comment,
            run_id=body.run_id,
            row_idx=body.row_idx,
            finding_index=body.finding_index,
            note_id=body.note_id,
            ai_message_id=body.ai_message_id,
        )
    except (LookupError, ValueError) as exc:
        raise _err(exc) from exc
    return _resolved(sharing.resolve(session, item, case_id))


@router.delete("/{case_id}/shared/{item_id}", status_code=204)
def unshare(case_id: int, item_id: int, session: SessionDep) -> Response:
    from app.models import SharedItem

    item = session.get(SharedItem, item_id)
    if item is None or item.case_id != case_id:
        raise HTTPException(404, "shared item not found in this case")
    sharing.unshare(session, item_id)
    return Response(status_code=204)


# --------------------------------------------------------------------------------- indicators


class IndicatorIn(BaseModel):
    type: str
    value: str
    match_mode: str = "exact"
    column: str = ""
    comment: str = ""
    source_key: str = ""


def _indicator_out(i: Any, counts: dict[int, int] | None = None) -> dict[str, Any]:
    return {
        "id": i.id,
        "case_id": i.case_id,
        "type": i.type.value,
        "value": i.value,
        "normalized": i.normalized,
        "match_mode": i.match_mode.value,
        "column": i.column,
        "comment": i.comment,
        "source_key": i.source_key,
        "created_by": i.created_by,
        "created_at": i.created_at.isoformat(),
        "checked_at": i.checked_at.isoformat() if i.checked_at else None,
        "hits_by_evidence": counts or {},
    }


@router.get("/{case_id}/indicators")
def list_indicators(case_id: int, session: SessionDep) -> dict[str, Any]:
    """The case's watchlist with hit counts per image, and the state of any running check."""
    from app.services import indicators

    try:
        cases_service.get_case(session, case_id)
    except LookupError as exc:
        raise _err(exc) from exc
    counts = indicators.hit_counts(session, case_id)
    return {
        "indicators": [
            _indicator_out(i, counts.get(i.id))
            for i in indicators.list_indicators(session, case_id)
        ],
        "check": indicators.job_state(case_id),
    }


@router.post("/{case_id}/indicators", status_code=201)
def add_indicator(case_id: int, body: IndicatorIn, session: SessionDep) -> dict[str, Any]:
    """Add an indicator. New runs are checked automatically; to check existing runs, POST
    /{case_id}/indicators/check."""
    from app.services import indicators

    try:
        ind = indicators.add_indicator(
            session,
            case_id,
            body.type,
            body.value,
            mode=body.match_mode,
            column=body.column,
            comment=body.comment,
            source_key=body.source_key,
        )
    except LookupError as exc:
        raise _err(exc) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _indicator_out(ind)


@router.delete("/{case_id}/indicators/{indicator_id}", status_code=204)
def remove_indicator(case_id: int, indicator_id: int, session: SessionDep) -> Response:
    from app.models import Indicator
    from app.services import indicators

    ind = session.get(Indicator, indicator_id)
    if ind is None or ind.case_id != case_id:
        raise HTTPException(404, "indicator not found in this case")
    indicators.remove_indicator(session, indicator_id)
    return Response(status_code=204)


@router.post("/{case_id}/indicators/check", status_code=202)
def check_indicators(case_id: int, session: SessionDep) -> dict[str, Any]:
    """Re-check every run of the case's images against its indicators, in the background
    (can take a while on big runs). Poll GET /{case_id}/indicators for progress."""
    from app.services import indicators

    try:
        cases_service.get_case(session, case_id)
    except LookupError as exc:
        raise _err(exc) from exc
    if not indicators.start_case_check(case_id):
        raise HTTPException(409, "a check of this case is already running")
    return {"started": True}


@router.get("/{case_id}/indicators/hits")
def indicator_hits(
    case_id: int, session: SessionDep, evidence_id: int | None = None
) -> list[dict[str, Any]]:
    from app.services import indicators

    return [
        {
            "indicator_id": h.indicator.id,
            "indicator": h.indicator.value,
            "type": h.indicator.type.value,
            "evidence_id": h.evidence.id,
            "rel_path": h.evidence.rel_path,
            "run_id": h.run.id,
            "plugin": h.run.plugin,
            "row": f"R{h.run.id}:{h.hit.row_idx}",
            "column": h.hit.column,
            "cell": h.hit.cell,
        }
        for h in indicators.hits(session, case_id, evidence_id=evidence_id)
    ]
