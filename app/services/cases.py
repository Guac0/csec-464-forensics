"""Cases: groups of evidence items investigated together.

A case is the only link between images. Being in the same case does not mix anything: each
image keeps its own runs, rows, notes, AI history and hooks. The case adds case notes, a label
per image ("before", "after", "laptop-2"...) and the items analysts explicitly share to it
(app/services/sharing.py). An image can be in several cases. Cases are optional.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Case, CaseEvidence, Evidence, Note, SharedItem
from app.services import audit
from app.services.evidence import get_evidence

MAX_NAME = 200
MAX_LABEL = 100


def _clean_name(name: str) -> str:
    name = " ".join((name or "").split())
    if not name:
        raise ValueError("case name must not be empty")
    if len(name) > MAX_NAME:
        raise ValueError(f"case name longer than {MAX_NAME} characters")
    return name


def _clean_label(label: str | None) -> str:
    label = " ".join((label or "").split())
    if len(label) > MAX_LABEL:
        raise ValueError(f"label longer than {MAX_LABEL} characters")
    return label


def get_case(session: Session, case_id: int) -> Case:
    case = session.get(Case, case_id)
    if case is None:
        raise LookupError(f"case {case_id} not found")
    return case


def list_cases(session: Session) -> list[Case]:
    return list(session.scalars(select(Case).order_by(Case.name)))


def cases_for_evidence(session: Session, evidence_id: int) -> list[tuple[Case, str]]:
    """(case, label of the image in it) for every case the image is in, by case name."""
    rows = session.execute(
        select(Case, CaseEvidence.label)
        .join(CaseEvidence, CaseEvidence.case_id == Case.id)
        .where(CaseEvidence.evidence_id == evidence_id)
        .order_by(Case.name)
    )
    return [(c, label) for c, label in rows]


def membership(session: Session, case_id: int, evidence_id: int) -> CaseEvidence | None:
    return session.get(CaseEvidence, (case_id, evidence_id))


def labels(session: Session, case_id: int) -> dict[int, str]:
    """{evidence_id: label} for a case's members."""
    return dict(
        session.execute(
            select(CaseEvidence.evidence_id, CaseEvidence.label).where(
                CaseEvidence.case_id == case_id
            )
        ).all()
    )


def create_case(session: Session, name: str, description: str = "") -> Case:
    name = _clean_name(name)
    if session.scalar(select(Case.id).where(Case.name == name)):
        raise ValueError(f"a case named {name!r} already exists")
    case = Case(name=name, description=(description or "").strip())
    session.add(case)
    session.flush()
    audit.record(
        session,
        "case.create",
        object_type="case",
        object_id=case.id,
        summary=f"Created case {case.id}: {name}",
        details={"name": name, "description": case.description},
    )
    session.commit()
    return case


def update_case(
    session: Session, case_id: int, name: str | None = None, description: str | None = None
) -> Case:
    case = get_case(session, case_id)
    before = {"name": case.name, "description": case.description}
    if name is not None:
        name = _clean_name(name)
        clash = session.scalar(select(Case.id).where(Case.name == name, Case.id != case_id))
        if clash:
            raise ValueError(f"a case named {name!r} already exists")
        case.name = name
    if description is not None:
        case.description = description.strip()
    audit.record(
        session,
        "case.update",
        object_type="case",
        object_id=case.id,
        summary=f"Updated case {case.id}",
        details={"before": before, "after": {"name": case.name, "description": case.description}},
    )
    session.commit()
    return case


def delete_case(session: Session, case_id: int) -> None:
    """Delete an EMPTY case (no images, notes or shared items): nothing is ever lost by
    deleting a case. Remove its images and notes first."""
    case = get_case(session, case_id)
    members = session.scalar(select(func.count()).where(CaseEvidence.case_id == case_id)) or 0
    notes = session.scalar(select(func.count(Note.id)).where(Note.case_id == case_id)) or 0
    shared = (
        session.scalar(select(func.count(SharedItem.id)).where(SharedItem.case_id == case_id)) or 0
    )
    if members or notes or shared:
        raise ValueError(
            f"case is not empty ({members} image(s), {notes} note(s), {shared} shared item(s))"
        )
    audit.record(
        session,
        "case.delete",
        object_type="case",
        object_id=case.id,
        summary=f"Deleted empty case {case.id}: {case.name}",
    )
    session.delete(case)
    session.commit()


def add_evidence(session: Session, case_id: int, evidence_id: int, label: str = "") -> CaseEvidence:
    case = get_case(session, case_id)
    ev = get_evidence(session, evidence_id)
    if membership(session, case_id, evidence_id):
        raise ValueError(f"{ev.rel_path} is already in case {case.name!r}")
    member = CaseEvidence(case_id=case_id, evidence_id=evidence_id, label=_clean_label(label))
    session.add(member)
    # The new image's existing runs have not been checked against the case's indicators yet.
    from app.models import Indicator

    for ind in session.scalars(select(Indicator).where(Indicator.case_id == case_id)):
        ind.checked_at = None
    audit.record(
        session,
        "case.add_evidence",
        object_type="case",
        object_id=case_id,
        evidence_id=evidence_id,
        summary=f"Added {ev.rel_path} to case {case.name}",
        details={"label": member.label},
    )
    session.commit()
    return member


def set_label(session: Session, case_id: int, evidence_id: int, label: str) -> CaseEvidence:
    member = membership(session, case_id, evidence_id)
    if member is None:
        raise LookupError("that image is not in this case")
    before = member.label
    member.label = _clean_label(label)
    audit.record(
        session,
        "case.label",
        object_type="case",
        object_id=case_id,
        evidence_id=evidence_id,
        summary=f"Label of evidence {evidence_id} in case {case_id}: {member.label or '(none)'}",
        details={"before": before, "after": member.label},
    )
    session.commit()
    return member


def remove_evidence(session: Session, case_id: int, evidence_id: int) -> int:
    """Remove an image from a case. Items shared FROM it in this case are un-shared (they no
    longer have a member image behind them). Returns how many were un-shared."""
    from app.services import sharing

    member = membership(session, case_id, evidence_id)
    if member is None:
        raise LookupError("that image is not in this case")
    items = session.scalars(
        select(SharedItem).where(
            SharedItem.case_id == case_id, SharedItem.source_evidence_id == evidence_id
        )
    ).all()
    for item in items:
        sharing.unshare_in_tx(session, item, reason="image removed from the case")
    from app.services import indicators

    indicators.remove_hits_for_image(session, case_id, evidence_id)
    session.delete(member)
    audit.record(
        session,
        "case.remove_evidence",
        object_type="case",
        object_id=case_id,
        evidence_id=evidence_id,
        summary=f"Removed evidence {evidence_id} from case {case_id}",
        details={"unshared_items": len(items)},
    )
    session.commit()
    return len(items)


def member_evidence(session: Session, case_id: int) -> list[tuple[Evidence, str]]:
    """(evidence, label) of a case's images, in the order they were added."""
    rows = session.execute(
        select(Evidence, CaseEvidence.label)
        .join(CaseEvidence, CaseEvidence.evidence_id == Evidence.id)
        .where(CaseEvidence.case_id == case_id)
        .order_by(CaseEvidence.added_at, Evidence.id)
    )
    return [(ev, label) for ev, label in rows]
