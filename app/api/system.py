"""JSON API: setup and health checks (app/services/health.py). ``/health`` stays the liveness
probe; this is the detailed view."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_session
from app.services import health

SessionDep = Annotated[Session, Depends(get_session)]

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/health")
def system_health(session: SessionDep) -> dict[str, Any]:
    """Cheap checks (disk, folders, symbols, worker, database, audit chain, hooks, AI config)."""
    checks = health.quick_checks(session)
    return {"status": health.overall(checks), "checks": [c.as_dict() for c in checks]}


@router.post("/health/volatility")
def test_volatility() -> dict[str, Any]:
    """Run ``vol -h`` (takes a few seconds) and check every catalog plugin exists."""
    return health.run_volatility_test().as_dict()


@router.post("/health/ai")
def test_ai() -> dict[str, Any]:
    """Send one tiny request to the AI provider (uses a few tokens)."""
    return health.run_ai_test().as_dict()


@router.get("/backups")
def list_backups() -> dict[str, Any]:
    """Backups in FT_BACKUP_DIR (newest first) and the state of manual/automatic backups."""
    from app.services import backup

    return {
        "backups": [b.as_dict() for b in backup.list_backups()],
        "manual": backup.manual_state(),
        "last_automatic_error": backup.get_scheduler().last_error,
    }


@router.post("/backups", status_code=202)
def start_backup() -> dict[str, Any]:
    """Start a manual backup in the background; poll GET /api/system/backups."""
    from fastapi import HTTPException

    from app.services import backup

    if not backup.start_manual_backup():
        raise HTTPException(409, "a backup is already being made")
    return {"started": True}


@router.post("/backups/{name}/verify")
def verify_backup(name: str) -> dict[str, Any]:
    from fastapi import HTTPException

    from app.services import backup

    try:
        backup.get_backup(name)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return backup.verify_backup(name).as_dict()


@router.get("/biggest-runs")
def biggest_runs(session: SessionDep, limit: int = 10) -> list[dict[str, Any]]:
    from app.services import run_deletion

    return [
        {
            "run_id": run.id,
            "evidence_id": run.evidence_id,
            "plugin": run.plugin,
            "status": run.status.value,
            "deleted": run.deleted_at is not None,
            "bytes_on_disk": size,
        }
        for run, size in run_deletion.biggest_runs(session, limit=max(1, min(limit, 100)))
    ]


@router.get("/settings")
def get_app_settings(session: Session = Depends(get_session)) -> list[dict[str, Any]]:  # noqa: B008
    """Settings changeable in the app: effective value, environment default, who changed it."""
    from app.services import app_settings

    return [
        {
            "key": v.spec.key,
            "label": v.spec.label,
            "value": v.value,
            "default": v.default,
            "overridden": v.overridden,
            "updated_by": v.updated_by,
            "updated_at": v.updated_at,
        }
        for v in app_settings.list_settings(session)
    ]


@router.put("/settings")
def put_app_settings(
    body: dict[str, Any],
    session: Session = Depends(get_session),  # noqa: B008
) -> dict[str, Any]:
    """Change settings: ``{key: value}`` in UI units (agent_max_seconds in MINUTES)."""
    from fastapi import HTTPException

    from app.services import app_settings

    try:
        changed = app_settings.update(session, body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"changed": {k: {"old": o, "new": n} for k, (o, n) in changed.items()}}


@router.delete("/settings/{key}")
def reset_app_setting(key: str, session: Session = Depends(get_session)) -> dict[str, Any]:  # noqa: B008
    from app.services import app_settings

    return {"reset": app_settings.reset(session, key)}
