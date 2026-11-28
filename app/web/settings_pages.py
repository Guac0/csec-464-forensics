"""Settings page: settings the analyst may change in the app (app/services/app_settings.py)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse

from app.services import app_settings
from app.web.pages import FormDep, SessionDep, redirect, render, same_origin_post

router = APIRouter(include_in_schema=False)


def _page(request: Request, session: SessionDep, **extra: object) -> HTMLResponse:
    return render(request, "settings.html", settings=app_settings.list_settings(session), **extra)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, session: SessionDep) -> HTMLResponse:
    return _page(request, session)


@router.post("/settings", dependencies=[Depends(same_origin_post)])
def save_settings(request: Request, form: FormDep, session: SessionDep) -> Response:
    values = {k: v for k, v in form.items() if k in app_settings.EDITABLE}
    try:
        changed = app_settings.update(session, values)
    except ValueError as exc:
        session.rollback()
        return _page(request, session, error=str(exc), values=values)
    message = f"Saved {len(changed)} change(s)." if changed else "Nothing changed."
    return _page(request, session, message=message)


@router.post("/settings/{key}/reset", dependencies=[Depends(same_origin_post)])
def reset_setting(request: Request, key: str, session: SessionDep) -> Response:
    if key not in app_settings.EDITABLE:
        return redirect("/settings")
    app_settings.reset(session, key)
    return _page(request, session, message=f"{app_settings.EDITABLE[key].label} reset.")
