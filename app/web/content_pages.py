"""Read-only /content page: status of the forensics content (app/tools/content_report.py)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.tools.content_report import build_report
from app.web.pages import render

router = APIRouter(include_in_schema=False)


@router.get("/content", response_class=HTMLResponse)
def content_page(request: Request) -> HTMLResponse:
    return render(request, "content.html", report=build_report())
