"""JSON API: registered post-run hooks and hook modules that failed to load."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.tools import hooks

router = APIRouter(prefix="/api/hooks", tags=["hooks"])


class HookOut(BaseModel):
    name: str
    tool: str
    plugins: list[str]
    version: str
    description: str


class HooksOut(BaseModel):
    hooks: list[HookOut]
    load_errors: dict[str, str]


@router.get("", response_model=HooksOut)
def list_hooks() -> HooksOut:
    return HooksOut(
        hooks=[
            HookOut(
                name=h.name,
                tool=h.tool,
                plugins=list(h.plugins),
                version=h.version,
                description=h.description,
            )
            for h in hooks.registered_hooks()
        ],
        load_errors=hooks.load_errors(),
    )
