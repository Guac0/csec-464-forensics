"""FastAPI application factory.

Run with ``uvicorn app.main:app`` (module-level instance) or
``uvicorn --factory app.main:create_app``.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.db import SessionLocal, init_engine, migrate
from app.jobs.worker import get_worker, recover_stale_runs
from app.services import audit
from app.tools import hooks

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "web" / "static"

# Routers included in this order; each module must expose ``router``.
ROUTER_MODULES = (
    "app.api.evidence",
    "app.api.runs",
    "app.api.notes",
    "app.api.hooks",
    "app.api.audit",
    "app.api.artifacts",
    "app.api.export",
    "app.api.ai",
    "app.web.pages",
)


def _configure_logging() -> None:
    # basicConfig is a no-op if the root logger is already configured (e.g. by uvicorn/pytest).
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _include_optional_router(app: FastAPI, module_name: str) -> bool:
    """Include ``module_name.router`` if the module imports; otherwise log a warning.

    Modules are developed in parallel by different owners, so a missing or broken module must
    not take the whole app down.
    """
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name and module_name.startswith(exc.name):
            logger.warning("router module %s not available; skipping", module_name)
        else:
            logger.warning(
                "router module %s failed to import; skipping", module_name, exc_info=True
            )
        return False
    except Exception:
        logger.warning("router module %s failed to import; skipping", module_name, exc_info=True)
        return False
    router = getattr(module, "router", None)
    if router is None:
        logger.warning("module %s has no 'router'; skipping", module_name)
        return False
    app.include_router(router)
    return True


def create_app(start_worker: bool = True) -> FastAPI:
    _configure_logging()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        init_engine()
        migrate()
        hook_errors = hooks.load_hooks()  # import hook modules now so errors show in the log
        settings = get_settings()
        audit.record_now(
            "app.start",
            summary="Application started",
            details={
                "version": _app.version,
                "audit_level": settings.audit_level,
                "hooks": [h.name for h in hooks.registered_hooks()],
                "hook_load_errors": hook_errors,
            },
        )
        with SessionLocal() as session:
            recover_stale_runs(session)
        worker = get_worker() if start_worker else None
        if worker is not None:
            worker.start()
        try:
            yield
        finally:
            if worker is not None:
                worker.stop()

    app = FastAPI(title="Forensics Tool", version="0.1.0", lifespan=lifespan)
    # Sets the audit context (origin/request id) and logs requests at FT_AUDIT_LEVEL=all.
    app.middleware("http")(audit.audit_requests_middleware)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    for module_name in ROUTER_MODULES:
        _include_optional_router(app, module_name)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app


app = create_app()
