"""Settings the analyst can change in the app (Settings page), on top of FT_* environment values.

A value saved here overrides the environment value until it is reset. Every change is audited.
Only the settings in ``EDITABLE`` can be changed this way; everything else stays environment-only
(paths, provider URL/key, security-relevant switches).

Code reads the effective value with ``get_value(key)`` (database override, else
``get_settings()``); it is cheap (one primary-key lookup) and safe from any thread.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AppSetting, utcnow
from app.services import audit


@dataclass(frozen=True)
class SettingSpec:
    key: str  # Settings attribute name; env var FT_<KEY>
    label: str
    help: str
    kind: str  # "int" | "choice"
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] = ()
    unit: str = ""  # shown next to the field
    scale: int = 1  # UI value * scale = stored value (e.g. minutes -> seconds)


EDITABLE: dict[str, SettingSpec] = {
    s.key: s
    for s in (
        SettingSpec(
            "agent_max_steps",
            "AI agent: default max steps",
            "AI calls one goal task may make (the analyst can change it per task).",
            "int",
            1,
            50,
        ),
        SettingSpec(
            "agent_max_seconds",
            "AI agent: default time limit",
            "Wall-clock time per task; time waiting for the analyst's approval does not count.",
            "int",
            1,
            60,
            unit="minutes",
            scale=60,
        ),
        SettingSpec(
            "agent_max_runs",
            "AI agent: default max plugin runs",
            "Plugin runs one task may queue (each needs approval unless 'yes to all'); "
            "0 = the agent only searches existing results.",
            "int",
            0,
            20,
        ),
        SettingSpec(
            "agent_max_concurrent",
            "AI agent: tasks running at once",
            "More tasks wait in the queue. Tasks waiting for approval or runs do not hold a slot.",
            "int",
            1,
            8,
        ),
        SettingSpec(
            "ai_tool_mode",
            "AI tool calling protocol",
            "auto = the provider's native function calling, falling back to a text protocol "
            "when the provider or model does not support it; native; text (any model).",
            "choice",
            choices=("auto", "native", "text"),
        ),
    )
}


@dataclass
class SettingView:
    spec: SettingSpec
    value: Any  # effective (stored units)
    default: Any  # environment value
    overridden: bool
    updated_by: str | None
    updated_at: datetime | None

    @property
    def display(self) -> Any:
        return _to_ui(self.spec, self.value)

    @property
    def display_default(self) -> Any:
        return _to_ui(self.spec, self.default)


def _to_ui(spec: SettingSpec, value: Any) -> Any:
    if spec.scale != 1 and isinstance(value, int | float):
        shown = value / spec.scale
        return int(shown) if shown == int(shown) else round(shown, 2)
    return value


def get_value(key: str, session: Session | None = None) -> Any:
    """Effective value of an editable setting (database override, else environment)."""
    default = getattr(get_settings(), key)
    if key not in EDITABLE:
        return default
    try:
        if session is not None:
            row = session.get(AppSetting, key)
            return row.value if row is not None else default
        from app.db import SessionLocal

        with SessionLocal() as s:
            row = s.get(AppSetting, key)
            return row.value if row is not None else default
    except Exception:  # e.g. before migrations ran: fall back to the environment
        return default


def list_settings(session: Session) -> list[SettingView]:
    settings = get_settings()
    out = []
    for key, spec in EDITABLE.items():
        row = session.get(AppSetting, key)
        default = getattr(settings, key)
        out.append(
            SettingView(
                spec,
                row.value if row is not None else default,
                default,
                row is not None,
                row.updated_by if row else None,
                row.updated_at if row else None,
            )
        )
    return out


def parse(spec: SettingSpec, raw: Any) -> Any:
    """Validate a UI/API value (in UI units) and return the stored value; ValueError if bad."""
    if spec.kind == "choice":
        value = str(raw).strip()
        if value not in spec.choices:
            raise ValueError(f"{spec.label}: choose one of {', '.join(spec.choices)}")
        return value
    try:
        number = float(str(raw).strip())
    except ValueError:
        raise ValueError(f"{spec.label}: enter a number") from None
    if spec.scale == 1 and number != int(number):
        raise ValueError(f"{spec.label}: enter a whole number")
    if (spec.minimum is not None and number < spec.minimum) or (
        spec.maximum is not None and number > spec.maximum
    ):
        unit = f" {spec.unit}" if spec.unit else ""
        raise ValueError(f"{spec.label}: must be {spec.minimum}-{spec.maximum}{unit}")
    return int(round(number * spec.scale))


def update(session: Session, values: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    """Save changed values (UI units; empty = keep). Returns {key: (old, new)}; validates all
    values before saving any (ValueError lists every problem)."""
    parsed: dict[str, Any] = {}
    errors = []
    for key, raw in values.items():
        spec = EDITABLE.get(key)
        if spec is None:
            errors.append(f"{key}: cannot be changed in the app")
            continue
        if raw is None or str(raw).strip() == "":
            continue
        try:
            parsed[key] = parse(spec, raw)
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        raise ValueError("; ".join(errors))
    changed: dict[str, tuple[Any, Any]] = {}
    actor = audit.current_context().actor
    for key, value in parsed.items():
        old = get_value(key, session)
        if old == value and session.get(AppSetting, key) is not None:
            continue
        row = session.get(AppSetting, key) or AppSetting(key=key)
        row.value = value
        row.updated_by = actor
        row.updated_at = utcnow()
        session.add(row)
        changed[key] = (old, value)
    if changed:
        audit.record(
            session,
            "settings.update",
            object_type="settings",
            summary="Settings changed: " + ", ".join(sorted(changed)),
            details={k: {"old": o, "new": n} for k, (o, n) in changed.items()},
        )
    session.commit()
    return changed


def reset(session: Session, key: str) -> bool:
    """Return a setting to its environment value. False if it was not overridden."""
    row = session.get(AppSetting, key)
    if row is None:
        return False
    old = row.value
    session.delete(row)
    audit.record(
        session,
        "settings.reset",
        object_type="settings",
        summary=f"Setting {key} reset to the environment value",
        details={"key": key, "old": old, "new": getattr(get_settings(), key)},
    )
    session.commit()
    return True
