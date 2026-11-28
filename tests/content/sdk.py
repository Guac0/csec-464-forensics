"""Same names as forensics/sdk.py (+ PID_FILTER from forensics/common.py), imported from app/
directly so this test copy does not depend on team-owned files."""

from app.tools.base import ArgSpec as Arg
from app.tools.base import GuideStep as Next
from app.tools.content import AIContext, Baseline, Plugin, Preset
from app.tools.hooks import HookContext, post_run

PID_FILTER = Arg(name="pid", flag="--pid", type="int_list", help="Only include these process IDs")

__all__ = [
    "PID_FILTER",
    "AIContext",
    "Arg",
    "Baseline",
    "HookContext",
    "Next",
    "Plugin",
    "Preset",
    "post_run",
]
