"""windows.handles.Handles: open object handles by process."""

from forensics.common import PID_FILTER
from forensics.sdk import Plugin

PLUGIN = Plugin(
    name="windows.handles.Handles",
    description="List open object handles by process.",
    args=[PID_FILTER],
)
