"""windows.dlllist.DllList: loaded DLLs by process."""

from forensics.common import PID_FILTER
from forensics.sdk import Plugin

PLUGIN = Plugin(
    name="windows.dlllist.DllList",
    description="List loaded DLLs and their paths by process.",
    args=[PID_FILTER],
)
