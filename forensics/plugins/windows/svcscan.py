"""windows.svcscan.SvcScan: Windows service records."""

from forensics.sdk import Plugin

PLUGIN = Plugin(
    name="windows.svcscan.SvcScan",
    description="Scan for Windows service records, including service names and states.",
)
