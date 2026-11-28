"""windows.filescan.FileScan: file objects and their paths."""

from forensics.sdk import Plugin

PLUGIN = Plugin(
    name="windows.filescan.FileScan",
    description="Scan memory for Windows file objects and report their paths.",
)
