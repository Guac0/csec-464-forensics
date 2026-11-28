"""windows.psscan.PsScan: process objects found by scanning memory."""

from forensics.sdk import Plugin

PLUGIN = Plugin(
    name="windows.psscan.PsScan",
    description="Scan memory for process objects, including remnants of exited processes.",
)
