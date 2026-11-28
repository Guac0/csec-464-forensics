"""windows.cmdline.CmdLine: the command line of each process.

Checked against volatility3 2.28.2: --pid is a list of numbers.
"""

from tests.content.sdk import PID_FILTER, Baseline, Plugin

PLUGIN = Plugin(
    name="windows.cmdline.CmdLine",
    description="Show the command line used to start each process.",
    args=[PID_FILTER],
    # EXAMPLE guide step - TODO(forensics): replace with the team's workflow.
    baseline=Baseline(30, "How each process was started (paths, arguments)."),
)
