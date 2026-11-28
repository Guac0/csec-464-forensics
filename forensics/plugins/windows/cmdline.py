"""windows.cmdline.CmdLine: the command line of each process.

Checked against volatility3 2.28.2: --pid is a list of numbers.
"""

from forensics.common import PID_FILTER
from forensics.sdk import Baseline, Plugin

PLUGIN = Plugin(
    name="windows.cmdline.CmdLine",
    description="Show the command line used to start each process.",
    args=[PID_FILTER],
    # EXAMPLE guide step - TODO(forensics): replace with the team's workflow.
    baseline=Baseline(30, "How each process was started (paths, arguments)."),
)
