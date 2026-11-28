"""windows.pstree.PsTree: processes as a parent/child tree."""

from forensics.sdk import Baseline, Next, Plugin

PLUGIN = Plugin(
    name="windows.pstree.PsTree",
    description="Show processes in a tree grouped by parent process.",
    # EXAMPLE guide steps - TODO(forensics): replace with the team's workflow.
    baseline=Baseline(20, "Who started whom: look for unusual parent processes."),
    next=[
        Next(
            "windows.cmdline.CmdLine",
            "A process has a parent that is not in the list: check its command line.",
            when="tag:suspicious-parent",
            priority=20,
        ),
    ],
)
