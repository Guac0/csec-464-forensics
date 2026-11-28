"""windows.pslist.PsList: processes from the active process list.

Checked against volatility3 2.28.2: --pid is a list of numbers; --dump is an on/off switch
("Extract listed processes"). Dumped files are named in the "File output" column.
--physical is not offered.
"""

from tests.content.sdk import PID_FILTER, Arg, Baseline, Next, Plugin, Preset

PLUGIN = Plugin(
    name="windows.pslist.PsList",
    description="List processes from the active process list.",
    args=[
        PID_FILTER,
        # Writes files: dumped processes are hashed, linked to their row and downloadable.
        Arg(
            name="dump",
            flag="--dump",
            type="bool",
            help="Extract the listed processes to files (can be large; combine with PID)",
            writes_files=True,
        ),
    ],
    presets=[Preset("EXAMPLE: PID 4 (System)", pid=[4])],
    # EXAMPLE comparison key - TODO(forensics): a better identity is name + path + parent name,
    # which needs pstree/cmdline data joined in.
    compare_keys=["ImageFileName"],
    # EXAMPLE guide steps - TODO(forensics): replace with the team's workflow.
    baseline=Baseline(10, "Which processes were running when memory was captured?"),
    next=[
        Next(
            "windows.pstree.PsTree",
            "Processes were found: check their parent/child relations.",
            when="has_rows",
            priority=10,
        ),
        Next(
            "windows.cmdline.CmdLine",
            "A hook flagged processes: see how they were started.",
            when="has_flags",
            priority=20,
        ),
        Next(
            "windows.pslist.PsList",
            "Dump the System process (PID 4) for offline analysis; files can be large.",
            args={"pid": [4], "dump": True},
        ),
    ],
)
