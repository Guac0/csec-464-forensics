"""windows.netscan.NetScan: network connections and listening sockets.

Checked against volatility3 2.28.2: no plugin options.
"""

from forensics.sdk import Baseline, Next, Plugin

PLUGIN = Plugin(
    name="windows.netscan.NetScan",
    description="Scan for TCP connections, TCP listeners, and UDP endpoints.",
    compare_keys=["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "Owner"],
    # EXAMPLE guide steps - TODO(forensics): replace with the team's workflow.
    baseline=Baseline(40, "Network connections and listening ports."),
    next=[
        Next(
            "windows.pstree.PsTree",
            "Connections were found: map their owner processes in the tree.",
            when="has_rows",
        ),
    ],
)
