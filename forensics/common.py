"""Pieces shared by several plugin files. Import them with:

from forensics.common import PID_FILTER
"""

from forensics.sdk import Arg

# The --pid option many Windows plugins have (volatility3 2.28.2: a list of numbers).
# Analysts type one or more PIDs separated by spaces or commas.
PID_FILTER = Arg(
    name="pid",
    flag="--pid",
    type="int_list",
    help="Only include these process IDs",
)
