"""TEMPLATE for a new plugin file. This file is NOT loaded (its name starts with "_").

To add a plugin:
1. Run `python -m forensics new <plugin name>`, or copy this file into the folder for its OS
   and name it after the plugin, without the class name, dots becoming underscores:
       windows.pslist.PsList            -> plugins/windows/pslist.py
       windows.malware.malfind.Malfind  -> plugins/windows/malware_malfind.py
2. Fill in the fields below. Delete the ones you don't need: only `name` is required.
3. Check it: `python -m forensics check`.

Never guess plugin names, options or column names: copy them from `vol -h`,
`vol <plugin> -h` and real output. Write down which volatility version you checked here.
"""

from forensics.common import PID_FILTER
from forensics.sdk import AIContext, Arg, Baseline, HookContext, Next, Plugin, Preset

PLUGIN = Plugin(
    # Full name exactly as `vol -h` lists it (volatility matches parts of names, so a short
    # name like "windows.pslist" can run the wrong plugin).
    name="windows.example.Example",
    # One line for the run form.
    description="What this plugin shows.",
    # The options analysts may use. Anything not listed here can never be passed.
    #   type: "int" (--flag 5), "int_list" (--flag 1 2 3), "bool" (--flag when ticked),
    #         "str" (--flag text).
    #   writes_files=True for any option that makes the plugin write files (like --dump).
    args=[
        PID_FILTER,
        Arg(name="dump", flag="--dump", type="bool", help="Extract to files", writes_files=True),
    ],
    # One-click queries on the run form. Use the arg names from above.
    presets=[Preset("PID 4 (System)", pid=[4])],
    # True = run automatically on every new image. Keep this for identification (OS, kernel).
    auto_enumerate=False,
    # Seconds before the run is stopped. None = the default (1 hour).
    timeout_seconds=None,
    # True if the plugin ALWAYS writes files, whatever the options (like windows.dumpfiles).
    writes_files=False,
    # Comparison page: the columns that identify "the same" row in two images. Never use PIDs or
    # memory offsets, they change between captures.
    compare_keys=["ImageFileName"],
    # Extra columns to ignore when deciding whether a row changed.
    compare_ignore=[],
    # Put the plugin in the standard first pass. Lower numbers run first.
    baseline=Baseline(50, "One short sentence: why run this early?"),
    # Suggestions shown after THIS plugin ran on an image.
    #   when: "succeeded" (default), "has_rows", "has_flags" (a hook flagged a row),
    #         or "tag:<tag>" (a hook flagged a row with that tag).
    #   priority: higher numbers are shown first.
    next=[
        Next(
            "windows.cmdline.CmdLine",
            "One short sentence telling a junior analyst why this is useful next.",
            when="has_rows",
            priority=10,
        ),
    ],
    # Which rows of a run are sent to the AI. max_rows: how many (default 50, 200 for "Summarize
    # this run"); columns: only these columns (empty = all). Rows flagged by a hook are always
    # sent as well. For anything smarter, write select_ai_rows below.
    ai_context=AIContext(max_rows=100, columns=["PID", "ImageFileName"]),
)


# Optional: choose exactly which rows the AI sees. Gets every row of the run in order and returns
# the row_idx numbers to send, most important first (at most max_rows are used). If it raises an
# error, the AI gets the first rows instead. Delete this if you don't need it.
def select_ai_rows(rows):
    for row in rows:
        if row.data.get("SomeColumn") == "something interesting":
            yield row.row_idx


# Optional hook: Python that runs after each successful run of this plugin.
# Delete this if you don't need it. See "Hooks" in forensics/README.md.
@PLUGIN.post_run(version="1")  # raise the version when you change the logic
def flag_interesting_rows(ctx: HookContext) -> None:
    """One line saying what this hook does (shown in the hook list)."""
    for row in ctx.rows():
        if row.data.get("SomeColumn") == "something interesting":
            ctx.annotate(row.row_idx, "interesting", severity="low", note="why it matters")
