"""Investigation guide: which volatility3 plugins the app RECOMMENDS running next.

=====================================================================================
TODO(forensics): this guide is owned by the forensic analysts. The entries below are
EXAMPLES that show every feature; replace/extend them with the team's real workflow.
=====================================================================================

What the analyst sees
---------------------
The image page has a "Recommended next" panel. It lists, in this order:

1. BASELINE steps that have not run yet on this image, in the order written below. The
   baseline is the standard first pass of a deeper investigation (processes, network, ...).
   It is separate from auto-enumerate (``auto_enumerate=True`` in plugins.py), which only
   identifies the image (OS, kernel) with no user input.
2. NEXT steps: "after plugin X succeeded, suggest plugin Y". Steps from every succeeded run
   are merged; if several runs suggest the same step its reasons are listed together. They are
   ranked by ``priority`` (higher first), then by how many runs suggest them.

A step disappears once the same plugin with the same args is queued, running or succeeded on
the image (a failed/cancelled attempt keeps it, marked "last attempt failed"). Steps for another
OS are hidden when the image's OS is known (a ``linux.`` plugin on a Windows image). Analysts can
Run a step, Edit its options first, run the remaining baseline at once, or Dismiss a step for
one image. The top 5 are shown; "Show all" lists the rest.

How to add a step
-----------------
1. Make sure the plugin is in the catalog (plugins.py) with the options you need. A guide step
   can only use catalog plugins and their ArgSpec names: it is validated exactly like a user's
   manual input.
2. Add a ``Step(...)``:
     - ``plugin``: full plugin name, e.g. ``"windows.pstree.PsTree"``.
     - ``reason``: ONE short sentence telling the analyst why this is the next useful thing.
       It is shown next to the Run button, so write it for a junior analyst.
     - ``args`` (optional): e.g. ``{"pid": [4]}``. Leave empty for a plain run.
     - ``when`` (NEXT steps only, optional) - when the source run makes this step relevant:
         "succeeded"  (default) the source run succeeded
         "has_rows"   ... and returned at least one row
         "has_flags"  ... and a post-run hook flagged at least one of its rows
         "tag:<tag>"  ... and a hook flagged a row with that tag, e.g. "tag:suspicious-parent"
       Steps cannot use values from the rows (e.g. "the flagged PID"): that needs a post-run
       hook (hooks/README.md), which can queue follow-ups with computed args.
     - ``priority`` (NEXT steps only, optional int, default 0): higher is shown first.
3. Check it: ``python -m app.tools.volatility.guide`` prints the whole guide as Markdown and
   lists problems (exit code 1 if any). The same check runs in CI (tests/test_guide.py), on
   the System page, and on the Guide page (/guide). Invalid steps are skipped, never shown.
4. Optional: add a test for a non-trivial rule (see "Testing a guide rule" in README.md here).

Good practice: keep the baseline short (4-8 cheap, high-value plugins); every NEXT step should
answer "what would an experienced analyst look at after seeing this output?".
"""

from __future__ import annotations

from app.tools.base import GuideStep as Step

# Run in this order after the image is identified. EXAMPLE - TODO(forensics).
BASELINE: list[Step] = [
    Step("windows.pslist.PsList", "Which processes were running when memory was captured?"),
    Step("windows.pstree.PsTree", "Who started whom: look for unusual parent processes."),
    Step("windows.cmdline.CmdLine", "How each process was started (paths, arguments)."),
    Step("windows.netscan.NetScan", "Network connections and listening ports."),
]

# "After <plugin> succeeded, suggest ...". EXAMPLE - TODO(forensics).
NEXT: dict[str, list[Step]] = {
    "windows.info.Info": [
        Step("windows.pslist.PsList", "The image is identified: start with the process list."),
    ],
    "windows.pslist.PsList": [
        Step(
            "windows.pstree.PsTree",
            "Processes were found: check their parent/child relations.",
            when="has_rows",
            priority=10,
        ),
        Step(
            "windows.cmdline.CmdLine",
            "A hook flagged processes: see how they were started.",
            when="has_flags",
            priority=20,
        ),
        Step(
            "windows.pslist.PsList",
            "Dump the System process (PID 4) for offline analysis; files can be large.",
            args={"pid": [4], "dump": True},
        ),
    ],
    "windows.pstree.PsTree": [
        Step(
            "windows.cmdline.CmdLine",
            "A process has a parent that is not in the list: check its command line.",
            when="tag:suspicious-parent",
            priority=20,
        ),
    ],
    "windows.netscan.NetScan": [
        Step(
            "windows.pstree.PsTree",
            "Connections were found: map their owner processes in the tree.",
            when="has_rows",
        ),
    ],
}


if __name__ == "__main__":  # python -m app.tools.volatility.guide -> print guide + problems
    from app.tools.guide import main

    raise SystemExit(main())
