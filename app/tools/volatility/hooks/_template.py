"""TEMPLATE for a new hook. Copy to a new file WITHOUT the leading underscore (files starting with
"_" are not loaded), rename the function, and set the plugin name(s).

Everything below is illustrative: the column names, tags and logic are placeholders.
"""

from __future__ import annotations

from app.tools.hooks import HookContext, post_run


@post_run("windows.example.Example", version="1")  # full plugin name(s) from plugins.py, or "*"
def example_hook(ctx: HookContext) -> None:
    """One-line description (shown in the hook list)."""
    flagged: list[int] = []
    for row in ctx.rows():  # read-only copies: row.row_idx, row.depth, row.parent_idx, row.data
        if row.data.get("SomeColumn") == "something interesting":
            ctx.annotate(row.row_idx, "interesting", severity="low", note="why it matters")
            flagged.append(row.row_idx)

    if flagged:
        ctx.add_finding(
            f"{len(flagged)} interesting rows",
            detail="What an analyst should check next.",
            severity="low",
            rows=flagged,  # rendered as citations R<run>:<row>
        )
        # Optional: queue another plugin (allowlist, de-duplication and loop guards apply).
        ctx.queue_follow_up("windows.other.Other", {"pid": [4]}, reason="inspect flagged PIDs")

    # Optional: facts about the image itself (merged into Evidence.os_info).
    # ctx.update_evidence_metadata(some_fact="value")

    # Cross-reference another plugin's latest successful run on the same evidence:
    # other = ctx.latest_run("windows.psscan.PsScan")
    # if other: for row in ctx.rows(other.id): ...
