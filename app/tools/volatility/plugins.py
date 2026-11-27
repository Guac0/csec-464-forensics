"""Allowlisted volatility3 plugins (the plugin catalog).

Only plugins listed here can ever be run, and only with the args declared in their ArgSpecs.

=====================================================================================
TODO(forensics): this catalog is owned by the forensic analysts. The two entries below
are EXAMPLES that prove the mechanism works; replace/extend them with the real catalog.
=====================================================================================

How to add a plugin
-------------------
1. ``name`` must be the FULL volatility3 plugin name exactly as listed by ``vol -h``
   (e.g. ``windows.pslist.PsList``). volatility3's CLI does *substring* matching on plugin
   names and errors if a name matches several plugins, so never use shortened names such
   as ``windows.pslist``.
2. ``args``: one ArgSpec per plugin option you want to expose. Check ``vol <plugin> --help``
   against the installed version (see Dockerfile) for each:
     - ``name``: key used in ToolRequest.args / the UI / AI suggestions (snake_case).
     - ``flag``: the long option exactly as shown in ``vol <plugin> --help`` (``--pid``).
       Only ``--long-flag`` form is accepted; global vol flags are refused (see runner.py).
     - ``type``:
         "int"      -> ``--flag N``         (volatility IntRequirement, parsed with int(x, 0))
         "int_list" -> ``--flag 1 2 3``     (volatility ListRequirement(element_type=int),
                                             argparse nargs="*"/"+")
         "bool"     -> ``--flag`` when true (volatility BooleanRequirement, store_true)
         "str"      -> ``--flag value``     (StringRequirement / URIRequirement etc.)
       Don't expose ``str`` list requirements yet: the runner has no "str_list" type.
     - ``required``: True only if the plugin itself requires it.
   Think twice before exposing options that write files (e.g. ``--dump``): output lands in
   ``<data_dir>/runs/<run_id>/output``, can be large (capped per run by FT_MAX_ARTIFACT_BYTES)
   and may be live malware. Such files are registered as derived artifacts: hashed, linked to
   the row naming them, and downloadable as an encrypted zip. Every option that writes files
   MUST be declared ``writes_files=True`` (or the whole PluginSpec, for plugins that always
   write, e.g. windows.dumpfiles.DumpFiles); the catalog check skips undeclared known ones.
   Entries that fail the catalog check (see ``catalog_problems`` in runner.py) are skipped,
   logged and shown on the System page; tests/test_catalog.py fails CI for them.
3. ``auto_enumerate=True`` puts the plugin in the "auto-enumerate" batch that is queued for
   each evidence item on request (one Run per plugin, no args). Choose cheap, high-value
   plugins; ``max_concurrent_runs`` defaults to 1 so the batch runs sequentially.
4. ``timeout_seconds``: set this for slow plugins (e.g. filescan/dumpfiles on big images);
   otherwise FT_RUN_TIMEOUT_SECONDS (1 h) applies.
5. ``presets``: (label, args) pairs shown as one-click suggested queries in the UI. The args
   are validated exactly like manual input, so they must use the ArgSpec names above.
6. OS detection: ``Evidence.os_info`` should be filled from ``windows.info.Info`` output
   (and linux/mac equivalents). That handling does not exist yet - it belongs in the worker's
   post-processing hook (see README.md in this directory).
7. Add a test in tests/test_tools_volatility.py for any non-trivial ArgSpec, and a fixture
   with real captured output under tests/fixtures/ (see README.md).
"""

from __future__ import annotations

from app.tools.base import ArgSpec, PluginSpec

# Verified against volatility3 2.28.2 (installed package source + `vol <plugin> --help`):
#   - windows.info.Info: no plugin options.
#   - windows.pslist.PsList: `--pid [PID ...]` is ListRequirement(name="pid", element_type=int,
#     optional=True); `--dump` is BooleanRequirement(name="dump", default=False) ("Extract listed
#     processes"); dumped files are named in the "File output" column. --physical not exposed.
PLUGINS: list[PluginSpec] = [
    # EXAMPLE entry - TODO(forensics): review/replace.
    PluginSpec(
        name="windows.info.Info",
        description="EXAMPLE: OS & kernel details of the memory sample.",
        auto_enumerate=True,
    ),
    # EXAMPLE entry - TODO(forensics): review/replace.
    PluginSpec(
        name="windows.pslist.PsList",
        description="EXAMPLE: processes from the active process list.",
        args=(
            ArgSpec(
                name="pid",
                flag="--pid",
                type="int_list",
                help="Only include these process IDs",
            ),
            # EXAMPLE of a file-writing option - TODO(forensics): decide which plugins may dump.
            # Output goes to runs/<id>/output, is hashed and downloadable (see
            # app/services/artifacts.py), and is capped by FT_MAX_ARTIFACT_BYTES.
            ArgSpec(
                name="dump",
                flag="--dump",
                type="bool",
                help="Extract the listed processes to files (can be large; combine with PID)",
                writes_files=True,
            ),
        ),
        presets=(("EXAMPLE: PID 4 (System)", {"pid": [4]}),),
    ),
]
