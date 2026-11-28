"""Everything a plugin file needs, in one import:

    from forensics.sdk import AIContext, Arg, Baseline, HookContext, Next, Plugin, Preset

- Plugin:   one volatility3 plugin: its name, options, presets, comparison keys, and where it
            sits in the investigation guide.
- Arg:      one option of the plugin that analysts may use (for example --pid).
- Preset:   a one-click query shown on the run form, e.g. Preset("PID 4 (System)", pid=[4]).
- Baseline: put the plugin in the standard first pass, e.g. Baseline(10, "Why run it").
- Next:     "after this plugin ran, suggest that one", e.g. Next("windows.pstree.PsTree", "Why").
- AIContext: which rows of a run are sent to the AI, e.g. AIContext(max_rows=200).
- HookContext / post_run: for hooks (Python that runs after a run and flags rows).

README.md in this folder explains each field with examples.
"""

from app.tools.base import ArgSpec as Arg
from app.tools.base import GuideStep as Next
from app.tools.content import AIContext, Baseline, Plugin, Preset
from app.tools.hooks import HookContext, post_run

__all__ = ["AIContext", "Arg", "Baseline", "HookContext", "Next", "Plugin", "Preset", "post_run"]
