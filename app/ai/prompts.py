"""Prompt templates for the AI analysis layer.

TODO(forensics): the forensics team owns the analysis prompt content. Everything below is a
generic placeholder that only encodes the infrastructure rules (citations, suggestion format).
"""

from __future__ import annotations

from app.tools.base import PluginSpec

# TODO(forensics): replace with a reviewed memory-forensics analysis prompt.
SYSTEM_PROMPT = """\
You are assisting a memory forensics analyst who is examining a RAM image with volatility3.

Rules:
1. Use ONLY the data provided in the context messages (evidence info, analyst notes and tool
   output rows). Do not invent processes, PIDs, addresses, paths or other values.
2. Cite every factual claim with the result row(s) it is based on, using the exact format
   [R<run>:<row>] (e.g. [R12:34]); several rows may be cited as [R12:34, R12:35]. Only cite
   row keys that appear in the context.
3. If the provided data is insufficient to answer, say so plainly and explain what further
   data would be needed.
4. Your output is an investigative lead, not evidence. Flag uncertainty and alternative
   benign explanations.
5. You may suggest additional tool queries, but you never run them. If you have suggestions,
   put them ONLY in one final fenced block exactly like this, as a JSON list (max 5 items):

```suggestions
[{"plugin": "<plugin name>", "args": {"<arg>": <value>}, "reason": "<why>"}]
```

   Use only plugins and argument names from the allowlist below. Omit the block if you
   have no suggestions.
"""

SUMMARIZE_RUN_QUESTION = (
    "Summarize the output of run R{run_id} ({plugin}). Describe what it shows, list the "
    "notable or suspicious entries as leads (with citations), and suggest follow-up queries "
    "if useful."
)  # TODO(forensics): per-plugin summary instructions.


def _arg_type_label(arg_type: str) -> str:
    return {"int_list": "list of int"}.get(arg_type, arg_type)


def render_plugin(spec: PluginSpec) -> str:
    line = f"- {spec.name}"
    if spec.description:
        line += f": {spec.description}"
    if spec.args:
        parts = []
        for a in spec.args:
            label = f"{a.name} ({_arg_type_label(a.type)}{', required' if a.required else ''})"
            parts.append(label)
        line += f"\n    args: {', '.join(parts)}"
    else:
        line += "\n    args: none"
    return line


def render_allowlist(tool: str = "volatility3") -> str:
    """Render the allowlisted plugins of a tool for inclusion in the system prompt."""
    from app.tools import registry  # imported lazily so tests can substitute it

    specs = registry.get_runner(tool).plugins()
    if not specs:
        return f"Allowlisted {tool} plugins: none."
    return f"Allowlisted {tool} plugins:\n" + "\n".join(render_plugin(s) for s in specs)


def build_system_prompt(tool: str = "volatility3") -> str:
    return f"{SYSTEM_PROMPT}\n{render_allowlist(tool)}\n"
