"""EXAMPLE hook: record OS details from windows.info on the evidence.

TODO(forensics): review and extend. This is a working example of the hook mechanism, not a
reviewed forensic interpretation. Verified against volatility3 2.28.2: windows.info outputs rows
with "Variable" and "Value" columns. Check the variable names against a real captured fixture.
"""

from __future__ import annotations

from app.tools.hooks import HookContext, post_run

# Variables copied to top-level evidence metadata keys (the rest go under "windows_info").
_KEYS = {
    "NTBuildLab": "build_lab",
    "NtProductType": "product_type",
    "MachineType": "machine_type",
    "SystemTime": "system_time",
    "KeNumberProcessors": "processors",
}


@post_run("windows.info.Info", version="1")
def record_os_info(ctx: HookContext) -> None:
    """Copy windows.info variables into the evidence's OS info."""
    variables: dict[str, str] = {}
    for row in ctx.rows():
        name, value = row.data.get("Variable"), row.data.get("Value")
        if isinstance(name, str) and value is not None:
            variables[name] = str(value)
    if not variables:
        return  # nothing recognisable; leave metadata untouched

    metadata: dict[str, object] = {"os": "windows", "windows_info": variables}
    for variable, key in _KEYS.items():
        if variable in variables:
            metadata[key] = variables[variable]
    major, minor = variables.get("NtMajorVersion"), variables.get("NtMinorVersion")
    if major and minor:
        metadata["nt_version"] = f"{major}.{minor}"
    ctx.update_evidence_metadata(**metadata)
