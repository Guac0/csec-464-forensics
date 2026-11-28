"""windows.info.Info: Windows version and kernel details of the memory image.

Checked against volatility3 2.28.2: no plugin options. Output rows have the columns
"Variable" and "Value".
"""

from tests.content.sdk import HookContext, Next, Plugin

PLUGIN = Plugin(
    name="windows.info.Info",
    description="Show Windows version and kernel details from the memory image.",
    # Runs automatically for every new image (identification only).
    auto_enumerate=True,
    # EXAMPLE comparison key: each row is one variable, so "changed" means its value differs.
    compare_keys=["Variable"],
    # EXAMPLE guide step - TODO(forensics): replace with the team's workflow.
    next=[
        Next("windows.pslist.PsList", "The image is identified: start with the process list."),
    ],
)


# Variables copied to top-level keys of the image's OS info (the rest go under "windows_info").
_KEYS = {
    "NTBuildLab": "build_lab",
    "NtProductType": "product_type",
    "MachineType": "machine_type",
    "SystemTime": "system_time",
    "KeNumberProcessors": "processors",
}


# EXAMPLE hook - TODO(forensics): review the variable names against real captured output.
@PLUGIN.post_run(version="1")
def record_os_info(ctx: HookContext) -> None:
    """Copy windows.info variables into the evidence's OS info."""
    variables: dict[str, str] = {}
    for row in ctx.rows():
        name, value = row.data.get("Variable"), row.data.get("Value")
        if isinstance(name, str) and value is not None:
            variables[name] = str(value)
    if not variables:
        return  # nothing recognisable; leave the OS info as it is

    metadata: dict[str, object] = {"os": "windows", "windows_info": variables}
    for variable, key in _KEYS.items():
        if variable in variables:
            metadata[key] = variables[variable]
    major, minor = variables.get("NtMajorVersion"), variables.get("NtMinorVersion")
    if major and minor:
        metadata["nt_version"] = f"{major}.{minor}"
    ctx.update_evidence_metadata(**metadata)
