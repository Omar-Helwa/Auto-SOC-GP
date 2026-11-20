"""Permitted benign scenario families (Epic C1).

Each family is a category of *legitimate* activity that can nonetheless trip a
detection rule as a false positive. These descriptions feed the red context /
prompt so the model proposes in-scope, benign look-alikes — never real attacks.
Keys match the `scenario.family` enum in the red_proposal contract.
"""

from __future__ import annotations

from schemas import constants

FAMILY_DESCRIPTIONS: dict[str, str] = {
    "admin_automation": (
        "Sanctioned administrative automation — scripts, scheduled tasks, and "
        "configuration management run by IT or service accounts."
    ),
    "software_deployment": (
        "Legitimate software installation and updates via installers, package "
        "managers, or deployment tools."
    ),
    "it_maintenance": (
        "Routine maintenance: patching, scheduled backups, disk cleanup, log "
        "rotation, and service restarts."
    ),
    "developer_activity": (
        "Normal developer workflows: build tools, debuggers, encoded command "
        "arguments, local servers, and CI steps."
    ),
    "power_user_tooling": (
        "Legitimate use of dual-use system tools (e.g. certutil, bitsadmin, "
        "netcat) for real administrative tasks."
    ),
    "backup_and_recovery": (
        "Backup and restore jobs, volume snapshots, and archive creation/extraction."
    ),
    "security_tooling": (
        "Sanctioned security activity: AV/EDR, vulnerability and compliance "
        "scanners, and authorized security testing."
    ),
}

# Safety: every contract family must have a description.
assert set(FAMILY_DESCRIPTIONS) == set(constants.SCENARIO_FAMILIES), (
    "FAMILY_DESCRIPTIONS out of sync with the red_proposal family enum"
)


def describe_families(families: list[str]) -> str:
    """Render a bullet list describing the given allowed families (for prompts)."""
    lines = []
    for fam in families:
        desc = FAMILY_DESCRIPTIONS.get(fam, "(no description)")
        lines.append(f"- {fam}: {desc}")
    return "\n".join(lines)
