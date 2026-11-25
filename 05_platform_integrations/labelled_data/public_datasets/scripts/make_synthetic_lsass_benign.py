"""Write SYNTHETIC benign Sysmon EventID 8 events for the LSASS remote-thread rule.

The rule "Create Remote Thread into LSASS" lists legitimate security tools as
its known false positives, but no downloaded dataset contains such events, and
reproducing one would mean injecting a thread into LSASS on a host. These
events are therefore constructed, not observed. They model a fictional agent
("Contoso EDR", Contoso being a placeholder vendor name) so they make no claim
about a real product's behaviour.

Output: original/attacks/benign/lab__synthetic_lsass_edr/{events.xml,manifest.yml}
The ``lab__`` prefix makes build_evaluation_set.py label them
``source: lab_telemetry`` (the label schema has no "synthetic" source and they
are not a public dataset). Their scenario_id and manifest say "synthetic".
Labels still start unreviewed: a human reviews them with the demo subset.

    python make_synthetic_lsass_benign.py
"""

from __future__ import annotations

import argparse
from pathlib import Path

from paths import BENIGN

FOLDER = "lab__synthetic_lsass_edr"
SYSMON_SOURCE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
AGENT = "C:\\Program Files\\Contoso EDR\\ContosoAgent.exe"
HOOK = "C:\\Program Files\\Contoso EDR\\ContosoHook.dll"

# (time, record id, host, source pid, source guid, target pid, target guid, thread, address, function)
EVENTS = (
    ("2026-11-20T08:15:02.104000000Z", 91001, "lab-ws-01.autosoc.local", 3120,
     "{6A1F2C3D-1A2B-6741-1001-000000000301}", 712, "{6A1F2C3D-0F11-6741-0C00-000000000301}",
     5104, "0x00007FFB1A2C1040", "ContosoSensorAttach"),
    ("2026-11-20T09:42:37.551000000Z", 91002, "lab-ws-02.autosoc.local", 2988,
     "{7B2E3D4C-2B3C-6741-1002-000000000302}", 696, "{7B2E3D4C-0F12-6741-0C00-000000000302}",
     4420, "0x00007FFB1A2C1040", "ContosoSensorAttach"),
    ("2026-11-21T07:03:11.920000000Z", 91003, "lab-dc-01.autosoc.local", 3456,
     "{8C3F4E5D-3C4D-6741-1003-000000000303}", 744, "{8C3F4E5D-0F13-6741-0C00-000000000303}",
     6012, "0x00007FFB1A2C1110", "ContosoCredGuardCheck"),
)

MANIFEST = f"""\
# SYNTHETIC benign events: constructed by scripts/make_synthetic_lsass_benign.py,
# not recorded from a real host. Fictional vendor "Contoso EDR".
label_basis: synthetic benign (modelled on the rule's documented false positive, legitimate security tooling)
synthetic: true
sourcetype: XmlWinEventLog
source: {SYSMON_SOURCE}
datasets:
  - name: events
    path: events.xml
    sourcetype: XmlWinEventLog
    source: {SYSMON_SOURCE}
"""


def _event(time, record, host, spid, sguid, tpid, tguid, thread, address, function) -> str:
    data = (
        ("RuleName", "-"),
        ("UtcTime", time[:23].replace("T", " ")),
        ("SourceProcessGuid", sguid),
        ("SourceProcessId", str(spid)),
        ("SourceImage", AGENT),
        ("TargetProcessGuid", tguid),
        ("TargetProcessId", str(tpid)),
        ("TargetImage", "C:\\Windows\\System32\\lsass.exe"),
        ("NewThreadId", str(thread)),
        ("StartAddress", address),
        ("StartModule", HOOK),
        ("StartFunction", function),
    )
    event_data = "".join(f"<Data Name='{name}'>{value}</Data>" for name, value in data)
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>"
        "<EventID>8</EventID><Version>2</Version><Level>4</Level><Task>8</Task><Opcode>0</Opcode>"
        "<Keywords>0x8000000000000000</Keywords>"
        f"<TimeCreated SystemTime='{time}'/><EventRecordID>{record}</EventRecordID><Correlation/>"
        f"<Execution ProcessID='2152' ThreadID='3460'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        f"<Computer>{host}</Computer><Security UserID='S-1-5-18'/></System>"
        f"<EventData>{event_data}</EventData></Event>"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args()
    folder = BENIGN / FOLDER
    if folder.exists():
        raise SystemExit(f"refusing to overwrite {folder}; delete it to regenerate")
    folder.mkdir(parents=True)
    (folder / "events.xml").write_text(
        "".join(_event(*fields) + "\n" for fields in EVENTS), encoding="utf-8", newline="\n"
    )
    (folder / "manifest.yml").write_text(MANIFEST, encoding="utf-8", newline="\n")
    print(f"wrote {len(EVENTS)} SYNTHETIC benign events to {folder}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
