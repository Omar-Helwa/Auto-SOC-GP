"""Download the benign command-line / PowerShell sets from SOCBED (github.com/fkie-cad/amides).

SOCBED is the benign dataset released with the AMIDES paper (USENIX Security 2024,
usenix.org/conference/usenixsecurity24/presentation/uetz). It contains benign
Windows process-creation command lines and benign PowerShell scripts. Each line
is one benign event. Files are copied unchanged into
original/attacks/benign/socbed__<subset>/ with a manifest that gives the Splunk
sourcetype/source to use.

Usage:
    python download_benign_socbed.py
"""
from __future__ import annotations

import json
import urllib.request

from paths import BENIGN

RAW = "https://raw.githubusercontent.com/fkie-cad/amides/main/data/socbed"
SUBSETS = {
    # subset -> (sourcetype, source, field name holding the event text)
    "process_creation": ("socbed:process_creation", "socbed:process_creation", "CommandLine"),
    "powershell": ("socbed:powershell", "socbed:powershell", "ScriptBlockText"),
}


def main() -> int:
    for subset, (sourcetype, source, field) in SUBSETS.items():
        url = f"{RAW}/{subset}/all"
        data = urllib.request.urlopen(url, timeout=120).read()
        out = BENIGN / f"socbed__{subset}"
        out.mkdir(parents=True, exist_ok=True)
        lines = [line for line in data.decode("utf-8", errors="replace").splitlines() if line.strip()]
        # Normalise to JSON lines so the builder records each line as one event.
        jsonl = out / "events.jsonl"
        with jsonl.open("w", encoding="utf-8", newline="\n") as fh:
            for line in lines:
                text = line.strip()
                if len(text) > 1 and text[0] == text[-1] == '"':
                    text = text[1:-1]
                fh.write(json.dumps({field: text, "EventID": 1 if subset == "process_creation" else 4104,
                                     "socbed_subset": subset}, ensure_ascii=False) + "\n")
        (out / "manifest.yml").write_text(
            f"source_repo: https://github.com/fkie-cad/amides\n"
            f"source_url: {url}\n"
            f"citation: Uetz et al., AMIDES, USENIX Security 2024\n"
            f"label_basis: benign by construction (SOCBED benign set)\n"
            f"sourcetype: {sourcetype}\n"
            f"source: {source}\n"
            f"datasets:\n"
            f"  - name: events\n"
            f"    path: events.jsonl\n"
            f"    sourcetype: {sourcetype}\n"
            f"    source: {source}\n",
            encoding="utf-8")
        print(f"{subset}: {len(lines)} benign events -> {jsonl}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
