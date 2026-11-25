"""Download Splunk Attack Data scenarios (https://github.com/splunk/attack_data).

Each scenario folder has a YAML manifest (technique, sourcetype, source) plus
log files stored in Git LFS. LFS files are fetched from media.githubusercontent.com.

Usage:
    python download_attack_data.py                       # default scenarios
    python download_attack_data.py T1059.001/encoded_powershell T1003.001/atomic_red_team
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

import yaml  # pip install pyyaml

REPO = "splunk/attack_data"
BRANCH = "master"
API = f"https://api.github.com/repos/{REPO}/contents/datasets/attack_techniques"
RAW = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}"
MEDIA = f"https://media.githubusercontent.com/media/{REPO}/{BRANCH}"

DEFAULT_SCENARIOS = [
    "T1059.001/encoded_powershell",
    "T1059.001/hidden_powershell",
    "T1059.001/powershell_script_block_logging",
]

from paths import ATTACKS as RAW_DIR


def _get(url: str, timeout: int = 120) -> bytes:
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "autosoc-dataset-loader"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as exc:  # noqa: BLE001 - retry any network error
            if attempt == 2:
                raise RuntimeError(f"download failed: {url}: {exc}") from exc
            time.sleep(2 * (attempt + 1))
    raise AssertionError("unreachable")


def download_scenario(scenario: str, force: bool = False) -> Path:
    """scenario = '<technique>/<folder>', e.g. 'T1059.001/encoded_powershell'."""
    out = RAW_DIR / scenario.replace("/", "__")
    out.mkdir(parents=True, exist_ok=True)

    listing = json.loads(_get(f"{API}/{scenario}"))
    yml_files = [f for f in listing if f["name"].endswith((".yml", ".yaml"))]
    if not yml_files:
        raise RuntimeError(f"no manifest .yml in {scenario}")
    manifest_bytes = _get(yml_files[0]["download_url"])
    (out / "manifest.yml").write_bytes(manifest_bytes)
    manifest = yaml.safe_load(manifest_bytes)

    for ds in manifest.get("datasets", []):
        rel = ds["path"].lstrip("/")
        target = out / Path(rel).name
        if target.exists() and target.stat().st_size > 1024 and not force:
            print(f"  skip (exists) {target.name}")
            continue
        data = _get(f"{MEDIA}/{rel}")
        if data.startswith(b"version https://git-lfs"):
            data = _get(f"{RAW}/{rel}")  # not actually in LFS
        target.write_bytes(data)
        print(f"  {target.name}: {len(data):,} bytes")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenarios", nargs="*", default=DEFAULT_SCENARIOS)
    ap.add_argument("--force", action="store_true", help="re-download existing files")
    args = ap.parse_args(argv)
    for s in args.scenarios:
        print(f"[{s}]")
        try:
            print(f"  -> {download_scenario(s, args.force)}")
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
