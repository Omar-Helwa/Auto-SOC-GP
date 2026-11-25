"""Download Splunk Security Content detections and macros (github.com/splunk/security_content).

Downloads the repository zip once and extracts only detections/ and macros/
into original/rules/splunk_security_content/. Files are not modified.

Usage:
    python download_rules.py
    python download_rules.py --branch develop --force
"""
from __future__ import annotations

import argparse
import io
import json
import shutil
import urllib.request
import zipfile
from datetime import datetime, timezone

from paths import RULES

REPO = "splunk/security_content"
KEEP = ("detections/", "macros/")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--branch", default="develop")
    ap.add_argument("--force", action="store_true", help="delete and re-download")
    args = ap.parse_args()

    if (RULES / "detections").exists() and not args.force:
        print(f"already present: {RULES} (use --force to refresh)")
        return 0
    if RULES.exists():
        shutil.rmtree(RULES)

    url = f"https://codeload.github.com/{REPO}/zip/refs/heads/{args.branch}"
    print(f"downloading {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "autosoc-dataset-loader"})
    with urllib.request.urlopen(req, timeout=600) as r:
        data = r.read()
    print(f"  {len(data):,} bytes")

    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            rel = name.split("/", 1)[1] if "/" in name else ""
            if not rel.startswith(KEEP) or name.endswith("/"):
                continue
            target = RULES / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(name))
            count += 1

    (RULES / "SOURCE.json").write_text(json.dumps({
        "repo": f"https://github.com/{REPO}", "branch": args.branch,
        "downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": count}, indent=2), encoding="utf-8")
    print(f"extracted {count} files to {RULES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
