import hashlib, json, os, re
from pathlib import Path
from typing import Any, Mapping

JUDGE_ROOT = Path(__file__).resolve().parents[2]

def save_output(result: Mapping[str, Any], directory: Path | str | None = None):
    """Save the judge_result as <judge_input_id>.json in the outputs folder and return its path.
    The folder is ``directory`` if given, else JUDGE_OUTPUT_DIR, else 04_deterministic_judge/outputs.
    """
    name = result.get("judge_input_id")
    if not name:
        # Unreadable input has no id: name the file by a hash of the result so it stays deterministic.
        digest = hashlib.sha256(json.dumps(result, sort_keys=True).encode("utf-8")).hexdigest()[:12]
        name = f"judge_result_{digest}"
    file_name = re.sub(r"[^A-Za-z0-9._-]", "_", name) + ".json"

    target = Path(directory or os.environ.get("JUDGE_OUTPUT_DIR") or JUDGE_ROOT / "outputs")
    target.mkdir(parents=True, exist_ok=True)
    path = target / file_name
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return path
