import argparse, json, sys
from pathlib import Path

SANDBOX_DIR = Path(__file__).resolve().parent
JUDGE_ROOT = (SANDBOX_DIR / "../..").resolve()
sys.path.insert(0, str(JUDGE_ROOT))

from interfaces.inputs.judge_input import run_judge
from interfaces.outputs.judge_result import save_output

DATA_DIR = JUDGE_ROOT / "dev" / "mocks"
OUTPUT_DIR = JUDGE_ROOT / "dev" / "temp_outputs"
BASELINE_DIR = DATA_DIR / "baseline_matches"
CANDIDATE_DIR = DATA_DIR / "candidate_matches"
LABELS_DIR = DATA_DIR / "reviewed_labels"
CASES = ("case_001", "case_002", "case_003", "case_004")

def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)

def build_input(case: str):
    """Assemble a judge_input bundle from one mock case, as the Orchestrator would."""
    baseline = load_json(BASELINE_DIR / f"{case}.json")
    candidate = load_json(CANDIDATE_DIR / f"{case}.json")
    labels = load_json(LABELS_DIR / f"{case}.json")
    return {
        "contract_version": "0.1.0",
        "judge_input_id": f"judge-input-{case}",
        "task_id": baseline["task_id"],
        "detection_id": baseline["detection_id"],
        "baseline_match_set": baseline,
        "candidate_match_set": candidate,
        "reviewed_label_set": labels,
        "criteria": {
            "minimum_attack_retention": 1.0,
            "maximum_new_benign_matches": 0,
        },
        "versions": {
            "round_request": "0.1.0",
            "red_prompt": "dev",
            "blue_prompt": "dev",
        },
    }

def main():
    parser = argparse.ArgumentParser(description="Run the deterministic judge locally.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", type=Path, help="judge_input bundle JSON")
    source.add_argument("--case", choices=CASES, default="case_001", help="mock case to run")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="where to save the result")
    args = parser.parse_args()

    bundle = load_json(args.input) if args.input else build_input(args.case)
    result = run_judge(bundle)
    path = save_output(result, args.output_dir)
    print(json.dumps(result, indent=2))
    print(f"\nsaved: {path}", file=sys.stderr)

if __name__ == "__main__":
    main()
