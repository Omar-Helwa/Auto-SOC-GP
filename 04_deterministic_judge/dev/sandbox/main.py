import argparse, json, sys
from pathlib import Path

SANDBOX_DIR = Path(__file__).resolve().parent
JUDGE_ROOT = (SANDBOX_DIR / "../..").resolve()
sys.path.insert(0, str(JUDGE_ROOT))
from interfaces.judge_interface import judge

DATA_DIR = (SANDBOX_DIR / "../../dev/mocks").resolve()
OUTPUT_DIR = (SANDBOX_DIR / "../../dev/temp_outputs").resolve()
BASELINE_DIR = DATA_DIR / "baseline_matches"
CANDIDATE_DIR = DATA_DIR / "candidate_matches"
LABELS_DIR = DATA_DIR / "reviewed_labels"

def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)

def build_input(case: str):
    baseline = load_json(BASELINE_DIR / f"{case}.json")
    candidate = load_json(CANDIDATE_DIR / f"{case}.json")
    labels = load_json(LABELS_DIR / f"{case}.json")

    return {
        "judge_input_id": f"judge-input-{case}",
        "task_id": baseline["task_id"],
        "evaluation_set": {
            "evaluation_set_id": baseline["evaluation_set_id"],
            "evaluation_set_version": baseline["evaluation_set_version"],
            "expected_event_ids": [
                item["event_id"] for item in labels["labels"]
            ],
        },
        "baseline": baseline,
        "candidate": candidate,
        "reviewed_labels": labels,
        "criteria": {
            "criteria_id": "criteria-dev-001",
            "criteria_version": "1.0",
            "minimum_attack_retention": 1.0,
            "maximum_new_benign_matches": 0,
        },
        "provenance": {
            "baseline_execution_id": baseline["execution"]["execution_id"],
            "candidate_execution_id": candidate["execution"]["execution_id"],
            "label_set_id": labels["label_set_id"],
            "criteria_id": "criteria-dev-001",
            "criteria_version": "1.0",
        },
    }

def main():
    parser = argparse.ArgumentParser(description="Run the deterministic judge.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", type=Path, help="assembled judge input JSON")
    source.add_argument(
        "--case",
        choices=("case_001", "case_002", "case_003"),
        default="case_001",
        help="mock case to run",
    )
    parser.add_argument("--output", type=Path, help="optional output JSON path")
    args = parser.parse_args()

    if args.input:
        result = judge(load_json(args.input))
    else:
        result = judge(build_input(args.case))

    serialized = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    else:
        output_path = OUTPUT_DIR / f"{args.case or 'judge_result'}.json"
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path.write_text(serialized, encoding="utf-8")
        print(serialized, end="")

if __name__ == "__main__":
    main()
