from typing import Any, Mapping

from evaluation.judge import evaluate

def judge(judge_input: Mapping[str, Any]):
    """Public application boundary for deterministic evaluation."""
    return evaluate(judge_input)
