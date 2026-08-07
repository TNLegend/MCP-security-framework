import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.services.tool_analysis import (  # noqa: E402
    HashingEmbeddingModel,
    LocalEmbeddingModel,
    LocalZeroShotSemanticModel,
    SEMANTIC_CATEGORIES,
    SemanticResult,
    analyze_tool_version,
    compute_tool_fingerprint,
    tool_fingerprint_payload,
)


class HeuristicSemanticModel:
    model_name = "heuristic-evaluation-model"
    model_version = "1.0.0"

    def classify(self, text: str, categories: list[str]) -> SemanticResult:
        lowered = text.lower()
        scores = {category: 0.02 for category in categories}
        if (
            "ignore" in lowered
            or "restriction" in lowered
            or "safeguard" in lowered
            or "prefer the tool" in lowered
        ):
            scores["prompt_injection"] = 0.91
        if "upload" in lowered or "collector" in lowered:
            scores["data_exfiltration"] = 0.86
        if "api key" in lowered or "environment" in lowered:
            scores["secret_collection"] = 0.88
        if "shell" in lowered or "command" in lowered:
            scores["command_execution"] = 0.89
        if max(scores.values()) < 0.5:
            scores["normal_tool_description"] = 0.9
        best = max(scores, key=scores.get)
        return SemanticResult(
            scores=scores,
            best_category=best,
            confidence=scores[best],
            model_name=self.model_name,
            model_version=self.model_version,
            flagged=best != "normal_tool_description" and scores[best] >= 0.74,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the tool analyzer dataset.")
    parser.add_argument(
        "--dataset",
        default=str(BACKEND_DIR / "datasets" / "tool_description_analysis_v1.json"),
    )
    parser.add_argument("--output", default=None)
    parser.add_argument(
        "--real-models",
        action="store_true",
        help="Also evaluate with local MiniLM and E5 models.",
    )
    args = parser.parse_args()

    dataset = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    report: dict[str, Any] = {
        "dataset_id": dataset["dataset_id"],
        "version": dataset["version"],
        "examples": len(dataset["examples"]),
        "dataset_note": "Synthetic smoke dataset for Task 7B calibration; not a scientific benchmark.",
        "heuristic_test_metrics": evaluate_dataset(
            dataset,
            semantic_model=HeuristicSemanticModel(),
            embedding_model=HashingEmbeddingModel(),
        ),
    }
    if args.real_models:
        report["real_model_metrics"] = evaluate_dataset(
            dataset,
            semantic_model=LocalZeroShotSemanticModel(),
            embedding_model=LocalEmbeddingModel(),
        )

    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    print(output)
    return 0


def evaluate_dataset(dataset: dict[str, Any], *, semantic_model, embedding_model) -> dict[str, Any]:
    rows = []
    tp = fp = fn = tn = 0
    total_latency_ms = 0.0
    for example in dataset["examples"]:
        tool_snapshot, baseline_snapshot, profile_snapshot = _snapshots(example)
        started = time.perf_counter()
        result = analyze_tool_version(
            tool_snapshot=tool_snapshot,
            baseline_snapshot=baseline_snapshot,
            profile_snapshot=profile_snapshot,
            semantic_model=semantic_model,
            embedding_model=embedding_model,
        )
        latency_ms = (time.perf_counter() - started) * 1000
        total_latency_ms += latency_ms
        fingerprint_changed = False
        if baseline_snapshot is not None:
            current_fingerprint = _fingerprint(tool_snapshot, profile_snapshot)
            baseline_fingerprint = _fingerprint(baseline_snapshot, profile_snapshot)
            fingerprint_changed = current_fingerprint != baseline_fingerprint
        predicted_risky = (
            result["semantic_flagged"]
            or result["deterministic_critical_finding"]
            or result["risk_level"] in {"high", "critical"}
            or fingerprint_changed
        )
        expected_risky = example["label"] in {"blocked", "review_required"}
        if predicted_risky and expected_risky:
            tp += 1
        elif predicted_risky and not expected_risky:
            fp += 1
        elif not predicted_risky and expected_risky:
            fn += 1
        else:
            tn += 1
        rows.append(
            {
                "id": example["id"],
                "expected_risky": expected_risky,
                "predicted_risky": predicted_risky,
                "risk_level": result["risk_level"],
                "drift_status": result["drift_status"],
                "fingerprint_changed": fingerprint_changed,
                "semantic_flagged": result["semantic_flagged"],
                "semantic_best_category": result["semantic_scores"]["best_category"],
                "semantic_confidence": result["semantic_scores"]["confidence"],
                "deterministic_critical_finding": result[
                    "deterministic_critical_finding"
                ],
                "latency_ms": round(latency_ms, 3),
            }
        )

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "model_versions": _model_versions(semantic_model, embedding_model),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "true_negatives": tn,
        "avg_latency_ms": round(total_latency_ms / len(dataset["examples"]), 3),
        "rows": rows,
    }


def _snapshots(example: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    schema_properties = {
        "path": {"type": "string"},
        **(example.get("schema_properties") or {}),
    }
    baseline_schema_properties = {
        "path": {"type": "string"},
        **(example.get("baseline_schema_properties") or {}),
    }
    tool_snapshot = {
        "name": "read_file",
        "description": example["text"],
        "input_schema": {
            "type": "object",
            "properties": schema_properties,
            "required": ["path"],
            "additionalProperties": False,
        },
        "output_schema": {},
        "annotations": {},
    }
    baseline_snapshot = None
    if example.get("baseline_text"):
        baseline_snapshot = {
            **tool_snapshot,
            "description": example["baseline_text"],
            "input_schema": {
                **tool_snapshot["input_schema"],
                "properties": baseline_schema_properties,
            },
        }
    profile_snapshot = {
        "revision": "eval-profile-v1",
        "operation": "read",
        "required_capability": "filesystem.read",
    }
    return tool_snapshot, baseline_snapshot, profile_snapshot


def _model_versions(semantic_model, embedding_model) -> dict[str, dict[str, str]]:
    return {
        "semantic": {
            "name": getattr(semantic_model, "model_name", "unknown"),
            "version": getattr(semantic_model, "model_version", "unknown"),
        },
        "embedding": {
            "name": getattr(embedding_model, "model_name", "unknown"),
            "version": getattr(embedding_model, "model_version", "unknown"),
        },
    }


def _fingerprint(tool_snapshot: dict[str, Any], profile_snapshot: dict[str, Any]) -> str:
    return compute_tool_fingerprint(
        tool_fingerprint_payload(
            server_ref="eval-server",
            tool_name=tool_snapshot["name"],
            description=tool_snapshot.get("description"),
            input_schema=tool_snapshot.get("input_schema"),
            output_schema=tool_snapshot.get("output_schema"),
            annotations=tool_snapshot.get("annotations"),
            profile=profile_snapshot,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
