from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import _bootstrap  # noqa: F401
import numpy as np


METRICS = ["correct", "opened_nodes", "selected_nodes", "leakage", "replay_fidelity", "latency_ms"]
COMPARISONS = ["full_replay_oracle", "otel_logs", "agent_sentry_bounds"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze held-out real-data results with paired block bootstrap.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--blocks", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20260618)
    args = parser.parse_args()
    result = analyze(args.input, args.bootstrap, args.blocks, args.seed)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result["headline"], indent=2))


def analyze(path: str, bootstrap: int, block_count: int, seed: int) -> dict:
    totals: dict[str, Counter] = defaultdict(Counter)
    confusion: dict[str, Counter] = defaultdict(Counter)
    expected_counts: Counter = Counter()
    blocks: dict[str, list[Counter]] = {
        name: [Counter() for _ in range(block_count)] for name in COMPARISONS
    }
    n = 0
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("status") != "ok":
                continue
            n += 1
            expected = row["expected_verdict"]
            expected_counts[expected] += 1
            for name, values in row["baselines"].items():
                for metric in METRICS:
                    totals[name][metric] += float(values[metric])
                confusion[name][f"{expected}->{values['verdict']}"] += 1
            block = int(hashlib.sha256(row["case_id"].encode("utf-8")).hexdigest()[:8], 16) % block_count
            crr = row["baselines"]["crr_agent"]
            for comparator in COMPARISONS:
                other = row["baselines"][comparator]
                entry = blocks[comparator][block]
                entry["n"] += 1
                entry["accuracy_diff"] += float(crr["correct"]) - float(other["correct"])
                entry["leakage_diff"] += float(crr["leakage"]) - float(other["leakage"])
                entry["opened_diff"] += float(crr["opened_nodes"]) - float(other["opened_nodes"])

    summaries = {}
    for name, values in totals.items():
        correct = values["correct"]
        accuracy = correct / n
        summaries[name] = {
            metric: values[metric] / n for metric in METRICS
        }
        summaries[name]["accuracy_ci95"] = _wilson_interval(correct, n)
        summaries[name]["confusion"] = dict(confusion[name])
        summaries[name]["per_class_recall"] = _per_class_recall(confusion[name], expected_counts)

    paired = {
        comparator: _bootstrap_differences(block_rows, bootstrap, seed + index)
        for index, (comparator, block_rows) in enumerate(blocks.items())
    }
    crr = summaries["crr_agent"]
    full = summaries["full_replay_oracle"]
    headline = {
        "n": n,
        "label_distribution": dict(expected_counts),
        "crr_accuracy": crr["correct"],
        "crr_accuracy_ci95": crr["accuracy_ci95"],
        "full_accuracy": full["correct"],
        "crr_opened_nodes": crr["opened_nodes"],
        "full_opened_nodes": full["opened_nodes"],
        "opened_node_reduction_vs_full": 1.0 - crr["opened_nodes"] / full["opened_nodes"],
        "crr_leakage": crr["leakage"],
        "full_leakage": full["leakage"],
        "leakage_reduction_vs_full": 1.0 - crr["leakage"] / full["leakage"],
        "crr_latency_ms": crr["latency_ms"],
        "full_latency_ms": full["latency_ms"],
    }
    return {
        "source": path,
        "bootstrap_replicates": bootstrap,
        "bootstrap_blocks": block_count,
        "headline": headline,
        "methods": summaries,
        "paired_crr_minus_comparator": paired,
    }


def _bootstrap_differences(rows: list[Counter], replicates: int, seed: int) -> dict:
    counts = np.array([row["n"] for row in rows], dtype=np.float64)
    values = {
        metric: np.array([row[metric] for row in rows], dtype=np.float64)
        for metric in ["accuracy_diff", "leakage_diff", "opened_diff"]
    }
    rng = np.random.default_rng(seed)
    draws = rng.integers(0, len(rows), size=(replicates, len(rows)))
    denominator = counts[draws].sum(axis=1)
    result = {}
    for metric, array in values.items():
        samples = array[draws].sum(axis=1) / denominator
        result[metric] = {
            "mean": float(array.sum() / counts.sum()),
            "ci95": [float(np.quantile(samples, 0.025)), float(np.quantile(samples, 0.975))],
        }
    return result


def _wilson_interval(successes: float, total: int, z: float = 1.959963984540054) -> list[float]:
    if total == 0:
        return [0.0, 0.0]
    p = successes / total
    denominator = 1.0 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [center - margin, center + margin]


def _per_class_recall(confusion: Counter, expected_counts: Counter) -> dict[str, float]:
    return {
        label: confusion.get(f"{label}->{label}", 0) / count
        for label, count in expected_counts.items()
        if count
    }


if __name__ == "__main__":
    main()
