from __future__ import annotations

import csv
import json
import os
import platform
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path
from typing import Iterable

import psutil
import yaml

from .baselines import build_baseline
from .ablations import ablation_mode, apply_ablation
from .experiment import ExperimentRunner
from .io import read_json
from .real_data import iter_xes_cases, load_dataset_manifest, stable_split
from .real_instrumentation import instrument_real_case
from .real_rules import evaluate_real_case
from .types import BenchmarkCase


def run_real_experiment(
    dataset_id: str,
    split: str,
    profile_name: str,
    config_path: str,
    resources_path: str,
    manifest_path: str,
    output_path: str,
    ledger_path: str,
) -> dict:
    config = read_json(config_path)
    resources = yaml.safe_load(Path(resources_path).read_text(encoding="utf-8"))["profiles"][profile_name]
    manifest = load_dataset_manifest(manifest_path)[dataset_id]
    _apply_thread_limits(resources)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    completed = _load_completed_ids(output)
    max_cases = resources.get("max_cases")
    workers = int(resources["cpu_workers"])
    checkpoint_every = int(resources["checkpoint_every"])
    baselines = list(config.get("baselines", []))
    start = time.perf_counter()
    submitted = 0
    written = 0
    failed = 0
    pending = set()

    with output.open("a", encoding="utf-8", buffering=1) as handle, ProcessPoolExecutor(max_workers=workers) as pool:
        for real_case in iter_xes_cases(manifest["file"], dataset_id):
            if stable_split(dataset_id, real_case.case_id) != split:
                continue
            case_key = f"{dataset_id}:{real_case.case_id}"
            if case_key in completed:
                continue
            finding = evaluate_real_case(real_case)
            benchmark_case = instrument_real_case(real_case, finding, config.get("policy", {}))
            pending.add(pool.submit(_evaluate_case, benchmark_case, config, baselines))
            submitted += 1
            if len(pending) >= workers * 3:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        handle.write(json.dumps(future.result(), ensure_ascii=False) + "\n")
                        written += 1
                    except Exception as exc:
                        failed += 1
                        handle.write(json.dumps({"status": "failed", "error": repr(exc)}, ensure_ascii=False) + "\n")
                if written and written % checkpoint_every == 0:
                    handle.flush()
            if max_cases is not None and submitted >= int(max_cases):
                break
        for future in pending:
            try:
                handle.write(json.dumps(future.result(), ensure_ascii=False) + "\n")
                written += 1
            except Exception as exc:
                failed += 1
                handle.write(json.dumps({"status": "failed", "error": repr(exc)}, ensure_ascii=False) + "\n")

    elapsed = time.perf_counter() - start
    metadata = {
        "run_id": f"{dataset_id}-{split}-{profile_name}-{int(time.time())}",
        "dataset": dataset_id,
        "split": split,
        "profile": profile_name,
        "submitted": submitted,
        "written": written,
        "failed": failed,
        "elapsed_seconds": elapsed,
        "cases_per_second": written / elapsed if elapsed else 0.0,
        "output": str(output),
        "workers": workers,
        "peak_process_rss_gb": psutil.Process().memory_info().rss / 2**30,
        "python": platform.python_version(),
        "status": "complete" if failed == 0 else "complete_with_failures",
    }
    output.with_suffix(output.suffix + ".meta.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    _append_ledger(ledger_path, metadata, config_path, submitted)
    return metadata


def run_real_ablation_experiment(
    dataset_id: str,
    split: str,
    profile_name: str,
    config_path: str,
    resources_path: str,
    manifest_path: str,
    output_path: str,
    ledger_path: str,
) -> dict:
    config = read_json(config_path)
    resources = yaml.safe_load(Path(resources_path).read_text(encoding="utf-8"))["profiles"][profile_name]
    manifest = load_dataset_manifest(manifest_path)[dataset_id]
    _apply_thread_limits(resources)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    completed = _load_completed_ids(output)
    max_cases = resources.get("max_cases")
    workers = int(resources["cpu_workers"])
    names = list(config.get("ablations", []))
    start = time.perf_counter()
    submitted = written = failed = 0
    pending = set()
    with output.open("a", encoding="utf-8", buffering=1) as handle, ProcessPoolExecutor(max_workers=workers) as pool:
        for real_case in iter_xes_cases(manifest["file"], dataset_id):
            if stable_split(dataset_id, real_case.case_id) != split:
                continue
            case_key = f"{dataset_id}:{real_case.case_id}"
            if case_key in completed:
                continue
            finding = evaluate_real_case(real_case)
            benchmark_case = instrument_real_case(real_case, finding, config.get("policy", {}))
            pending.add(pool.submit(_evaluate_ablation_case, benchmark_case, config, names))
            submitted += 1
            if len(pending) >= workers * 3:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        handle.write(json.dumps(future.result(), ensure_ascii=False) + "\n")
                        written += 1
                    except Exception as exc:
                        failed += 1
                        handle.write(json.dumps({"status": "failed", "error": repr(exc)}, ensure_ascii=False) + "\n")
            if max_cases is not None and submitted >= int(max_cases):
                break
        for future in pending:
            try:
                handle.write(json.dumps(future.result(), ensure_ascii=False) + "\n")
                written += 1
            except Exception as exc:
                failed += 1
                handle.write(json.dumps({"status": "failed", "error": repr(exc)}, ensure_ascii=False) + "\n")
    elapsed = time.perf_counter() - start
    metadata = {
        "run_id": f"{dataset_id}-{split}-{profile_name}-ablation-{int(time.time())}",
        "dataset": dataset_id,
        "split": split,
        "profile": f"{profile_name}-ablation",
        "submitted": submitted,
        "written": written,
        "failed": failed,
        "elapsed_seconds": elapsed,
        "cases_per_second": written / elapsed if elapsed else 0.0,
        "output": str(output),
        "workers": workers,
        "peak_process_rss_gb": psutil.Process().memory_info().rss / 2**30,
        "python": platform.python_version(),
        "status": "complete" if failed == 0 else "complete_with_failures",
    }
    output.with_suffix(output.suffix + ".meta.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    _append_ledger(ledger_path, metadata, config_path, submitted)
    return metadata


def _evaluate_case(case: BenchmarkCase, config: dict, baseline_names: list[str]) -> dict:
    runner = ExperimentRunner(config)
    results = {}
    for name in baseline_names:
        report = build_baseline(name).adjudicate(case, runner.adjudicator)
        results[name] = {
            "verdict": report.verdict.value,
            "correct": report.verdict == report.expected_verdict,
            "opened_nodes": len(report.subgraph.opened_node_ids),
            "selected_nodes": len(report.subgraph.node_ids),
            "leakage": report.subgraph.leakage,
            "replay_fidelity": report.replay.replay_fidelity,
            "latency_ms": report.replay.latency_ms,
            "receipt_verification_ms": report.replay.receipt_verification_time_ms,
            "policy_replay_ms": report.replay.policy_replay_time_ms,
        }
    return {
        "status": "ok",
        "dataset": case.scenario,
        "case_id": case.case_id,
        "split": case.trace.metadata["split"],
        "rule_id": case.trace.metadata["rule_id"],
        "event_count": case.trace.metadata["event_count"],
        "expected_verdict": case.dispute.expected_verdict.value,
        "baselines": results,
    }


def _evaluate_ablation_case(case: BenchmarkCase, config: dict, names: list[str]) -> dict:
    runner = ExperimentRunner(config)
    results = {}
    for name in names:
        trace = apply_ablation(case.trace, name)
        report = runner.adjudicator.adjudicate(trace, case.dispute, mode=ablation_mode(name))
        results[name] = {
            "verdict": report.verdict.value,
            "correct": report.verdict == report.expected_verdict,
            "opened_nodes": len(report.subgraph.opened_node_ids),
            "selected_nodes": len(report.subgraph.node_ids),
            "leakage": report.subgraph.leakage,
            "replay_fidelity": report.replay.replay_fidelity,
            "latency_ms": report.replay.latency_ms,
        }
    return {
        "status": "ok",
        "dataset": case.scenario,
        "case_id": case.case_id,
        "split": case.trace.metadata["split"],
        "rule_id": case.trace.metadata["rule_id"],
        "event_count": case.trace.metadata["event_count"],
        "expected_verdict": case.dispute.expected_verdict.value,
        "ablations": results,
    }


def summarize_real_output(paths: Iterable[str], output_path: str) -> dict:
    aggregates: dict[str, dict[str, float]] = {}
    counts: dict[str, int] = {}
    for path in paths:
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                if row.get("status") != "ok":
                    continue
                result_group = row.get("baselines") or row.get("ablations") or {}
                for name, values in result_group.items():
                    counts[name] = counts.get(name, 0) + 1
                    metric_keys = ["correct", "opened_nodes", "selected_nodes", "leakage", "replay_fidelity", "latency_ms"]
                    if "receipt_verification_ms" in values:
                        metric_keys.extend(["receipt_verification_ms", "policy_replay_ms"])
                    acc = aggregates.setdefault(name, {key: 0.0 for key in metric_keys})
                    for key in acc:
                        acc[key] += float(values[key])
    summary = {
        name: {key: value / counts[name] for key, value in totals.items()} | {"n": counts[name]}
        for name, totals in aggregates.items()
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _apply_thread_limits(resources: dict) -> None:
    os.environ["OMP_NUM_THREADS"] = str(resources.get("omp_threads", 1))
    os.environ["MKL_NUM_THREADS"] = str(resources.get("mkl_threads", 1))
    os.environ["OPENBLAS_NUM_THREADS"] = "1"
    os.environ["NUMEXPR_NUM_THREADS"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"


def _load_completed_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    completed = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("status") == "ok" and row.get("case_id"):
                completed.add(row["case_id"])
    return completed


def _append_ledger(path: str, metadata: dict, config_path: str, requested: int) -> None:
    ledger = Path(path)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "run_id": metadata["run_id"],
        "created_at": int(time.time()),
        "code_version": "working-tree",
        "config": config_path,
        "dataset": metadata["dataset"],
        "split": metadata["split"],
        "n_requested": requested,
        "n_valid": metadata["written"],
        "n_failed": metadata["failed"],
        "seed": "hash-split",
        "output": metadata["output"],
        "status": metadata["status"],
    }
    write_header = not ledger.exists() or ledger.stat().st_size == 0
    with ledger.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        if write_header:
            writer.writeheader()
        writer.writerow(row)
