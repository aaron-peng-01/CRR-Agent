from __future__ import annotations

import argparse
from pathlib import Path

from .experiment import ExperimentRunner
from .io import read_json, read_jsonl, write_json, write_jsonl
from .scenarios import ScenarioGenerator
from .serde import cases_from_rows


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default="configs/default.json")


def generate_benchmark(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic CRR-Agent benchmark cases.")
    add_common_args(parser)
    parser.add_argument("--out", required=True)
    parser.add_argument("--num-cases", type=int, default=None)
    args = parser.parse_args(argv)

    config = read_json(args.config)
    generator = ScenarioGenerator(config)
    cases = generator.generate(args.num_cases)
    write_jsonl(args.out, [case.to_dict() for case in cases])


def run_baselines(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run configured baselines on a CRR-Agent benchmark.")
    add_common_args(parser)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--baseline", action="append", default=None)
    args = parser.parse_args(argv)

    config = read_json(args.config)
    cases = cases_from_rows(read_jsonl(args.benchmark))
    runner = ExperimentRunner(config)
    names = args.baseline or [name for name in config.get("baselines", []) if name != "crr_agent"]
    write_json(args.out, {name: runner.run_baseline(cases, name) for name in names})


def run_crr(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run CRR-Agent adjudication on a benchmark.")
    add_common_args(parser)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    config = read_json(args.config)
    cases = cases_from_rows(read_jsonl(args.benchmark))
    runner = ExperimentRunner(config)
    write_json(args.out, runner.run_baseline(cases, "crr_agent"))


def run_ablation(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run CRR-Agent ablations on a benchmark.")
    add_common_args(parser)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--ablation", action="append", default=None)
    args = parser.parse_args(argv)

    config = read_json(args.config)
    cases = cases_from_rows(read_jsonl(args.benchmark))
    runner = ExperimentRunner(config)
    names = args.ablation or config.get("ablations", [])
    write_json(args.out, {name: runner.run_ablation(cases, name) for name in names})


def run_cost_latency(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Sweep selector weights for privacy/cost/latency tradeoffs.")
    add_common_args(parser)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    base_config = read_json(args.config)
    cases = cases_from_rows(read_jsonl(args.benchmark))
    results = {}
    for leak_weight in [1.0, 2.0, 4.0, 8.0]:
        config = dict(base_config)
        selector = dict(base_config.get("selector", {}))
        selector["lambda_leak"] = leak_weight
        config["selector"] = selector
        runner = ExperimentRunner(config)
        results[f"lambda_leak_{leak_weight:g}"] = runner.run_baseline(cases, "crr_agent")
    write_json(args.out, results)


def export_tables(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Export compact JSON/CSV summaries from experiment result files.")
    parser.add_argument("--inputs", nargs="+", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for input_path in args.inputs:
        data = read_json(input_path)
        if "summary" in data:
            rows.append(_summary_row(Path(input_path).stem, data))
        else:
            for name, result in data.items():
                rows.append(_summary_row(name, result))
    write_json(out_dir / "summary.json", rows)
    with (out_dir / "summary.csv").open("w", encoding="utf-8") as fh:
        headers = sorted({key for row in rows for key in row})
        fh.write(",".join(headers) + "\n")
        for row in rows:
            fh.write(",".join(str(row.get(header, "")) for header in headers) + "\n")


def run_all(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the complete CRR-Agent experiment pipeline.")
    add_common_args(parser)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--num-cases", type=int, default=None)
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    benchmark = out_dir / "benchmark.jsonl"
    baselines = out_dir / "baselines.json"
    crr = out_dir / "crr_agent.json"
    ablation = out_dir / "ablation.json"
    cost_latency = out_dir / "cost_latency.json"
    tables = out_dir / "tables"

    generate_benchmark(["--config", args.config, "--out", str(benchmark)] + (["--num-cases", str(args.num_cases)] if args.num_cases else []))
    run_baselines(["--config", args.config, "--benchmark", str(benchmark), "--out", str(baselines)])
    run_crr(["--config", args.config, "--benchmark", str(benchmark), "--out", str(crr)])
    run_ablation(["--config", args.config, "--benchmark", str(benchmark), "--out", str(ablation)])
    run_cost_latency(["--config", args.config, "--benchmark", str(benchmark), "--out", str(cost_latency)])
    export_tables(["--inputs", str(baselines), str(crr), str(ablation), str(cost_latency), "--out", str(tables)])


def _summary_row(name: str, result: dict) -> dict:
    row = {"name": name}
    row.update(result.get("summary", {}))
    row.pop("by_claim_accuracy", None)
    row.pop("verdict_counts", None)
    return row
