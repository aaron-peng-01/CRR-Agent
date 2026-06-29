from __future__ import annotations

import argparse
import json

import _bootstrap  # noqa: F401

from crr_agent.real_experiment import run_real_experiment


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CRR-Agent on real business event logs.")
    parser.add_argument("--dataset", choices=["bpi2017", "bpi2019"], required=True)
    parser.add_argument("--split", choices=["validation", "test"], required=True)
    parser.add_argument("--profile", choices=["audit", "pilot", "full", "stress"], default="pilot")
    parser.add_argument("--config", default="configs/real_default.json")
    parser.add_argument("--resources", default="configs/resources.yaml")
    parser.add_argument("--manifest", default="data/manifests/datasets.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--ledger", default="docs/RESULT_LEDGER.csv")
    args = parser.parse_args()
    result = run_real_experiment(
        dataset_id=args.dataset,
        split=args.split,
        profile_name=args.profile,
        config_path=args.config,
        resources_path=args.resources,
        manifest_path=args.manifest,
        output_path=args.output,
        ledger_path=args.ledger,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
