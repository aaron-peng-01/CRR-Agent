import argparse

import _bootstrap  # noqa: F401

from crr_agent.controlled_experiments import run_selector_analysis
from crr_agent.io import read_json, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Run selector optimality, sensitivity, and wall-clock analysis.")
    parser.add_argument("--config", default="configs/default.json")
    parser.add_argument("--out", default="outputs/tables/selector_analysis_summary.json")
    parser.add_argument("--num-cases", type=int, default=250)
    args = parser.parse_args()

    config = read_json(args.config)
    result = run_selector_analysis(config, num_cases=args.num_cases)
    write_json(args.out, result)


if __name__ == "__main__":
    main()
