import argparse

import _bootstrap  # noqa: F401

from crr_agent.controlled_experiments import run_tamper_fault_injection
from crr_agent.io import read_json, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Run controlled tamper and fault injection experiments.")
    parser.add_argument("--config", default="configs/default.json")
    parser.add_argument("--out", default="outputs/tables/tamper_fault_summary.json")
    parser.add_argument("--cases-per-tamper", type=int, default=200)
    args = parser.parse_args()

    config = read_json(args.config)
    result = run_tamper_fault_injection(config, cases_per_tamper=args.cases_per_tamper)
    write_json(args.out, result)


if __name__ == "__main__":
    main()
