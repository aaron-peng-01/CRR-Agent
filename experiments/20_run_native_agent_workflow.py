import argparse

import _bootstrap  # noqa: F401

from crr_agent.controlled_experiments import run_native_agent_workflow
from crr_agent.io import read_json, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Run controlled native Web-agent workflow experiments.")
    parser.add_argument("--config", default="configs/default.json")
    parser.add_argument("--out", default="outputs/tables/native_agent_workflow_summary.json")
    parser.add_argument("--cases-per-scenario", type=int, default=250)
    args = parser.parse_args()

    config = read_json(args.config)
    result = run_native_agent_workflow(config, cases_per_scenario=args.cases_per_scenario)
    write_json(args.out, result)


if __name__ == "__main__":
    main()
