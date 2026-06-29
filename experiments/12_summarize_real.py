from __future__ import annotations

import argparse
import json

import _bootstrap  # noqa: F401

from crr_agent.real_experiment import summarize_real_output


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate real-data per-case outputs.")
    parser.add_argument("--inputs", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(summarize_real_output(args.inputs, args.output), indent=2))


if __name__ == "__main__":
    main()
