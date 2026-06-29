#!/usr/bin/env bash
set -euo pipefail

CONFIG="${1:-configs/default.json}"
OUT_DIR="${2:-output}"

python experiments/run_all.py --config "$CONFIG" --out-dir "$OUT_DIR"
