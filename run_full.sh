#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <pilot_run_directory>" >&2
  echo "Example: $0 tda_statistical_experiment/runs/run_20261006_220000" >&2
  exit 2
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
PYTHON_BIN="${PYTHON_BIN:-python}"

"$PYTHON_BIN" tda_statistical_experiment/run_experiment.py \
  --stage analyze \
  --run-dir "$1"
