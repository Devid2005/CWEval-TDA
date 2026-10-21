#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON_BIN="${PYTHON_BIN:-python}"
MODEL_PATH="${MODEL_PATH:-$HOME/models/codebert-base}"
DEVICE="${DEVICE:-auto}"

"$PYTHON_BIN" tda_statistical_experiment/run_experiment.py \
  --stage pilot \
  --model-path "$MODEL_PATH" \
  --device "$DEVICE"
