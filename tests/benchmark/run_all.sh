#!/bin/bash
# Run full benchmark suite locally (Layer 1 + Agent-Vuln-Bench + quality gate)
set -e

echo "============================================"
echo "  agent-audit Benchmark Suite"
echo "============================================"
echo ""

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$ROOT/results}"
mkdir -p "$RESULTS_DIR"

# Layer 1
echo ">>> [1/3] Running Layer 1: Precision & Recall..."
python "$ROOT/tests/benchmark/precision_recall.py" \
    --fixtures "$ROOT/tests/fixtures" \
    --ground-truth "$ROOT/tests/ground_truth/labeled_samples.yaml" \
    --output-json "$RESULTS_DIR/layer1.json" \
    2>&1 | tail -10
echo ""

# Agent-Vuln-Bench
echo ">>> [2/3] Running Agent-Vuln-Bench..."
python "$ROOT/tests/benchmark/agent-vuln-bench/harness/run_eval.py" \
    --tool agent-audit \
    --dataset all \
    --output "$RESULTS_DIR/avb_results.json" \
    --report "$RESULTS_DIR/avb_report.md" \
    2>&1 | tail -15
echo ""

# Quality Gate
echo ">>> [3/3] Running Quality Gate Check..."
python "$ROOT/tests/benchmark/quality_gate_check.py" \
    --config "$ROOT/tests/benchmark/quality_gates_v2.yaml" \
    --results "$RESULTS_DIR"
GATE_EXIT=$?
echo ""
echo "============================================"
echo "  Reports: $RESULTS_DIR/"
echo "============================================"
exit $GATE_EXIT
