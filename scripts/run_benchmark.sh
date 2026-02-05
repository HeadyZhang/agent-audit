#!/bin/bash
# Run complete benchmark suite locally
# Usage: ./scripts/run_benchmark.sh

set -e

cd "$(dirname "$0")/.."

echo "=== Agent-Audit Benchmark Suite ==="
echo ""

# Step 1: Run precision/recall
echo "Running Precision/Recall Evaluation..."
python3 tests/benchmark/precision_recall.py --verbose --output-json /tmp/benchmark-pr.json

# Step 2: Run ATLAS coverage
echo ""
echo "Running MITRE ATLAS Coverage..."
python3 tests/benchmark/atlas_report.py

# Step 3: Run performance test (if exists)
if [ -f "tests/benchmark/performance_test.py" ]; then
    echo ""
    echo "Running Performance Tests..."
    cd packages/audit
    poetry run pytest ../../tests/benchmark/performance_test.py -v --tb=short || true
    cd ../..
fi

# Step 4: Generate summary
echo ""
echo "=== BENCHMARK SUMMARY ==="
python3 << 'EOF'
import json
import yaml
import os

# Load P/R results
with open('/tmp/benchmark-pr.json') as f:
    r = json.load(f)

print(f'Precision: {r["precision"]:.2%}')
print(f'Recall:    {r["recall"]:.2%}')
print(f'F1-Score:  {r["f1_score"]:.2%}')
print(f'TP: {r["true_positives"]} | FP: {r["false_positives"]} | FN: {r["false_negatives"]}')

# Count fixtures
fixture_count = len([f for f in os.popen('find tests/fixtures -name "*.py"').read().split('\n') if f])
print(f'\nFixtures: {fixture_count}')

# Count ATLAS mappings
with open('rules/mappings/mitre_atlas.yaml') as f:
    atlas = yaml.safe_load(f)
atlas_count = len(atlas.get('mappings', {}))
print(f'ATLAS Mappings: {atlas_count}')

# Count ground truth samples
with open('tests/ground_truth/labeled_samples.yaml') as f:
    gt = yaml.safe_load(f)
gt_count = len(gt.get('samples', []))
print(f'Ground Truth Samples: {gt_count}')

# Calculate score
score = 0
if r['precision'] >= 0.90: score += 20
elif r['precision'] >= 0.70: score += 10
if r['recall'] >= 0.85: score += 20
elif r['recall'] >= 0.70: score += 10
if r['f1_score'] >= 0.87: score += 20
elif r['f1_score'] >= 0.70: score += 10

if fixture_count >= 50: score += 20
elif fixture_count >= 30: score += 10

if atlas_count >= 20: score += 10
elif atlas_count >= 10: score += 5

if gt_count >= 30: score += 10
elif gt_count >= 20: score += 5

print(f'\n=== FINAL SCORE: {score}/100 ===')
if score >= 85:
    print('INDUSTRIAL GRADE ACHIEVED')
elif score >= 70:
    print('GOOD PROGRESS - Continue improving')
else:
    print('NEEDS IMPROVEMENT')
EOF

echo ""
echo "Benchmark complete. Results in /tmp/benchmark-pr.json"
