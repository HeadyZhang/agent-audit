# Reproducing F1 (v0.19.0) — raw + adjusted derivation

> **RETRACTION NOTE (2026-05):** Earlier versions of public docs reported an adjusted F1 of 0.842 (raw FPs from post-v0.16 rules not yet in ground truth were excluded). To keep all headline figures directly reproducible from the included script, public docs now report the raw F1 (0.778). The adjusted figure will be revisited when GT v2.3 lands (planned June 2026). This document retains the full derivation for transparency.

## TL;DR

The current **headline F1 = 0.778** (raw, reproducible) used in `README.md`, `README_CN.md`, `COMPETITIVE-COMPARISON.md`, `BENCHMARK-RESULTS.md`, `CLAUDE.md`, and `docs/index.html` is produced directly by **`tests/benchmark/precision_recall.py`** against the ground-truth file **`tests/ground_truth/labeled_samples.yaml`** (v2.2, 2026-02-04). The historical adjusted F1 of 0.842 — derived post-hoc by excluding FPs from rules added after v0.16 — is documented below for full transparency but is no longer cited as a headline figure.

## Test set

| Field | Value |
|---|---|
| GT file | `agent-security-suite/tests/ground_truth/labeled_samples.yaml` |
| GT version | v2.2 (2026-02-04) |
| Sample files | **81** |
| Total labels | 238 (236 positive, 2 negative; 12 of the 81 files are safe-files with no vulns) |
| Header reports | `total_vulnerabilities: 218` (drift from on-disk count) |
| Fixtures scanned | `agent-security-suite/tests/fixtures/` |

## Reproduce

```bash
cd agent-security-suite
python3 tests/benchmark/precision_recall.py --output-json /tmp/pr.json
```

The script runs `agent-audit scan tests/fixtures --format json`, parses findings, and matches them to GT keys `(file, line, rule_id)` with a 3-line tolerance.

### Raw output reproduced on 2026-05-31 (agent-audit 0.19.0)

```
True Positives:  195
False Positives: 70
False Negatives: 41
Precision: 73.58%   Recall: 82.63%   F1: 77.84%   FP Rate: 26.42%
```

Raw F1 **0.7784** matches the documented **0.778** exactly.

## How "0.842" is derived (adjustment)

`precision_recall.py` does **not** compute the adjusted figure itself. The adjustment described in the READMEs — "excludes findings from 18 new rules added since v0.16 that have not yet been labeled in GT" — is applied post-hoc by subtracting FPs whose `rule_id` is one of the rule ranges added after v0.16 (AGENT-053+ and AGENT-058–064, 110–119).

### Reproduction of the adjustment

From the 70 FPs in the raw run, 40 originate from new-rule IDs not yet present in GT:

| Cutoff | FPs excluded | TP | FP (adj) | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| ≥ AGENT-053 | 40 | 195 | 30 | 41 | 86.67% | 82.63% | **0.846** |
| ≥ AGENT-054 | 37 | 195 | 33 | 41 | 85.53% | 82.63% | **0.840** |

The documented **P 85.9% / R 82.6% / F1 0.842** falls between these two — matching when the cutoff includes AGENT-054+ plus most AGENT-053 findings (or with one extra label refresh). Reproducible within rounding.

## FP breakdown (raw run, 2026-05-31)

| Rule | FPs | Status |
|---|---|---|
| AGENT-034 | 8 | pre-v0.16 (legitimate) |
| AGENT-047 | 6 | pre-v0.16 |
| AGENT-116 | 6 | new (no GT labels) |
| AGENT-004 | 5 | pre-v0.16 |
| AGENT-001 | 4 | pre-v0.16 |
| AGENT-059 | 4 | new |
| AGENT-114 | 4 | new |
| AGENT-026 | 4 | pre-v0.16 |
| AGENT-028 | 2 | pre-v0.16 |
| AGENT-043 | 1 | pre-v0.16 |
| All AGENT-053–064, 110–119 | 40 total | new — drive the raw→adjusted gap |

## Bottom line

- **Raw F1 0.778**: fully reproducible, run the script.
- **Adjusted F1 0.842**: reproducible within ±0.004 by subtracting the 37–40 FPs from rules added after v0.16. Will converge with raw once GT v2.3 refreshes labels for AGENT-053+ (planned June 2026; see comment at `precision_recall.py:483`).
- The CI gate inside `precision_recall.py` is set at `f1 < 0.75` (line 485) — passes today, raises to 0.84 once GT refresh lands.
