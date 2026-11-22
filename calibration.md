# Router calibration

Measured: 2026-11-22T01:35:05  ·  runs per task: 3  ·  corpus: censored, planted PII
Verdict: **CALIBRATED** — within-task SD 0 (deterministic for identical input); separation 1.067 >= practical floor 1.0

| task | group | run 1 | run 2 | run 3 | mean | SD |
|---|---|---|---|---|---|---|
| easy-01 | easy | 3.780 | 3.780 | 3.780 | 3.78 | 0.0 |
| easy-02 | easy | 3.802 | 3.802 | 3.802 | 3.802 | 0.0 |
| easy-03 | easy | 3.530 | 3.530 | 3.530 | 3.53 | 0.0 |
| easy-04 | easy | 3.638 | 3.638 | 3.638 | 3.638 | 0.0 |
| med-01 | medium | 3.927 | 3.927 | 3.927 | 3.927 | 0.0 |
| med-02 | medium | 4.559 | 4.559 | 4.559 | 4.559 | 0.0 |
| med-03 | medium | 4.546 | 4.546 | 4.546 | 4.546 | 0.0 |
| med-04 | medium | 4.702 | 4.702 | 4.702 | 4.702 | 0.0 |
| hard-01 | hard | 4.350 | 4.350 | 4.350 | 4.35 | 0.0 |
| hard-02 | hard | 4.580 | 4.580 | 4.580 | 4.58 | 0.0 |
| hard-03 | hard | 5.036 | 5.036 | 5.036 | 5.036 | 0.0 |
| hard-04 | hard | 5.054 | 5.054 | 5.054 | 5.054 | 0.0 |

Easy group mean: 3.688  ·  Hard group mean: 4.755
Separation: 1.067  ·  pooled within-task SD: 0.0  ·  ratio: None

Threshold: **4.221** (midpoint, justified)

A passing argument is separation >= 3x noise. Below that the numbers are reported and no side is picked.
