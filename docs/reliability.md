# Reliability evidence

Measured on one host, 2026-11-22. The numbers below come from files the pipeline
wrote, not from a console summary. They describe **this** deployment and corpus;
they are not a benchmark of any model.

## Before and after

```
baseline                        final
91 offline checks, 0 fail       338 checks, 0 fail
live 3/3 censored               20 completed runs, 60 cases
     3/3 compiled               56 OK · 1 TRUNCATED · 1 EXEC_FAIL
     3/3 executed               2 GENERATOR_WEDGED · 0 unclassified
frontier 0/3                    frontier 0/60 at the calibrated 4.221
no per-run log                  every run: JSONL + heartbeats + class
```

## Failure classes over 60 live cases

| class | count |
|---|---|
| OK | 56 |
| TRUNCATED | 1 |
| EXEC_FAIL | 1 |
| GENERATOR_WEDGED | 2 |
| EMPTY / COMPILE_ERROR / CENSOR_BLOCKED / JUDGE_UNAVAILABLE / NO_ARTIFACT / ROUTE_UNSET | 0 |
| **unclassified** | **0** |

Plus one run-level `GENERATOR_WEDGED` refusal before any case ran: `/health`
returned 200, two completion probes failed, no rates were reported.

## The five original failures

| failure | outcome | evidence |
|---|---|---|
| **F1** silent truncation | fixed | completeness gate; synthetic 20/20 `TRUNCATED`, correct artifact 20/20 accepted. In the wild: a 35-byte stub was rejected and retried to 532 bytes; another run reported `TRUNCATED` after one retry instead of looping |
| **F2** no observability | fixed | 21 run logs, minimum 50 heartbeats/run, maximum gap 5.0 s, 0 records containing a planted value; SIGKILL leaves the stage named |
| **F3** liveness lies | mitigated | real completion probes, wedge verdict, preflight refusal. A live run refused a wedged server. Still external: a supervisor restarted the model three times mid-series, killing long single-slot generations |
| **F4** router cannot discriminate | honest, marginal | 12 tasks × 3 runs on censored tasking: separation 1.067 against a declared 1.0 floor, within-task SD 0 → threshold 4.221. Frontier fired 0/60. Reported, not hidden |
| **F5** raw API emits nothing | documented | only the profile transport produces content under the measured server flags; the API adapter now asserts non-empty content instead of calling a zero-content response live |

## Calibration

```
easy group mean 3.688   hard group mean 4.755   separation 1.067
within-task SD 0.000 (deterministic for identical input)
threshold 4.221 (group midpoint, calibrated: true)
```

The ratio rule degenerates when the judge is deterministic, so the calibration
falls back to a declared practical floor of 1.0 level. 1.067 is only 6.7% above
it: **marginal**. A bare-tasking calibration measured 1.258 separation and is kept
as `calibration.bare.*` for comparison; it is not used, because the router scores
censored text.

## What remains unverified

- Judge noise across keys/installs. Within one fixed corpus/key the judge is
  deterministic; the previously observed ~0.2 swing was not reproduced and is not
  explained here.
- Separation 1.067 against the 1.0 floor. Any unmeasured cross-session noise would
  invalidate the threshold.
- Frontier 0/60 at 4.221. The threshold was never crossed on the live trio. A
  manual override (5.2) is used in `config.json` to exercise the local lane; it is
  not a calibration result.
- 1 TRUNCATED and 1 EXEC_FAIL in 60 is small-n. Causes are recorded per run;
  nothing was retried to improve a rate.
- The supervisor interaction above is a separate system and was not modified.
- The ETB benchmark lane referenced by earlier internal work is out of scope here.

## How to reproduce

```bash
python3 verify.py                 # all offline controls
python3 calibration.py            # 12 x 3 judge calls
python3 verify.py --live          # one full live run
```

Artifacts from the measured series are not shipped in this repository. The tests
that produced each claim are: `test_completeness.py`, `test_runlog.py`,
`test_classify.py`, `test_liveness.py`, `test_router.py`, `test_pii_coverage.py`.
