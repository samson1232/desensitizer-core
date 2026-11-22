# desensitizer-core

[![verify](https://github.com/samson1232/desensitizer-core/actions/workflows/verify.yml/badge.svg)](https://github.com/samson1232/desensitizer-core/actions/workflows/verify.yml)

A fail-closed PII pipeline for text that leaves your machine: censors prompts and
artifacts, restores them exactly at the boundary, routes work by a calibrated
score, and logs enough to prove what happened — without ever writing a real value
to disk.

No third-party dependencies. Python 3.10+.

```
prompt ──► censor ──► judge ──► route ──► lane ──► restore ──► verify
             │                   │          │
             │                   │          ├─ local    (small model)
             │                   │          └─ frontier (delegated subagent)
             │                   └─ local | frontier | unrouted
             └─ tokens, never values
```

## Why this exists

Most redaction tools fail in ways that look like success:

- a truncated model artifact still compiles, so the pipeline reports success;
- `/health` returns 200 while the model server is wedged;
- a six-minute run prints nothing, so "hung" and "slow" are indistinguishable;
- a router whose noise equals its signal still picks a side.

This project treats each of those as a bug with a control that fails without
the fix. Every run is classified, logged, and either delivered or refused.

## Quick start

```bash
git clone <this repo> desensitizer-core
cd desensitizer-core

# 1. prove the package before trusting it (offline, no model needed)
python3 verify.py             # 338 checks

# 2. local inspector
python3 ui_server.py          # http://127.0.0.1:8788
```

`verify.py --live` adds one real judge + generator run; it needs services on
`:8791` and a configured generator lane.

The UI has three modes:

| mode | what runs | cost |
|---|---|---|
| dry | censor + entity table only | instant, no network |
| judge | + difficulty score + route | one judge call |
| live | + generation, gate, restore, compile | model latency |

## What "censored" means here

Two reversible schemes, because they have different threat models:

| | Layer 1 — outbound scrub | Layer 2 — artifact aliases |
|---|---|---|
| entry | `Pipeline.scrub(text)` | `Pipeline.alias(text)` |
| token | `<kind>:<26 × base32>` (HMAC) | `person_ID_1` (readable) |
| reversible by | in-session token space | per-scope dict |
| purpose | unlinkable on the wire | a human can read the artifact |

`restore()` reverses both in one pass. Unknown tokens and aliases are left
untouched and reported — never guessed.

### Detected kinds

Names (roster or context-bound), emails, phones, postal addresses (US/UK/SG),
employee IDs, SSNs (full and labelled last-4), usernames, IPs (v4/v6), MACs,
UUIDs, hostnames/FQDNs, IBANs, cards, money, postcodes, UTRs, dates of birth,
API secrets, AWS keys, URI credentials, SSH fingerprints.

Full table, examples and known limits: [`docs/detectors.md`](docs/detectors.md).

### What is deliberately not detected

- A bare person name with no roster entry and no role context. Regex cannot do
  this safely; use the roster or declare the literal.
- Free-text addresses outside the recognised shapes. Declare them explicitly.
- Lowercase hostnames with fewer than two digits (`db2`). Seed them.

Every one of those is a documented contract, not a silent gap. The pipeline
fails closed if a detector stops firing: `CensorPass.self_test()` runs canaries
before every prompt.

## Routing and lanes

A judge returns a normalised difficulty level (1–10). A pure function decides:

```
level >= threshold  -> frontier
level <  threshold  -> local
no calibrated threshold -> unrouted (no lane, no artifact)
```

Lanes are delegated Hermes subagents, one profile each. The route chooses the
lane; the model never chooses its own. **A missing frontier lane is
`FRONTIER_UNCONFIGURED`, never a silent fallback to local** — that fallback turns
a routing decision into a false claim.

Calibration is evidence, not a number carried on faith: 12 tasks × 3 runs through
the censored pipeline. If separation does not beat noise, the router returns
`unrouted`. See [`docs/operations.md`](docs/operations.md).

## Failure classes

Every artifact run ends in exactly one of:

`OK` · `TRUNCATED` · `EMPTY` · `COMPILE_ERROR` · `EXEC_FAIL` · `CENSOR_BLOCKED`
· `JUDGE_UNAVAILABLE` · `GENERATOR_WEDGED` · `NO_ARTIFACT` · `ROUTE_UNSET`

Plus two explicit non-artifact outcomes in the inspector: `CENSORED_ONLY` and
`DELIVERED_TEXT` (a prose answer is a deliverable, not a failed artifact).

Each class has a synthetic control in `tests/test_classify.py`. A classifier
never shown to emit `TRUNCATED` is not a classifier.

## Observability

Every run writes one append-only JSONL file:

```json
{"ts":"...","run_id":"r01","stage":"judge","event":"heartbeat","stage_elapsed_s":25.0,"bytes":0}
```

- stage records for `preflight`, `censor`, `judge`, `route`, `generate`,
  `restore`, `verify`, `done`
- a heartbeat at least every 5 s while a stage is in flight
- counts, timings, classes and short enums only — never prompts, previews or values
- a killed run's last record names the stage it died in

Controls: a SIGKILL test, a heartbeat-gap test, and a planted-PII scan over the
log. See [`docs/architecture.md`](docs/architecture.md).

## Security model

- Censoring is unconditional. There is no bypass flag; `CensorFailure` blocks.
- The key is per installation (`desens_key.bin`, 0600) and never bundled.
- The pivot table (alias → value) stays in process memory. `close()` clears it.
- The UI binds `127.0.0.1`, requires JSON + matching `Origin` on POST, ships a
  strict CSP, and serves reveal only for one token of one run.
- Restore is single-pass, scope-bound, and only for artifacts returning to the
  originating task.

Read [`SECURITY.md`](SECURITY.md) before deploying. The tool reduces exposure; it
does not make an untrusted model trustworthy.

## Repository layout

```
pipeline.py        facade: scrub, alias, restore, route, audit
censor_pass.py     outbound pass: canaries, residual check, detector pre-pass
engine/            key handling, ScrubGate, HMAC TokenSpace
alias_bridge.py    readable, scoped artifact aliases
backends.py        judge/generator contracts + subagent adapters
lanes.py           two-lane dispatch, no cross-lane fallback
runlog.py          per-run JSONL with heartbeats and redaction
classify.py        10 failure classes with evidence
completeness.py    truncation gate (boundary, symbol, finish_reason, budget)
calibration.py     12×3 corpus, separation vs noise
verify.py          one command, all controls
ui_server.py, ui/  local prompt-flow inspector
tests/             338 offline checks
agentworld/        synthetic site corpus used by the demo/tests
```

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — data flow, invariants, failure handling
- [`docs/detectors.md`](docs/detectors.md) — every kind, pattern, and known limit
- [`docs/operations.md`](docs/operations.md) — install, config, calibration, troubleshooting
- [`docs/reliability.md`](docs/reliability.md) — measured evidence and what remains unverified
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — tests-first rules for changes
- [`CHANGELOG.md`](CHANGELOG.md) — version history

## Testing

```bash
python3 verify.py            # offline: 338 checks, no model
python3 verify.py --live     # + one real judge/generator run
python3 tests/test_ui.py     # inspector controls only
```

The suite is stdlib-only and starts real local servers on ephemeral ports. No
test is skipped. Controls are written so that deleting a guard fails the suite
and names it.

## License

MIT. See [`LICENSE`](LICENSE).
