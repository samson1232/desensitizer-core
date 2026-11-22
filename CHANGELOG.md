# Changelog

All notable changes to this project. The format follows Keep a Changelog; versions
use semantic versioning.

## [1.6.4] — 2026-11-22

### Added

- `host_labeled` and `host_upper` detectors for `Hostname: DESKTOP-9941A` and the
  unlabelled uppercase form, with an identifier denylist.
- `ipv6` detector for full, `::`-compressed and loopback forms; clock times and
  ISO timestamps are explicitly preserved.
- Singapore address detector (`address_sg`): `Blk` prefixes, `#NN-NN` units,
  building names before or after the unit, mandatory `Singapore NNNNNN`.

### Changed

- Routing threshold in `config.json` raised to 5.2 as a manual override to exercise
  the local lane. The calibrated value remains 4.221 in `calibration.json`.

## [1.6.3] — 2026-11-22

### Changed

- Threshold override to 5.2 (config only).
- Verification totals after the PII pre-pass: 330 checks.

## [1.6.2] — 2026-11-22

### Added

- `address_sg` Singapore address shapes.
- Threshold override to 4.5 for local-lane testing.

## [1.6.1] — 2026-11-22

### Added

- PII pre-pass claiming whole structured spans: context-bound names, US/UK
  addresses, employee IDs, SSNs (full and labelled last-4), usernames, API/AWS
  secrets, SSH fingerprints, URI credentials, whole UUIDs.
- `docs/detectors.md`-style canaries for every new kind.

### Fixed

- A UUID could be fragmented into `550e8400-<host token><phone token>`.
- A database URI could leave its password cleartext after a partial match.
- Hostnames such as `DESKTOP-9941A` and IPv6 addresses were not detected.

## [1.6.0] — 2026-11-22

### Added

- Two-lane dispatch: `local` and `frontier` delegated subagent profiles, chosen by
  the route. A missing frontier lane is `FRONTIER_UNCONFIGURED`, never a local
  fallback.
- `SubagentGenerator` probes the selected profile, not a shared API port.
- Inspector records `lane`, backend and profile on every attempt.

### Fixed

- `route: frontier` no longer silently generates on the local lane.
- Prose answers are delivered as `DELIVERED_TEXT` instead of being discarded as
  `EMPTY`; restore and verify are skipped with an explanation.
- Model transcript tail is captured (8 000 chars) and rendered in the UI.

## [1.5.1] — 2026-11-22

### Fixed

- Censor events serialised raw detector matches (`kinds`) into the browser stream.
  Now counts only; `preview_in` removed; the logger refuses `kinds`/`names`.
- `host_bare` over-matched ordinary words with one digit (`last-4`, `ssw0rd`,
  `ED25519`, `sha256`, `us-west-2`). Now lowercase, two digits minimum, with a
  technical-token denylist.
- Live mode probes the generator before generating; attempts carry `rc` and a
  transcript tail.

## [1.5.0] — 2026-11-22

### Added

- Local prompt-flow inspector (`ui_server.py`, `ui/`): SSE stage events, entity
  table, explicit per-run reveal, strict CSP, loopback-only bind.
- Dry, judge and live modes.

## [1.4.0] — 2026-11-22

### Added

- `runlog.py`: per-run JSONL, 5 s heartbeats, redaction, kill survival.
- `classify.py`: ten failure classes with evidence and precedence.
- `completeness.py`: truncation gate (boundary, symbol, finish reason, budget).
- `calibration.py`: 12 tasks × 3 runs on censored tasking.
- Preflight with real completion probes; wedge verdict and recovery command.
- `route()` returns `unrouted` unless a calibration proves separation.

### Changed

- A threshold is honoured only when `calibrated: true` and the noise rule passes.

## [1.3.0] — 2026-11-21

### Added

- Handoff package, single-command verification, install refusal on failed controls.
- 91 offline checks.

## [1.2.0] — 2026-11-21

### Fixed

- Detectors no longer re-tokenise their own tokens (`name:iban:XXXX`).
- Filenames (`answer.py`, `notes.md`) are excluded from FQDN detection.
- `censor_prompt()` runs detector canaries before every prompt.

## [1.1.0] — 2026-11-21

### Added

- Reversible artifact aliasing with per-scope isolation and strict restore.

## [1.0.0] — 2026-11-21

### Added

- Initial pipeline: HMAC token scrubbing, alias bridge, pure routing, audit log.
