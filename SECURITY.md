# Security policy

## Reporting

Report vulnerabilities through **GitHub private vulnerability reporting**
(Security → Advisories → Report a vulnerability). Do not open a public issue for
a bypass, a leak, or a key-handling flaw.

Include: the version, the detector or stage, the input shape (not a real secret),
and the observed output. Never include a live credential.

## Supported versions

The latest release on `main` is supported. Older tags are not patched.

## Threat model

### In scope

- **Outbound prompt text** bound for a local or remote model.
- **Artifacts** returning from a model that must be restored to real values.
- **Accidental disclosure through logs**, run records, audits or the inspector.
- **Fail-open behaviour**: a dead detector, an unavailable judge, a wedged
  generator, a missing lane.

### Out of scope

- A compromised host, keylogger, or root attacker. The key must be readable by
  the process; a root attacker can read it.
- A model that memorises and later repeats a value it was never given.
- Side channels in timing or token counts (token width is fixed to reduce this,
  but it is not a proof).
- Availability of third-party model servers.
- Data at rest outside this package (databases, backups, chat history).

## Guarantees, and their limits

1. **Censoring is unconditional.** There is no bypass flag, environment variable
   or "safe mode". `CensorFailure` blocks the payload.
2. **A dead detector cannot certify clean.** Canaries run before every prompt and
   every file. If a pattern stops firing, the pass raises.
3. **Residual identifiers block.** After substitution the pass re-scans the
   output; a recognised value still visible is a refusal, not a warning.
4. **The pivot table never leaves the process.** It is not written to disk, not
   logged, and cleared by `close()`.
5. **Restore is strict and scoped.** Unknown aliases are left untouched and
   reported; one scope cannot resolve another's aliases.
6. **The inspector is local.** It binds `127.0.0.1`, requires JSON and a matching
   `Origin`, ships a strict CSP, and serves cleartext only through an explicit
   per-run reveal.

### What it cannot guarantee

- That every PII value is detected. Detection is shape-based plus roster/declared
  literals. A bare name with no roster and a free-text address with no recognised
  shape will pass. See `docs/detectors.md`.
- That a model will not infer a value from context.
- That a restored artifact is semantically correct. Restoration can produce code
  that runs but is wrong; the completeness gate checks structure, not meaning.
- That a test key in a fixture is not a real key. Fixtures in this repository are
  synthetic; do not paste real credentials into examples.

## Key handling

- One 32-byte key per installation, at `<profile>/desens_key.bin`, mode 0600.
- Never bundled in a release, never copied between profiles, never committed.
- Losing the key makes prior tokens unlinkable; that is the intended trade-off.
- Rotating the key invalidates existing token mappings. Finish or discard
  in-flight work first.

## Logging

Run logs contain stage names, counts, timings, classes, and short enums. They
must never contain prompts, previews, transcripts, or values. The logger refuses
whole-document keys by name and redacts PII shapes in strings. The inspector's
raw-event view omits preview fields.

Audit files contain aliases and counts, never values.

## Inspector exposure

- Default bind `127.0.0.1`. A non-loopback bind requires `--allow-remote` and is
  not recommended; there is no authentication layer.
- `POST` requires `Content-Type: application/json` and, when an `Origin` header is
  present, an exact match. Cross-origin requests are refused.
- Cleartext reveal is an explicit request for one token of one run, answered from
  process memory.
- Temp profiles and artifacts are deleted when a run ends.

Treat the inspector as a single-operator local tool, not a shared service.

## Dependencies

The package uses the Python standard library only. That is a deliberate reduction
in supply-chain surface; keep it that way unless there is a strong reason.
