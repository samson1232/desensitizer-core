# Contributing

Two rules matter more than style here.

## 1. Every gate ships with a control that fails without it

A test that passes on a broken gate is worse than no test. For each guard, add a
synthetic case that must produce the failure, plus a positive control that must
pass. Examples already in the suite:

- truncation: 20/20 `TRUNCATED`, and a correct artifact 20/20 accepted;
- dead detector: disarm `PATTERNS` and assert `CensorFailure`;
- wedge: a server that answers `/health` 200 and never completes → refused;
- router: a threshold with ratio 2.9 must be ignored;
- UI leak: planted values must not appear in events or logs.

Run `python3 verify.py` before opening a PR. Deleting any guard must make it exit
non-zero and name the suite.

## 2. Censoring has no bypass

Do not add an environment flag, a "trusted caller" path, or a warning-only mode
for `CensorFailure`. If a payload cannot be proven clean, the answer is refusal.

## Adding a detector

1. Put the pattern in `PRE_PATTERNS` if it must win over generic rules, otherwise
   `PATTERNS`.
2. Add a canary in `CensorPass.CANARIES`.
3. Add a control in `tests/test_pii_coverage.py` asserting:
   - the value is gone;
   - the kind is reported;
   - `restore(scrub(x)) == x`;
   - a benign neighbour survives (false-positive control).
4. Never leave a token glued to a word character; the token grammar requires a
   boundary on both sides.
5. Never let one pattern's tail swallow the next field. Prefer structured
   components over `.*`.

## Code style

- Python 3.10+, standard library only.
- No new runtime dependencies without a written justification in the PR.
- Keep modules small and single-purpose. `pipeline.py` is a facade; policy lives
  in the module that owns the invariant.
- Comments explain *why*, especially when the choice prevents a measured failure.
- Logs: numbers, counts, enums. No prompts, previews, transcripts, or values.

## Tests

```bash
python3 verify.py
python3 verify.py --live      # requires local judge/generator; not needed for most PRs
```

CI runs the offline suite on Python 3.10–3.12. Any test that needs a model must be
skipped by default and documented as such; the offline suite must stay runnable on
a laptop with no services.

## Commits and PRs

- Conventional Commits: `fix(detectors): …`, `feat(ui): …`, `docs: …`.
- One concern per PR. A detector change and a UI change belong in separate PRs.
- State what was measured, on what corpus, and what remains unverified.

## Security issues

Do not open a public issue. See `SECURITY.md`.
