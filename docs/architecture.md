# Architecture

## Data flow

```
                 ┌─────────────────────────── process boundary ───────────────────────────┐
 prompt/artifact │  scrub()                    alias()                    restore()      │
 ────────────────►  detect → tokenise  ──►  readable aliases  ──►  single-pass reverse   │
                 │       │                      │                        │              │
                 │       └── CensorFailure      └── per-scope ledger     └── strict, no  │
                 │           blocks, never          (in memory)              guessing     │
                 │           warns                                                       │
                 └───────────────────────────────────────────────────────────────────────┘
```

Censoring happens before anything crosses the boundary. Restoration happens only
on artifacts returning to the originating task, only for tokens minted in that
scope, and never on outbound text.

## Layers

| module | responsibility | invariant |
|---|---|---|
| `engine/keys.py` | 32-byte per-install key | absent key refuses to run; never mints silently |
| `engine/tokenspace.py` | HMAC tokens | stable in-session, collision-detected, unlinkable across installs |
| `engine/scrub.py` | `ScrubGate` | operator literals win over regex; tokens are never re-scanned |
| `censor_pass.py` | outbound pass | canary self-test per prompt; residual identifiers block |
| `alias_bridge.py` | readable aliases | per-scope, longest-first, never aliases a value to itself |
| `pipeline.py` | facade + route | `route()` is total, deterministic, model-free |
| `lanes.py` | lane dispatch | no frontier → local fallback, ever |
| `completeness.py` | artifact gate | compiling is not completeness |
| `classify.py` | outcome taxonomy | every outcome named, evidence attached |
| `runlog.py` | observability | heartbeat ≤ 5 s; no cleartext writable |

## Censoring order (why it matters)

1. **Pre-pass** (`censor_pass.PRE_PATTERNS`) claims whole structured spans:
   URI credentials, API/AWS secrets, SSH fingerprints, UUIDs, SSNs, employee IDs,
   addresses (US/UK/SG), context-bound names, usernames, labelled/uppercase hosts,
   IPv6.
2. **Gate** (`ScrubGate.scrub`) applies operator-declared literals, then engine
   patterns (email, phone, card, IBAN, IP, postcode, money, UTR, UUID, AWS, bearer).
3. **Names** from the roster, whitespace-tolerant.
4. **Extra patterns** for kinds the engine does not own.

The pre-pass exists because shorter patterns can fragment a longer identifier.
Measured failure: a UUID became `550e8400-<host token><phone token>`, and a DB URI
left its password cleartext after a partial credential match. Both are worse than
a miss because the output *looks* censored.

Every emitted token is `<kind>:<26 base32>`. Later scans run outside those spans,
so a base32 body can never be re-tokenised as an IBAN or card.

## Completeness gate

An artifact is accepted only if **all** hold:

- it parses, and its final logical line ends at a statement boundary;
- the requested symbol exists (when one was requested);
- `finish_reason != "length"`;
- completion tokens are below 98% of the budget (when the backend reports usage).

On `TRUNCATED`: one retry with a larger budget, both attempts recorded. A second
truncation is reported and stops. Compiling is never treated as success.

## Liveness

`/health` is not proof of life. A lane is live only if a real completion returns
non-empty content:

```
probe() → live | empty
health 200 + two empty probes → WEDGED   (refuse, log recovery)
socket refused                → down      (refuse)
```

The subagent probe runs the actual profile (`hermes -p <profile> chat -q`), not a
shared API port. Probing `:8083` for a frontier profile would report the local
model's health and call it live.

## Run log

One JSONL per run:

```
stage_start · progress · heartbeat · stage_end · stage_error · classified
```

Fields: `ts`, `run_id`, `stage`, `event`, `elapsed_s`, `stage_elapsed_s`, `bytes`.
Whole-document keys (`source`, `code`, `prompt`, `transcript`, `tasking`, `pivot`)
are refused by the logger; strings pass a redactor; floats/ints/bools pass through.
A heartbeat thread runs every 5 s while any stage is in flight, so a SIGKILLed run
still names the stage it died in.

## Lanes

```
route local    → local subagent profile
route frontier → frontier subagent profile
route unrouted → no lane (ROUTE_UNSET)
missing lane   → FRONTIER_UNCONFIGURED (no artifact, no fallback)
```

Each `generate()` result carries `lane`, `backend`, `profile`. The terminal event
records the lane, making `route: frontier` with `lane: local` impossible.

## Failure taxonomy

| class | meaning |
|---|---|
| `OK` | complete, compiled, executed (when an execution check exists) |
| `TRUNCATED` | gate rejected: boundary/symbol/finish_reason/budget |
| `EMPTY` | a transport returned zero content |
| `COMPILE_ERROR` | `py_compile` failed |
| `EXEC_FAIL` | assertion/execution failed |
| `CENSOR_BLOCKED` | the censor refused the payload |
| `JUDGE_UNAVAILABLE` | no score, so no route |
| `GENERATOR_WEDGED` | probe or generation timed out / empty |
| `NO_ARTIFACT` | no file and no code (no transport) |
| `ROUTE_UNSET` | a decision was needed and absent |

Precedence is deliberate: censor > judge > wedge > route > artifact presence >
truncation > compile > execute. Truncation outranks compile because a truncated
file can compile.

## Invariants enforced by tests

1. No real value survives `scrub()`.
2. `restore(scrub(x)) == x` byte for byte, including across 25 random keys.
3. Unknown tokens/aliases are untouched and reported.
4. Aliases are scope-bound; two scopes may disagree about `person_ID_1`.
5. `route()` is total; `None`/NaN/non-finite block.
6. A dead detector raises instead of certifying clean.
7. Logs and audits contain counts, aliases, timings — never values.
8. A missing frontier lane cannot silently become a local run.
