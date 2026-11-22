# Operations

## Requirements

- Python 3.10+ (standard library only)
- Optional: a judge endpoint and one or two delegated model profiles
- Linux, macOS or Windows; the inspector assumes a local loopback browser

## Install into a profile

```bash
python3 install.py --profile ~/.hermes/profiles/myagent
```

It copies the package into `<profile>/pii/`, creates `desens_key.bin` (0600) if
absent, writes `config.json` if absent, then runs every suite and refuses to
report success on failure. The key is never copied between profiles.

## Configure

`config.example.json` is the template.

```json
{
  "threshold": 4.221,
  "judge": {"backend": "openjev", "url": "http://127.0.0.1:8791", "timeout": 300},
  "generator": {"backend": "hermes-profile", "profile": "desens-local"},
  "lanes": {
    "local":    {"backend": "hermes-subagent", "profile": "desens-local"},
    "frontier": {"backend": "hermes-subagent", "profile": "desens-frontier"}
  }
}
```

- `threshold` is on the **normalised 1–10 level**, never the judge's raw index.
- `null`/absent threshold means `route()` returns `unrouted`.
- A lane whose profile directory does not exist is unavailable; the frontier lane
  then reports `FRONTIER_UNCONFIGURED` and **does not** fall back to local.

## Create the two lanes

```bash
hermes profile create desens-local    --clone-from <local-profile>
hermes profile create desens-frontier --clone-from <frontier-profile>
```

Both profiles must have file and terminal toolsets, or the model will paste code
instead of writing an artifact:

```bash
hermes -p desens-frontier config set 'toolsets' \
  '["hermes-cli","web","terminal","file","todo"]'
```

Verify each lane with a real write:

```bash
mkdir -p /tmp/lane && cd /tmp/lane
hermes -p desens-frontier chat -q \
  "Write a Python file answer.py containing def reverse(s): return s[::-1]. Do not explain."
ls -l answer.py
```

A run whose footer says `(1 user, 0 tool calls)` did not write a file.

## Calibrate before routing

```bash
python3 calibration.py            # 12 tasks x 3 runs, censored tasking
```

Writes `calibration.json` and `calibration.md`. A threshold is honoured only if
the file says `"calibrated": true` and the separation beats the declared noise
rule. Otherwise `route()` stays `unrouted`.

The corpus is censored on purpose: the router scores censored text. A bare
calibration measures a different distribution.

## Run

```bash
python3 verify.py                  # offline controls
python3 verify.py --live           # + one real judge/generator run
python3 live_integration.py --tasks trivial,medium,hard
python3 ui_server.py --port 8788   # inspector
```

Logs land in `runs/run-<id>.jsonl`; one record per stage plus heartbeats. The
inspector also keeps the last 20 runs in memory for SSE replay.

## Read a run

```bash
jq -r 'select(.event=="classified") | [.stage,.label,.why] | @tsv' runs/run-*.jsonl
jq -r 'select(.event=="heartbeat") | .stage' runs/run-*.jsonl | sort | uniq -c
```

A run is healthy when:

- every artifact case has a class from the taxonomy;
- heartbeats exist for every long stage (≤ 5 s apart);
- `censor` reports no leaks;
- `restore` reports `unknown == 0`;
- a frontier-routed case records `lane == "frontier"`.

## Troubleshooting

| symptom | cause | fix |
|---|---|---|
| `key not found` | profile has no `desens_key.bin` | run `install.py` for that profile; never copy a key between profiles |
| `unrouted` on every case | threshold missing or calibration not proven | run `calibration.py`, check `calibration.json` |
| `FRONTIER_UNCONFIGURED` | route chose frontier, lane profile missing | create the profile or lower the threshold; do not add a fallback |
| generator writes nothing | profile lacks `file`/`terminal` toolsets, or answered in prose | check `tool calls` in the transcript; prose is delivered as `DELIVERED_TEXT` |
| `GENERATOR_WEDGED` | probe returned empty | restart the server; a compute loop that ignores SIGTERM needs SIGKILL |
| judge slow (minutes) | CPU judge, prompt length dominates | check thread count and prompt size before blaming the model |
| UI unreachable | server bound but page JS error | check the browser console; `curl /api/health` separates server from page |
| token glued to a digit | a detector span ended inside another number | fix the span, not the token grammar; see `docs/detectors.md` |

## Recovery of a wedged model server

```bash
# send SIGTERM, confirm the pid is gone, then SIGKILL
pgrep -f 'llama-server.*<port>'
kill <pid>; sleep 5
kill -9 <pid> 2>/dev/null
# relaunch via your supervisor
```

Do not trust `/health` 200. Use a completion probe with a small `max_tokens`.

## Updating

```bash
python3 verify.py
python3 install.py --profile <profile>
```

`install.py` skips files that are not newer, and never overwrites an existing key
or config.
