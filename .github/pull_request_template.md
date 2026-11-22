## What changed

<!-- one paragraph; say which invariant or failure class it touches -->

## Evidence

```
python3 verify.py
```

<!-- paste the PASS/FAIL summary, not the whole log -->

## Controls

- [ ] Every new gate has a control that fails without it
- [ ] Positive control passes (the gate does not reject good input)
- [ ] No test was skipped or weakened
- [ ] No real PII or credentials in fixtures

## Docs

- [ ] README / docs updated if behaviour or limits changed
- [ ] CHANGELOG entry added for a user-visible change
