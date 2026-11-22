# Detectors

Every kind below is a named detector with a canary in `CensorPass.self_test()`.
If any canary stops firing, the pass refuses to certify anything clean.

## Pre-pass kinds (whole-span, run before the generic gate)

| kind | example | notes |
|---|---|---|
| `person` | `Reporter: Sarah Jenkins` | only with a role/field context (Reporter, SRE, Contact, Submitted By, …). Bare names need the roster. |
| `address` | `742 Evergreen Terrace, Apt 4B, San Francisco, CA 94107` | number + street suffix + structured unit/city/state+ZIP. No free-text tail. |
| `address_sg` | `Blk 35 Mandalay Road, #01-01, Singapore 308215` | Blk prefix, `#NN-NN` units, building names before/after the unit, mandatory `Singapore NNNNNN`. |
| `employee_id` | `EMP-90482`, `STF-9999` | 4–8 digits. |
| `ssn` | `123-45-6789` | full US SSN. |
| `ssn_last4` | `Last 4 SSN: 6789` | labelled form; tolerates parentheses. |
| `username` | `Accepted publickey for mvance`, `sudo: mvance`, `/Users/mvance/` | context-bound; stopwords (`for the`, `for this`, …) excluded. |
| `api_secret` | `sk_test_…`, `pk_live_…`, `rk_test_…` | payment-processor key shapes. |
| `aws_key` | `AKIA…`, `ASIA…` | 20-character access key IDs. |
| `ssh_fingerprint` | `SHA256:nThb…`, `MD5:aa:bb:…` | |
| `uuid` | `550e8400-e29b-41d4-a716-446655440000` | claimed whole; prevents fragmentation. |
| `url_credential` | `postgresql://user:pass@host:5432/db` | the whole URI, password and path included. |
| `credential` | `user:pass@host` | no scheme required. |
| `host_labeled` | `Hostname: DESKTOP-9941A` | Host/Computer/Device/Machine forms. |
| `host_upper` | `DESKTOP-9941A` | uppercase form with 3+ digits after the hyphen; denies INC-/EMP-/STF-/CVE-/RFC-/ISO-/GPT-. |
| `ipv6` | `2001:0db8:…:7334`, `fe80::1` | full, compressed and loopback. Clock times are not claimed. |

## Gate kinds (generic)

`email`, `phone`, `ni_number`, `ipv4`, `postcode`, `money`, `utr`, `card`,
`iban`, `dob`, `fqdn`, `host_bare`, plus site-specific `staff_id`, `hostname`,
`infra_host`.

`host_bare` requires lowercase and **two or more digits**. One-digit names
(`db2`) are ambiguous and must be seeded:

```python
pipeline.censor.gate.mark_sensitive("db2", "host")
```

## Ordering rules

- Longest / most specific first. The pre-pass exists because the generic gate can
  fragment a UUID or leave a password behind.
- `money` before `utr` before `phone`: `61840.00` is money, `1234567890` is a UTR.
- `uuid` before `host_bare`/`phone`: a UUID tail looks like both.
- fqdn starts with a letter and excludes code/data extensions, so `answer.py` is
  a filename, not a Paraguayan domain.
- Labeled host and name rules replace the whole span (label included). If you
  need the label, change the substitution to replace only the capture group.

## Known limits

- **Names** are roster-first. Context detection catches ticket-style mentions
  (`Reporter: …`, `SRE …`), not a bare name in prose.
- **Addresses** are shape-based. An address with no recognised suffix
  (`Level 3, 88 George Street` is fine; `The Old Bakery` is not) must be declared.
- **Usernames** need a principal context. A bare `mvance` in prose is not claimed.
- **Secrets**: known prefixes and assignment-shaped values only. Random high-entropy
  strings with no label are not detectable by shape; declare them.
- **IPv6**: full and `::` forms. An IPv4-mapped form is covered by the IPv4 part.
- **Digits**: `INC-884920` (ticket), `ISO-27001`, `GPT-6`, `COVID-19` are left
  alone on purpose; they are identifiers of things, not people.

## Adding a detector

1. Add `(kind, regex)` to `PRE_PATTERNS` if it must win over generic patterns;
   otherwise to `PATTERNS`.
2. Add a canary to `CensorPass.CANARIES`.
3. Add a control to `tests/test_pii_coverage.py` with:
   - the value removed,
   - the right kind reported,
   - `restore(scrub(x)) == x`,
   - a benign neighbour that must survive.
4. Run `python3 verify.py`. A detector without a failing control is not done.
