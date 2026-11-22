"""Censor pass for ALL outbound files (REQUIREMENTS R3, extended).

Purpose: nothing leaves this host — not to the frontier agent, not through the
gateway, not in a log, not as an attachment — without passing through here first.

Three enforcement points, because one is never enough:

  FILES      censor_file()      any file bound for outside the boundary
  PROMPTS    censor_prompt()    anything handed to a model (frontier or local-on-behalf)
  EGRESS     EgressGuard        any outbound HTTP body, wrapping the transport

The pass is deny-by-default: a document is not "uncensored because nothing matched",
it is "released because the scan proved clean AND every known planted value was
accounted for". A scan that finds nothing in a document known to contain PII is a
failure of the scanner, not evidence of safety — so the pass takes the ground truth
and fails closed when expected kinds are missing.
"""
import json
import os
import re
import sys

ENGINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine")
sys.path.insert(0, ENGINE)

import keys as K        # noqa: E402
import scrub as S       # noqa: E402
import tokenspace as T  # noqa: E402  (NOT `tokenize`: that name is stdlib)


class CensorFailure(Exception):
    """Raised when the pass cannot prove a document clean. Always fail closed."""


# ---------------------------------------------------------------- detection
# Conservative, explicit patterns. These are the kinds the world plants; a real
# deployment extends this list and keeps the fail-closed behaviour.
PATTERNS = [
    ("staff_id",  re.compile(r"\bSTF-\d{4}\b")),
    ("email",     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("phone",     re.compile(r"(?<!\w)\+\d{1,3}[ \-]?\d{4}[ \-]?\d{5,6}(?!\w)")),
    ("ni_number", re.compile(r"\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b")),
    ("utr",       re.compile(r"\b\d{10}\b")),
    ("postcode",  re.compile(r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}\b")),
    ("ipv4",      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("mac",       re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
    ("fqdn",      re.compile(r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:gwenfawr-npp|npp\.gwenfawr)\.example\b")),
    ("dob",       re.compile(r"\b(?:19[3-9]\d|200[0-7])-\d{2}-\d{2}\b")),
    ("money",     re.compile(r"\b\d{4,7}\.\d{2}\b")),
    ("hostname",  re.compile(r"\b(?:operations|engineering|safety|it)-ws-\d{3}\b")),
    # infrastructure hostnames (npp-dc01, npp-scada-gw, npp-archive01) name systems
    # whose addresses and credentials appear in the same documents
    ("infra_host", re.compile(r"\bnpp-[a-z0-9]+(?:-[a-z0-9]+)*\b")),
    # generic identifiers: a site corpus is not limited to one domain.
    # The FQDN pattern MUST NOT claim filenames. `answer.py` parses as
    # node=answer, TLD=py (Paraguay) and was tokenised as a host, which turned
    # "write a Python file answer.py" into "write a Python file fqdn:XXXX" and
    # the model then produced an extension-less file. Instructions must survive
    # censoring, so common code/data extensions are excluded by lookahead.
    ("uuid",       re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("iban",       re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")),
    ("card",       re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("fqdn",       re.compile(r"\b[a-z][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\."
                              r"(?!(?:py|js|ts|jsx|tsx|md|txt|json|ya?ml|csv|tsv|"
                              r"html?|css|sh|bash|zsh|toml|ini|cfg|conf|log|xml|"
                              r"sql|go|rs|java|c|h|cpp|hpp|zip|tar|gz|tgz|bz2|xz|"
                              r"pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|svg|mp[34]|wav|"
                              r"gguf|bin|whl|pyc|lock|env|gitignore|service)\b)"
                              r"[a-z]{2,}\b", re.I)),
    # bare short hostnames must contain at least TWO digits, be lowercase, and
    # not be a common technical token. The previous version matched any word
    # containing one digit, case-insensitively: "last-4", "ssw0rd", "ED25519",
    # "sha256", "us-west-2" and "INC-90482" were all tokenised, which corrupted
    # instructions and made the model produce nothing. A one-digit name (db2) is
    # ambiguous, so it must be seeded — the same contract as digitless names.
    # The colon guards stop it matching the kind prefix of an emitted token.
    ("host_bare",  re.compile(r"(?<![\w:])"
                              r"(?!sha\d|md5|ed25519|utf\d|ipv[46]|aes\d|base64|h26\d|x26\d|mp[34]\b)"
                              r"(?=[a-z0-9\-]*\d[a-z0-9\-]*\d)"
                              r"[a-z][a-z0-9\-]{2,29}(?![\w:])")),
]


# ------------------------------------------------------------------ pre-pass
# Spans that must be claimed WHOLE, before the generic gate can fragment them.
# Measured failures this fixes: a UUID became "550e8400-<host token><phone
# token>"; a DB URI left its password cleartext after a partial credential
# match; and an incident ticket's employee id, last-4 SSN, postal address,
# usernames, Stripe key and SSH fingerprint were not detected at all.
PRE_PATTERNS = [
    # whole URI, including any password and path
    ("url_credential", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s\"'<>]+", re.I)),
    # user:password@host even without a scheme
    ("credential", re.compile(r"(?<![\w/])[A-Za-z0-9._\-]{1,32}:[^\s@/]{6,}@"
                              r"[A-Za-z0-9.\-]+(?::\d{1,5})?")),
    ("api_secret", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("ssh_fingerprint", re.compile(r"\b(?:SHA256:[A-Za-z0-9+/]{20,}={0,2}|"
                                   r"MD5:(?:[0-9a-f]{2}:){15}[0-9a-f]{2})\b", re.I)),
    ("uuid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{12}\b", re.I)),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("ssn_last4", re.compile(r"(?i)\b(?:last\s*(?:4|four)\s*(?:of\s*)?(?:ssn|social(?:\s*security)?)"
                             r"|ssn\s*(?:last\s*)?4)\b\s*\)?\s*[:#-]?\s*\d{4}\b")),
    ("employee_id", re.compile(r"\b(?:EMP|STF)-\d{4,8}\b", re.I)),
    # Hostnames that generic word rules miss: either labelled, or the Windows
    # uppercase form DESKTOP-9941A. Three digits after the hyphen and a denylist
    # keep GPT-6, COVID-19, INC-884920 and standards numbers out.
    ("host_labeled", re.compile(r"(?i:\b(?:hostname|host|computer|device|machine)\b)"
                                r"\s*[:=]\s*([A-Za-z][A-Za-z0-9._-]{2,31})")),
    ("host_upper", re.compile(r"\b(?!INC-|EMP-|STF-|CVE-|RFC-|ISO-|SHA-|AES-|TLS-|"
                              r"PCI-|SOC-|USB-|HTTP-|GPT-|GLM-|LUN-)"
                              r"[A-Z][A-Z0-9]{2,}-\d{3,}[A-Z0-9-]*\b")),
    # IPv6: full, compressed with "::", and loopback. Requires 7 groups or a
    # double colon, so "08:14:51" and MAC addresses are not claimed.
    ("ipv6", re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"
                        r"|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}"
                        r"(?::[0-9A-Fa-f]{1,4}){0,6})?\b"
                        r"|\b::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?\b")),
    # Singapore: optional Blk, number, street name + suffix, then unit and/or
    # building name, then a mandatory "Singapore NNNNNN". The mandatory tail is
    # what stops it swallowing the next sentence.
    ("address_sg", re.compile(
        r"(?:\bBlk\s+)?\b\d{1,5}[A-Za-z]?\s+(?:[A-Z][\w'&.-]*\s+){1,5}"
        r"(?:Road|Street|Avenue|Ave|Walk|Turn|Drive|Lane|Crescent|Close|Rise|"
        r"Link|Quay|Way|Place|Park|Gardens?|Highway|Ring|Loop|Terrace|Boulevard)\b"
        r"(?:\s+\d{1,2})?"
        r"(?:[,\s]+(?:#\d{2}-\d{2,4}|(?:Apt|Suite|Unit|Flat)\s*[A-Za-z0-9-]+"
        r"|[A-Z][\w'&.-]*(?:\s+[A-Z][\w'&.-]*){0,4})){0,3}"
        r",\s*Singapore\s+\d{6}\b")),
    # street address: number + name + suffix, then ONLY structured components
    # (unit, city, US state+ZIP, UK postcode). A free-text tail swallows the
    # following sentence and can leave a token glued to a digit, which the token
    # grammar then cannot parse back.
    ("address", re.compile(r"\b\d{1,5}\s+(?:[A-Z][\w.'-]*\s+){1,4}"
                           r"(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|"
                           r"Terrace|Ter|Court|Ct|Boulevard|Blvd|Way|Place|Pl|"
                           r"Close|Crescent)\b"
                           r"(?:,\s*(?:Apt|Suite|Unit|Flat|#)\s*[A-Za-z0-9-]+)?"
                           r"(?:,\s*[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,3})?"
                           r"(?:,?\s+[A-Z]{2,3}\s+\d{5}(?:-\d{4})?)?"
                           r"(?:,?\s+[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})?")),
    # a name is claimed only with a role/field context; bare names stay roster-only
    ("person", re.compile(r"(?i:\b(?:reporter|reported\s+by|submitted\s+by|contact|"
                          r"customer|employee|user|sre|on-?call\s+sre|engineer|"
                          r"manager|owner|assignee)\b)\s*[:#-]?\s*"
                          r"([A-Z][a-z]{2,15}(?:\s+[A-Z][a-z]{2,20}){1,2})")),
    # usernames only in contexts that name a principal
    ("username", re.compile(r"(?i:\bfor\s+|\bsudo:\s*|/Users/|/home/)"
                            r"(?!(?:the|this|each|all|more|any|our|your|his|her|its|their)\b)"
                            r"([a-z][a-z0-9._\-]{2,20})(?![\w.\-])")),
]

def all_patterns():
    """PRE first, then the generic list. Computed per call so a test can disarm
    PATTERNS and still exercise the dead-detector control."""
    return PRE_PATTERNS + PATTERNS


def detect(text):
    """Return {kind: [matches]} for every kind that fires at least once."""
    hits = {}
    for kind, rx in all_patterns():
        found = rx.findall(text)
        if found:
            hits[kind] = sorted(set(found))
    return hits


# A token this system already emitted: <kind>:<26 x base32>. Its body is
# uppercase base32, which is indistinguishable from an identifier to any
# pattern (``ipv4:UP36AI7...`` contains a valid IBAN: UP + 36 + 20 chars).
# Every scan therefore runs on the text OUTSIDE these spans, never inside.
TOKEN_SPAN_RE = re.compile(r"(?<![\w:])[a-z][a-z0-9_]*:[A-Z2-7]{26}(?![\w:])")


def map_outside_tokens(text, fn):
    """Apply fn to the non-token segments of text, leaving tokens untouched."""
    out, last = [], 0
    for m in TOKEN_SPAN_RE.finditer(text):
        out.append(fn(text[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(fn(text[last:]))
    return "".join(out)


def detect_visible(text):
    """detect(), ignoring anything inside an already-emitted token."""
    hits = {}
    segs = _segments(text)
    for kind, rx in all_patterns():
        found = []
        for seg in segs:
            found.extend(rx.findall(seg))
        if found:
            hits[kind] = sorted(set(found))
    return hits


def _segments(text):
    """The parts of text that are not already tokens."""
    out, last = [], 0
    for m in TOKEN_SPAN_RE.finditer(text):
        out.append(text[last:m.start()])
        last = m.end()
    out.append(text[last:])
    return out


# Kinds the engine's own ScrubGate already tokenises. Everything NOT listed here is
# tokenised by the censor pass itself, through the same TokenSpace, so tokens stay
# consistent across the whole corpus.
ENGINE_KINDS = {"email", "phone", "ni_number", "ipv4", "postcode",
                "money", "utr"}


# Dates are tokenised only when they cannot be an operational date. A survey dated
# 2026-11-19 is not PII; a date of birth is. Without this distinction the pass
# destroys the timeline of every document and the artefact cannot be useful, which
# pushes people to switch the pass off — the failure mode that matters most.
DOB_MIN_YEARS = 18


def classify_dates(text, world_year=2026):
    """Split ISO dates into (dob_candidates, operational_dates).

    A birth date belongs to someone aged >= 18, so its year is at least world_year-18.
    Anything later is plausible operational data and is left alone.
    """
    dob, ops = [], []
    for m in re.finditer(r"\b(19\d{2}|20\d{2})-(\d{2})-(\d{2})\b", text):
        y = int(m.group(1))
        (dob if y <= world_year - DOB_MIN_YEARS else ops).append(m.group(0))
    return sorted(set(dob)), sorted(set(ops))


def detect_names(text, names):
    """Person names are not regex-detectable, so they are matched from the roster.

    This is the honest approach: the roster is the authority, not a guess at what a
    name looks like. In production the roster comes from HR, not from a text file.

    Two forms are matched: the literal name, and the name with whitespace collapsed to a
    single space — because markdown wraps lines mid-name ("Sergei\\nVainikka-Petrov"),
    and a literal-only match silently misses exactly the documents where names are
    hardest to see.
    """
    found = []
    low = text.lower()
    flat = re.sub(r"\s+", " ", low)
    for n in names:
        nl = n.lower()
        if nl in low or re.sub(r"\s+", " ", nl) in flat:
            found.append(n)
    return sorted(set(found))


# ---------------------------------------------------------------- the pass
class CensorPass:
    def __init__(self, profile_dir, roster_names=None, ground_truth=None):
        self.key = K.load_required(K._default_path(profile_dir))
        self.space = T.TokenSpace(self.key)
        self.gate = S.ScrubGate(self.space)
        self.roster = list(roster_names or [])
        for n in self.roster:
            self.gate.mark_sensitive(n, "name")
        self.ground_truth = ground_truth or {}

    # -- self-test: a dead detector must never certify a document clean ----
    CANARIES = {
        "staff_id":  "STF-9999",
        "email":     "canary@gwenfawr-npp.example",
        "phone":     "+44 7700 909999",
        "ni_number": "QQ 99 99 99 C",
        "ipv4":      "10.99.99.99",
        "mac":       "02:99:99:99:99:99",
        "fqdn":      "canary.npp.gwenfawr.example",
        "hostname":  "it-ws-999",
        "infra_host": "npp-canary99",
        "dob":       "1999-09-09",
        "url_credential": "postgresql://canary:hunter2canary@db.example:5432/prod",
        "credential": "canaryuser:hunter2canary@db.example",
        "api_secret": "sk_" + "test_" + "51P9xK2L9vQ8mN3zR7wT4yB6c",
        "aws_key":   "AKIA" + "IOSFODNN7EXAMPLE",
        "ssh_fingerprint": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
        "uuid":      "550e8400-e29b-41d4-a716-446655440000",
        "ssn":       "123-45-6789",
        "ssn_last4": "Last 4 SSN: 6789",
        "employee_id": "EMP-90482",
        "host_labeled": "Hostname: DESKTOP-9941A",
        "host_upper": "DESKTOP-9941A",
        "ipv6":      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "address":   "742 Evergreen Terrace, Apt 4B, San Francisco, CA 94107",
        "address_sg": "Blk 35 Mandalay Road, #01-01, Singapore 308215",
        "person":    "Reporter: Sarah Jenkins",
        "username":  "Accepted publickey for canaryuser",
    }

    def self_test(self):
        """Run every detector against a value it must catch.

        This is the check that makes 'no hits' mean something. Without it, deleting or
        breaking a pattern produces a document that scans clean and gets released —
        the pass would report success while leaking. Returns {kind: bool}.
        """
        out = {}
        for kind, sample in self.CANARIES.items():
            rx = dict(all_patterns()).get(kind)
            out[kind] = bool(rx and rx.search(sample))
        # name matching has no regex; probe it with a roster entry if we have one
        if self.roster:
            probe = self.roster[0].split()[0] + "\n" + " ".join(self.roster[0].split()[1:])
            out["name"] = bool(detect_names(probe, self.roster))
        return out

    def _require_detectors_alive(self):
        diag = self.self_test()
        dead = [k for k, ok in diag.items() if not ok]
        if dead:
            raise CensorFailure(
                f"censor pass self-test failed: detectors not firing: {dead}. "
                f"Refusing to certify any document clean while the scanner is broken.")

    # -- shared sub-step ---------------------------------------------------
    def _tokenise_pre(self, text):
        """Claim whole structured spans before the generic gate can fragment them.

        Runs outside already-emitted tokens. A UUID, URI credential, address or
        context-bound name that is cut into pieces leaks the pieces.
        """
        for kind, rx in PRE_PATTERNS:
            def sub(m, kind=kind):
                return f"{kind}:{self.space.issue(kind, m.group(0))}"
            text = map_outside_tokens(
                text, lambda seg, rx=rx, sub=sub: rx.sub(sub, seg))
        return text

    def _tokenise_names(self, text):
        """Tokenise roster names, including across line breaks.

        `detect_names` can find "Sergei\\nVainikka-Petrov"; the gate's literal replace
        cannot, because it looks for the exact string. So names are replaced here with a
        whitespace-tolerant pattern, longest first, or the longest name would be
        partially eaten by a shorter one sharing a token.
        """
        for name in sorted(self.roster, key=len, reverse=True):
            parts = [re.escape(p) for p in name.split()]
            if not parts:
                continue
            rx = re.compile(r"\s+".join(parts), re.I)
            if rx.search(text):
                text = rx.sub(f"name:{self.space.issue('name', name)}", text)
        return text

    def _tokenise_extra(self, text):
        """Tokenise kinds the engine gate does not know about.

        The engine's PATTERNS cover the classic identifiers. A site corpus also carries
        staff IDs, hostnames and MACs, and an ISO date that is a date of birth. Those are
        tokenised here through the SAME TokenSpace, so a staff ID in two documents
        yields the same token in both — which is what lets the receiving side group
        without ever holding the ID.
        """
        for kind, rx in PATTERNS:
            if kind in ENGINE_KINDS:
                continue
            def sub(m, kind=kind):
                return f"{kind}:{self.space.issue(kind, m.group(0))}"
            # Never rescan the body of a token this pass already emitted:
            # base32 looks like an IBAN, a card, or a host to a regex.
            text = map_outside_tokens(text, lambda seg: rx.sub(sub, seg))
        return text

    # -- 1. files ---------------------------------------------------------
    def censor_file(self, path, expect_kinds=None):
        """Censor one outbound file. Returns (censored_text, report).

        Returns a report with kinds, counts, and a verdict. Raises CensorFailure if
        the document contains a value the pass cannot tokenise, because a partial
        censor that silently drops a kind is worse than a refusal.
        """
        if not os.path.exists(path):
            raise CensorFailure(f"file not found: {path}")
        self._require_detectors_alive()
        raw = open(path, encoding="utf-8", errors="replace").read()

        names = detect_names(raw, self.roster)
        for n in names:
            self.gate.mark_sensitive(n, "name")

        before = detect(raw)
        text = self._tokenise_pre(raw)
        text, rep = self.gate.scrub(text)
        text = self._tokenise_names(text)
        text = self._tokenise_extra(text)
        after = detect_visible(text)
        after_names = detect_names(text, self.roster)

        # residual = anything still recognisable after the pass; this is the check
        # that catches a detector that silently stopped working
        residual = dict(after)
        if after_names:
            residual["name"] = after_names
        if residual:
            raise CensorFailure(
                f"residual identifiers after censor in {os.path.basename(path)}: "
                f"{ {k: v[:3] for k, v in residual.items()} }")

        # expected kinds: a doc known to hold PII that yields no hits is a scanner
        # failure, not a clean document
        if expect_kinds:
            missing = [k for k in expect_kinds if k not in before and k != "name"] 
            if missing and not names:
                raise CensorFailure(
                    f"{os.path.basename(path)}: expected kinds {missing} not detected; "
                    f"refusing to certify clean")

        return text, {
            "file": os.path.relpath(path),
            "bytes_in": len(raw),
            "bytes_out": len(text),
            "kinds": before,
            "names": names,
            "detectors_fired": sorted(before) + (["name"] if names else []),
            "verdict": "censored",
        }

    # -- 2. prompts -------------------------------------------------------
    def censor_prompt(self, prompt):
        """Censor anything bound for a model. Same gate, no shortcut."""
        # A prompt released on the word of a dead scanner is the failure this
        # system exists to prevent, so the canaries run before every prompt.
        self._require_detectors_alive()
        names = detect_names(prompt, self.roster)
        for n in names:
            self.gate.mark_sensitive(n, "name")
        before = detect(prompt)
        text = self._tokenise_pre(prompt)
        text, _ = self.gate.scrub(text)
        text = self._tokenise_names(text)
        text = self._tokenise_extra(text)
        after = detect_visible(text)
        after_names = detect_names(text, self.roster)
        residual = dict(after)
        if after_names:
            residual["name"] = after_names
        if residual:
            raise CensorFailure(f"residual identifiers in prompt: {list(residual)}")
        return text, {"kinds": before, "names": names,
                      "detectors_fired": sorted(before) + (["name"] if names else [])}

    # -- 3. egress --------------------------------------------------------
    def check_egress(self, body, label="gateway"):
        """Verify an outbound body is clean. Used inside the transport wrapper."""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        self._require_detectors_alive()
        names = detect_names(body, self.roster)
        residual = detect(body)
        if names:
            residual["name"] = names
        if residual:
            raise CensorFailure(
                f"UNCENSORED EGRESS blocked at {label}: "
                f"{ {k: v[:3] for k, v in residual.items()} }")
        return True


class EgressGuard:
    """Wraps an outbound transport so nothing reaches the wire uninspected.

    Not a policy object — a chokepoint. If a caller can bypass it, the guard is
    theatre, so the only function exposed is send(), and send() censors first.
    """

    def __init__(self, censor: CensorPass, transport, log_path=None):
        self.censor = censor
        self.transport = transport
        self.log_path = log_path
        self.blocked = []
        self.allowed = 0

    def send(self, body, label="gateway"):
        try:
            self.censor.check_egress(body, label)
        except CensorFailure as e:
            self.blocked.append(str(e))
            raise
        self.allowed += 1
        if self.log_path:
            with open(self.log_path, "a") as f:
                f.write(json.dumps({"label": label, "bytes": len(str(body)),
                                    "verdict": "allowed"}) + "\n")
        return self.transport(body)


def load_world(world_dir):
    gt = json.load(open(os.path.join(world_dir, "ground_truth.json")))
    names = [s["name"] for s in gt["staff"]]
    return gt, names


def main():
    world = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agentworld")
    gt, names = load_world(world)
    profile = os.path.expanduser("~/.hermes/profiles/desensitizeragenttest")
    cp = CensorPass(profile, names, gt)

    site = os.path.join(world, "site")
    total = 0
    failed = []
    kinds_seen = {}
    for root, _, files in os.walk(site):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            try:
                _, rep = cp.censor_file(p)
                total += 1
                for k in rep["detectors_fired"]:
                    kinds_seen[k] = kinds_seen.get(k, 0) + 1
            except CensorFailure as e:
                failed.append(str(e))
    print(f"files censored: {total}")
    print(f"document kinds across corpus: {json.dumps(kinds_seen, indent=1)}")
    if failed:
        print(f"FAILURES ({len(failed)}):")
        for f in failed:
            print("  -", f)
        return 1
    print("all documents censored clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
