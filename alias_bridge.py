"""Alias bridge v2 — censor() actually scrubs, into aliases.

v1 (alias_bridge.py) had a reversible registry and a strict restore(), but
censor() was `_ALIAS_RE.sub(lambda m: m.group(0))` — a no-op. It could restore
but never scrub. v2 keeps v1's registry and restore() semantics byte-compatible
and adds the missing direction:

    text --detect--> mint aliases --> substituted text --restore--> text

Design rules carried from v1, unchanged:
  * restore() is single pass, strict, never guesses. Unknown aliases are left
    untouched and reported.
  * aliases are per-scope. One scope cannot resolve another's.

New rules for scrubbing:
  * censor() detects and replaces. It never leaves a detected value in place.
  * censor() is idempotent: censoring twice equals censoring once, because an
    alias is not itself a value to be re-aliased.
  * Overlap is resolved longest-first, so a card number beats a shorter
    numeric match inside it.
  * A value that appears twice maps to the same alias.
"""
import re

KIND_PREFIX = {
    "person": "person_ID",
    "host": "hostname",
    "money": "money",
    "email": "email",
    "phone": "phone",
    "postcode": "postcode",
    "utr": "utr",
    "ipv4": "ip",
    "card": "card",
    "iban": "iban",
    "uuid": "uuid",
}

_ALIAS_RE = re.compile(
    r"(?<![\w])((?:" + r"|".join(re.escape(p) for p in
     sorted(KIND_PREFIX.values(), key=len, reverse=True)) + r")_)(\d+)(?![\w])"
)

# -- detectors -------------------------------------------------------------
# Order matters only for readability; matching is longest-span-first.
DETECTORS = [
    ("uuid", re.compile(r"(?<![\w])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                        r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![\w])")),
    ("email", re.compile(r"(?<![\w.])[\w.+-]+@[\w-]+\.[\w.-]+(?![\w])")),
    ("iban", re.compile(r"(?<![\w])[A-Z]{2}\d{2}[A-Z0-9]{10,30}(?![\w])")),
    ("card", re.compile(r"(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])")),
    ("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    ("postcode", re.compile(r"(?<![\w])[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}(?![\w])")),
    ("money", re.compile(r"(?<![\w£$€])[£$€]\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?![\d])")),
    ("utr", re.compile(r"(?<![\d])\d{10}(?![\d])")),
    ("phone", re.compile(r"(?<![\d])\+?\d[\d ()-]{8,17}\d(?![\d])")),
    # Filenames must survive: "answer.py" parses as node + TLD (.py = Paraguay)
    # and must NOT be treated as a host, or the pipeline destroys its own
    # instructions. Code/data extensions are excluded.
    ("host", re.compile(r"(?<![\w.-])(?:[a-zA-Z][\w-]*\.)+"
                        r"(?!(?:py|js|ts|jsx|tsx|md|txt|json|ya?ml|csv|tsv|html?|"
                        r"css|sh|toml|ini|cfg|conf|log|xml|sql|go|rs|java|c|h|cpp|"
                        r"zip|tar|gz|pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|svg|mp[34]|"
                        r"gguf|bin|pyc|lock|env)\b)"
                        r"[a-zA-Z]{2,}\.?(?![\w-])")),
    # Bare short hostnames (srv01, ftcam01, s600). Requires a digit so ordinary
    # words are not claimed. Digitless names (sigmac) cannot be detected from
    # shape and must be seeded explicitly via seed_hosts().
    ("host_bare", re.compile(r"(?<![\w.-])(?=[a-z0-9-]*\d)[a-z][a-z0-9-]{2,29}(?![\w.-])")),
    # Names last: a capitalised two-word sequence is the most false-positive
    # prone pattern here, so it only claims spans nothing else wanted.
    ("person", re.compile(r"(?<![\w])(?:Dr|Mr|Mrs|Ms|Miss)?\s?"  # honourific optional
                          r"[A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20}){1,3}(?![\w])")),
]

# When two detectors claim the same span, the earlier one in this list wins.
# 10 digits is a UTR before it is a phone number.
PRECEDENCE = ["uuid", "email", "iban", "card", "ipv4", "postcode", "money", "utr",
              "phone", "host", "host_bare", "person"]


class AliasError(Exception):
    """A censor or restoration could not be performed safely."""


class AliasScope:
    """One task's alias ledger. Restoring outside its scope is impossible."""

    __slots__ = ("_v2a", "_a2v", "_counters", "scope_id")

    def __init__(self, scope_id: str = ""):
        self._v2a: dict[tuple[str, str], str] = {}
        self._a2v: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self.scope_id = scope_id

    # -- registry ----------------------------------------------------------
    def issue(self, kind: str, value) -> str:
        v = "" if value is None else str(value)
        if kind == "host_bare":
            kind = "host"          # share one hostname namespace
        prefix = KIND_PREFIX.get(kind)
        if prefix is None:
            raise AliasError(f"unknown kind {kind!r}; extend KIND_PREFIX deliberately")
        key = (kind, v)
        if key in self._v2a:
            return self._v2a[key]

        n = self._counters.get(prefix, 0)
        while True:
            n += 1
            alias = f"{prefix}_{n}"
            if alias == v:
                continue
            if alias in self._a2v and self._a2v[alias] != v:
                continue
            break
        self._counters[prefix] = n
        self._v2a[key] = alias
        self._a2v[alias] = v
        return alias

    def resolve(self, alias: str) -> str:
        try:
            return self._a2v[alias]
        except KeyError:
            raise AliasError(f"unknown alias {alias!r} in this scope") from None

    def known(self, alias: str) -> bool:
        return alias in self._a2v

    # -- scrubbing ---------------------------------------------------------
    def censor(self, text: str, min_kind_confidence: int = 1) -> tuple[str, dict]:
        """Replace every detected value with an alias minted in this scope.

        Returns (censored_text, report). The report lists what was replaced.
        Detected spans are resolved longest-first so a card number is not
        chopped up by the phone or UTR pattern inside it.
        """
        if not isinstance(text, str):
            raise AliasError(f"censor expects str, got {type(text).__name__}")

        spans = []          # (start, end, kind, value)
        for kind, rx in DETECTORS:
            for m in rx.finditer(text):
                spans.append((m.start(), m.end(), kind, m.group(0)))
        if not spans:
            return text, {"replaced": [], "count": 0}

        # longest span first; on equal length, PRECEDENCE decides, then start
        rank = {k: i for i, k in enumerate(PRECEDENCE)}
        spans.sort(key=lambda s: (-(s[1] - s[0]), rank.get(s[2], 99), s[0]))
        taken = []          # accepted non-overlapping spans
        for sp in spans:
            s, e = sp[0], sp[1]
            if any(not (e <= ts or s >= te) for ts, te, _, _ in taken):
                continue
            taken.append(sp)

        # An alias already in the text is not a value to re-mint. Detect it and
        # protect those spans so "person_ID_1" cannot be aliased again.
        protected = [(m.start(), m.end()) for m in _ALIAS_RE.finditer(text)]
        taken = [sp for sp in taken
                 if not any(not (sp[1] <= ps or sp[0] >= pe) for ps, pe in protected)]
        taken.sort(key=lambda s: s[0])

        out, cursor, replaced = [], 0, []
        for s, e, kind, value in taken:
            out.append(text[cursor:s])
            alias = self.issue(kind, value)
            out.append(alias)
            replaced.append({"value_kind": kind, "alias": alias})
            cursor = e
        out.append(text[cursor:])
        return "".join(out), {"replaced": replaced, "count": len(replaced)}

    def seed_hosts(self, hosts) -> dict:
        """Mint aliases for known hostnames that no detector can find.

        Digitless names like `sigmac` are lexically indistinguishable from an
        ordinary word, so shape-based detection cannot see them. Seeding puts
        them in the registry so restore() can still resolve them, and so a
        later exact-match pass can substitute them. Never guesses: only the
        names passed in are affected.
        """
        out = {}
        for h in hosts:
            if isinstance(h, str) and h.strip():
                out[h] = self.issue("host", h.strip())
        return out

    def censor_with_seeds(self, text: str, hosts) -> tuple[str, dict]:
        """censor(), plus exact-substring replacement for seeded hostnames."""
        censored, rep = self.censor(text)
        seeds = self.seed_hosts(hosts)
        replaced = list(rep["replaced"])
        for host in sorted(seeds, key=len, reverse=True):
            if host in censored:
                censored = censored.replace(host, seeds[host])
                replaced.append({"value_kind": "host_seeded", "alias": seeds[host]})
        return censored, {"replaced": replaced, "count": len(replaced)}

    # -- restoration -------------------------------------------------------
    def restore(self, text: str) -> tuple[str, dict]:
        """Restore aliases to real values, single pass, strict."""
        if not isinstance(text, str):
            raise AliasError(f"restore expects str, got {type(text).__name__}")
        unknown: list[str] = []
        restored: list[str] = []

        def _sub(m):
            alias = m.group(0)
            if alias in self._a2v:
                restored.append(alias)
                return self._a2v[alias]
            unknown.append(alias)       # Rule 3: never guess
            return alias

        out = _ALIAS_RE.sub(_sub, text)
        return out, {"unknown": unknown, "restored": restored}

    # -- introspection -----------------------------------------------------
    def export(self) -> dict:
        """The pivot table. NEVER send this to a frontier model."""
        return {"scope_id": self.scope_id,
                "a2v": dict(self._a2v)}
