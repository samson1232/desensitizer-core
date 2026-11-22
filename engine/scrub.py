"""Outbound scrubbing gate (REQUIREMENTS R3).

Every outbound payload passes through ScrubGate.scrub(). There is no second way out
of this package — engine.request refuses to build a payload any other way.

Honesty note, repeated here because it is the easiest thing to forget: the
detectors below are heuristics. They reliably catch structured identifiers. They do
NOT reliably catch human names, addresses, or free-form secrets. That is why
`mark_sensitive()` exists: the caller must tell the gate what it knows is sensitive.
A design that pretends regexes solve free text is the failure mode this module
documents rather than hides.
"""
import re

# Ordered: longest / most specific first so an ID is not mistaken for a shorter pattern.
# NOTE: censor_pass.ENGINE_KINDS declares which kinds it expects THIS list to handle.
# money, postcode and utr were listed there but absent here, so salary, postcode and
# UTR flowed through unscrubbed and were only caught by the residual check (blocking
# the document rather than scrubbing it). Any kind added to ENGINE_KINDS must exist
# here, or the pass must tokenise it itself.
PATTERNS = [
    ("url_cred", re.compile(r"\b[a-z][a-z0-9+.\-]*://([^/\s:@]+):([^/\s@]+)@", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("ni_number", re.compile(r"\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b")),
    ("card", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    # money before phone/utr: "61840.00" must not be eaten by a digit-run pattern
    ("money", re.compile(r"\b\d{4,7}\.\d{2}\b")),
    # utr before phone: a bare 10-digit run is a UTR, not a phone number. The old
    # ordering let phone claim 1234567890 and label it phone:, corrupting the token kind.
    ("utr", re.compile(r"\b\d{10}\b")),
    ("phone", re.compile(r"(?<!\w)(?:\+\d{1,3}[ \-]?)?(?:\(?\d{2,4}\)?[ \-]?)\d{3,4}[ \-]?\d{3,4}(?!\w)")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("postcode", re.compile(r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}\b")),
    ("uuid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("bearer", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}=*")),
]


class ScrubFailure(Exception):
    """Gate could not do its job. Callers must refuse to send (R7.1)."""


class Report:
    def __init__(self):
        self.hits = []          # (kind, replacement)
        self.literals = []      # operator-tagged literal matches

    def kinds(self):
        return sorted({k for k, _ in self.hits})

    def __repr__(self):
        return f"<Report hits={len(self.hits)} literals={len(self.literals)} kinds={self.kinds()}>"


class ScrubGate:
    """Tokenises detected values through the session TokenSpace, so the outbound
    text keeps its structure (R4.1) while carrying no real values (R3.2)."""

    # A token this gate already emitted. Its body is base32, which looks like a
    # postcode, a card or an IBAN to the patterns below — so every later
    # substitution must run on the text OUTSIDE these spans. Without this, a
    # literal replaced first is re-tokenised by a pattern afterwards, and the
    # document no longer restores (observed: name:iban:XXXX).
    TOKEN_SPAN_RE = re.compile(r"(?<![\w:])[a-z][a-z0-9_]*:[A-Z2-7]{26}(?![\w:])")

    def __init__(self, space):
        self.space = space
        self._literals = []      # (value, domain)

    @classmethod
    def _outside_tokens(cls, text, fn):
        out, last = [], 0
        for m in cls.TOKEN_SPAN_RE.finditer(text):
            out.append(fn(text[last:m.start()]))
            out.append(m.group(0))
            last = m.end()
        out.append(fn(text[last:]))
        return "".join(out)

    def mark_sensitive(self, value, domain="secret"):
        """Explicit sensitivity declaration (R3.3). Use this for names and any field
        you already know is sensitive; do not hope the regexes find it."""
        if value:
            self._literals.append((str(value), domain))
            self._literals.sort(key=lambda x: -len(x[0]))   # longest first
        return self

    def scrub(self, text):
        if text is None:
            raise ScrubFailure("refusing to scrub None; caller bug, not a payload")
        if not isinstance(text, str):
            raise ScrubFailure(f"payload must be text, got {type(text).__name__}")
        rep = Report()
        out = text

        # 1. operator-tagged literals win over pattern guesses
        for lit, domain in self._literals:
            def sub_lit(seg, lit=lit, domain=domain):
                if lit not in seg:
                    return seg
                t = self.space.issue(domain, lit)
                rep.literals.append((domain, t))
                return seg.replace(lit, f"{domain}:{t}")
            out = self._outside_tokens(out, sub_lit)

        # 2. structured detectors
        for kind, pat in PATTERNS:
            def sub(m, kind=kind):
                v = m.group(0)
                t = self.space.issue(kind, v)
                rep.hits.append((kind, f"{kind}:{t}"))
                return f"{kind}:{t}"
            out = self._outside_tokens(out, lambda seg, pat=pat, sub=sub: pat.sub(sub, seg))
        return out, rep

    def verify_clean(self, scrubbed, originals):
        """Post-condition check: assert none of the known real values survived.
        Cheap, and it is the difference between 'we scrubbed' and 'we can prove it'."""
        for v in originals:
            if v and len(str(v)) >= 4 and str(v) in scrubbed:
                raise ScrubFailure(f"scrub incomplete: value of length {len(str(v))} survived")
        return True
