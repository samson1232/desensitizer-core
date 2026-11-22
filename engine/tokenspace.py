"""Token derivation — the outbound blind (REQUIREMENTS R1).

Design decisions and why:

* HMAC-SHA256, not a bare hash. A bare `sha256(phone)` is a dictionary attack away
  from the real value (T2); the key must be in the derivation.
* A *domain* string is folded into the input. ``email:alice@x.com`` and
  ``name:alice@x.com`` must not collide to one token (R1.3), because a token that
  means two things cannot be re-anchored unambiguously (R5.4).
* The token is a fixed-length base32 slice of the MAC. Fixed length regardless of
  input is what stops length leaking the value (R1.4, T8). Truncation width is a
  real trade-off, discussed in TOKEN_CHARS below.
* Tokens are salted *implicitly* by the per-installation key. Two installations
  with different keys produce unrelated token spaces for the same value (R1.2).
"""
import hashlib
import hmac

# 26 base32 chars = 130 bits of MAC output. Overkill against brute force, and the
# cost of overkill here is only token width. Not shortened further: a short token
# would collide across a large dataset, and collision handling (R1.5) is a failure
# path we do not want to walk at 10 chars.
TOKEN_CHARS = 26
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # RFC 4648 base32, uppercase


class TokenCollision(Exception):
    """Two distinct values derived the same token. Must never be silently merged (R1.5)."""


def _mac(key, domain, value):
    msg = f"{domain}\x00{value}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).digest()


def raw_token(key, domain, value):
    """Full 52-char base32 of the MAC. Constant length for any input."""
    import base64
    return base64.b32encode(_mac(key, domain, value)).decode("ascii").rstrip("=")


def token(key, domain, value):
    """The token as it appears on the wire: fixed width, uniform alphabet."""
    return raw_token(key, domain, value)[:TOKEN_CHARS]


def prefixed(key, domain, value):
    """Token with a type hint. The hint is *not* the real value's type or length —
    it is the declared domain, which the remote side needs to reason at all
    (e.g. ``email:XXXX``). It must be a fixed vocabulary, never free text."""
    if not domain or not domain.isalpha():
        raise ValueError(f"domain must be alphabetic, got {domain!r}")
    return f"{domain}:{token(key, domain, value)}"


class TokenSpace:
    """In-session registry enforcing R1.1 (stability) and R1.5 (collision detection).

    Stability matters for the remote side: it must be able to group rows by a token.
    Collision detection matters for us: a collision means two real values share a
    pseudonym, and re-anchoring would write the wrong one.
    """

    def __init__(self, key):
        self.key = key
        self._t2v = {}   # token -> value
        self._v2t = {}   # (domain, value) -> token

    def issue(self, domain, value):
        v = "" if value is None else str(value)
        k = (domain, v)
        if k in self._v2t:
            return self._v2t[k]                 # R1.1 stable
        t = token(self.key, domain, v)
        if t in self._t2v and self._t2v[t] != v:
            raise TokenCollision(                 # R1.5
                f"token collision in domain {domain!r}: two distinct values mapped to {t}")
        self._v2t[k] = t
        self._t2v[t] = v
        return t

    def value_for(self, t):
        """Reverse lookup inside the session. Absent token is an error (R5.4)."""
        if t not in self._t2v:
            raise KeyError(f"unknown token {t!r}")
        return self._t2v[t]

    def known(self, t):
        return t in self._t2v

    def __len__(self):
        return len(self._t2v)
