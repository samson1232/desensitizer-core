"""Per-installation key management for the desensitizer.

The key is what makes tokens non-invertible and non-correlatable across installs
(REQUIREMENTS R1.2, R1.3). It never leaves this module's owner and is never
serialised into any outbound payload.

Key material lives in a file outside the vault (R2.1), mode 0600.
"""
import base64
import os
import secrets

KEY_BYTES = 32
KEY_FILE_MODE = 0o600


class KeyError_(Exception):
    """Key material missing, wrong length, or unreadable. Always fatal (R7.2)."""


def _default_path(profile_dir):
    return os.path.join(profile_dir, "desens_key.bin")


def load_or_create(path):
    """Return 32 key bytes, creating the file on first use.

    Creating on first use is convenient but must be loud: a missing key on an
    *existing* installation means the vault is unreadable, and silently minting a
    new one would make every stored token unresolvable. Callers that expect an
    existing key should pass create=False.
    """
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        if len(data) != KEY_BYTES:
            raise KeyError_(f"key file {path} is {len(data)} bytes, expected {KEY_BYTES}")
        return data
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = secrets.token_bytes(KEY_BYTES)
    # O_EXCL so two concurrent starts cannot race and one wins silently
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, KEY_FILE_MODE)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def load_required(path):
    """Load an existing key; raise rather than create. Used by the vault path (R2.4)."""
    if not os.path.exists(path):
        raise KeyError_(f"no key at {path}; refusing to operate (vault would be unreadable)")
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != KEY_BYTES:
        raise KeyError_(f"key file {path} is {len(data)} bytes, expected {KEY_BYTES}")
    return data


def install_secret_b64(path):
    """For operator records only — never call this on a payload."""
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()
