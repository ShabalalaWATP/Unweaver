"""
Symmetric encryption for sensitive values (API keys).

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the ``cryptography`` library.
The encryption key is derived from the ``UNWEAVER_SECRET_KEY`` environment
variable.  If no secret key is set, a per-installation key is auto-generated
and persisted to ``.unweaver_secret`` next to the database file.

The encrypt/decrypt helpers are plain synchronous functions so they can be
called from both sync and async contexts without awaiting.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_fernet: Fernet | None = None


def _derive_key(secret: str) -> bytes:
    """Derive a 32-byte URL-safe base64 Fernet key from an arbitrary secret."""
    raw = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(raw)


def _get_fernet() -> Fernet:
    """Return a cached Fernet instance, creating the key on first call."""
    global _fernet
    if _fernet is not None:
        return _fernet

    secret = os.environ.get("UNWEAVER_SECRET_KEY", "")
    if secret:
        _fernet = Fernet(_derive_key(secret))
        return _fernet

    # Auto-generate and persist a key file next to the DB.
    key_path = Path(".unweaver_secret")
    if key_path.exists():
        secret = key_path.read_text(encoding="utf-8").strip()
    else:
        secret = Fernet.generate_key().decode("utf-8")
        try:
            key_path.write_text(secret, encoding="utf-8")
            logger.info("Generated new encryption key at %s", key_path)
        except OSError:
            logger.warning("Could not persist encryption key to %s", key_path)

    # If the auto-generated secret is already a valid Fernet key, use directly.
    try:
        _fernet = Fernet(secret.encode("utf-8") if isinstance(secret, str) else secret)
    except Exception:
        _fernet = Fernet(_derive_key(secret))

    return _fernet


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext string and return a base64 token."""
    if not plaintext:
        return ""
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_value(token: str) -> str:
    """Decrypt a Fernet token back to plaintext.

    Returns the original string on success.  If decryption fails (e.g. the
    value was stored before encryption was enabled), the raw token is
    returned unchanged so the system degrades gracefully.
    """
    if not token:
        return ""
    f = _get_fernet()
    try:
        return f.decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        # Graceful fallback: treat as legacy plaintext value.
        return token
