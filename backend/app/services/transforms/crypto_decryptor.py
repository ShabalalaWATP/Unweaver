"""
AES / RC4 / symmetric cipher key extraction and decryption.

Detects hardcoded encryption keys and encrypted payloads in source code,
attempts decryption using common modes (AES-CBC, AES-ECB, RC4), and
replaces ciphertext with plaintext where successful.

Requires the ``cryptography`` library for AES.  RC4 uses a pure-Python
implementation to avoid extra dependencies.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseTransform, TransformResult

# ---------------------------------------------------------------------------
# Key detection patterns
# ---------------------------------------------------------------------------

# Hex key literals: "4142434445..." (32, 48, or 64 hex chars = 16, 24, 32 bytes)
_HEX_KEY_RE = re.compile(
    r"""(?:key|secret|password|aes_?key|rc4_?key|cipher_?key|k|iv)\s*"""
    r"""[=:]\s*['"]((?:[0-9a-fA-F]{2}){16,32})['"]""",
    re.IGNORECASE,
)

# Byte array keys: [0x41, 0x42, ...] (16, 24, or 32 bytes)
_BYTE_KEY_RE = re.compile(
    r"""(?:key|secret|password|aes_?key|rc4_?key|cipher_?key)\s*[=:]\s*"""
    r"""\[\s*((?:0x[0-9a-fA-F]{1,2}\s*,\s*){15,31}0x[0-9a-fA-F]{1,2})\s*\]""",
    re.IGNORECASE,
)

# Base64 key literals (16, 24, 32 bytes = 24, 32, 44 base64 chars)
_B64_KEY_RE = re.compile(
    r"""(?:key|secret|password|aes_?key|rc4_?key)\s*[=:]\s*"""
    r"""['"]([A-Za-z0-9+/]{22,44}={0,2})['"]""",
    re.IGNORECASE,
)

# IV / nonce patterns (16 bytes)
_IV_RE = re.compile(
    r"""(?:iv|nonce|init_?vec)\s*[=:]\s*"""
    r"""['"]([0-9a-fA-F]{32}|[A-Za-z0-9+/]{22,24}={0,2})['"]""",
    re.IGNORECASE,
)

# Encrypted payload patterns: long base64 blobs near crypto function calls
_ENCRYPTED_PAYLOAD_RE = re.compile(
    r"""(?:decrypt|decipher|aes|rc4|cipher)\s*\(\s*['"]([A-Za-z0-9+/=]{32,})['"]""",
    re.IGNORECASE,
)

# Generic long base64 near crypto keywords
_CRYPTO_CONTEXT_RE = re.compile(
    r"""(?:AES|RC4|DES|Rijndael|CryptoJS|Cipher|encrypt|decrypt)""",
    re.IGNORECASE,
)

# CryptoJS patterns (very common in web malware)
_CRYPTOJS_RE = re.compile(
    r"""CryptoJS\.AES\.decrypt\s*\(\s*['"]([A-Za-z0-9+/=]{16,})['"]"""
    r"""\s*,\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# .NET AES patterns
_DOTNET_AES_RE = re.compile(
    r"""(?:Aes|RijndaelManaged|AesCryptoServiceProvider)"""
    r""".*?\.Key\s*=\s*(?:Convert\.FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]"""
    r"""|new\s+byte\s*\[\s*\]\s*\{([^}]+)\})""",
    re.IGNORECASE | re.DOTALL,
)


def _hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _byte_array_to_bytes(array_str: str) -> bytes:
    parts = re.findall(r"0x([0-9a-fA-F]{1,2})", array_str)
    return bytes(int(p, 16) for p in parts)


def _b64_to_bytes(b64_str: str) -> Optional[bytes]:
    try:
        padded = b64_str + "=" * (-len(b64_str) % 4)
        return base64.b64decode(padded)
    except Exception:
        return None


def _is_printable(data: bytes, threshold: float = 0.65) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold


def _rc4(key: bytes, data: bytes) -> bytes:
    """Pure-Python RC4 (ARCFOUR) implementation."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    out = bytearray(len(data))
    for idx in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[idx] = data[idx] ^ S[(S[i] + S[j]) % 256]
    return bytes(out)


def _try_aes_decrypt(key: bytes, data: bytes, iv: Optional[bytes] = None) -> Optional[str]:
    """Try AES decryption in CBC and ECB modes."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as aes_padding
    except ImportError:
        return None

    if len(key) not in (16, 24, 32):
        return None
    if len(data) < 16 or len(data) % 16 != 0:
        return None

    # Try CBC with provided IV or first 16 bytes as IV
    for mode_iv in (iv, data[:16] if iv is None else None):
        if mode_iv is None:
            continue
        if len(mode_iv) != 16:
            continue
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(mode_iv))
            decryptor = cipher.decryptor()
            ciphertext = data[16:] if iv is None and mode_iv == data[:16] else data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            # Try PKCS7 unpadding
            try:
                unpadder = aes_padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(plaintext) + unpadder.finalize()
            except Exception:
                pass
            if _is_printable(plaintext):
                return plaintext.decode("utf-8", errors="replace")
        except Exception:
            continue

    # Try ECB
    try:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(data) + decryptor.finalize()
        try:
            unpadder = aes_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        except Exception:
            pass
        if _is_printable(plaintext):
            return plaintext.decode("utf-8", errors="replace")
    except Exception:
        pass

    return None


def _try_rc4_decrypt(key: bytes, data: bytes) -> Optional[str]:
    """Try RC4 decryption."""
    if len(key) < 1 or len(data) < 4:
        return None
    try:
        plaintext = _rc4(key, data)
        if _is_printable(plaintext):
            return plaintext.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _extract_keys(code: str) -> List[Tuple[str, bytes]]:
    """Extract potential encryption keys from code.

    Now also tries:
    - Cross-variable assembly: key = part1 + part2
    - Passphrase-based derivation: SHA-256/MD5 hash of a password string
    - Raw string keys (password-based encryption)
    """
    keys: List[Tuple[str, bytes]] = []
    seen: set = set()

    # Direct hex key literals
    for m in _HEX_KEY_RE.finditer(code):
        raw = _hex_to_bytes(m.group(1))
        if raw not in seen and len(raw) in (16, 24, 32):
            keys.append(("hex", raw))
            seen.add(raw)

    # Byte array keys
    for m in _BYTE_KEY_RE.finditer(code):
        raw = _byte_array_to_bytes(m.group(1))
        if raw not in seen and len(raw) in (16, 24, 32):
            keys.append(("byte_array", raw))
            seen.add(raw)

    # Base64 key literals
    for m in _B64_KEY_RE.finditer(code):
        raw = _b64_to_bytes(m.group(1))
        if raw and raw not in seen and len(raw) in (16, 24, 32):
            keys.append(("base64", raw))
            seen.add(raw)

    # Cross-variable hex key assembly: key = "1234" + "5678" + ...
    concat_key_re = re.compile(
        r"""(?:key|secret|password|aes_?key)\s*[=:]\s*"""
        r"""["']([0-9a-fA-F]+)["']\s*\+\s*["']([0-9a-fA-F]+)["']"""
        r"""(?:\s*\+\s*["']([0-9a-fA-F]+)["'])?"""
        r"""(?:\s*\+\s*["']([0-9a-fA-F]+)["'])?""",
        re.IGNORECASE,
    )
    for m in concat_key_re.finditer(code):
        combined = "".join(g for g in m.groups() if g)
        if len(combined) in (32, 48, 64):  # 16, 24, or 32 bytes
            raw = _hex_to_bytes(combined)
            if raw not in seen:
                keys.append(("concat_hex", raw))
                seen.add(raw)

    # Passphrase-based key derivation: derive keys from password strings
    # Common pattern: key = hashlib.sha256(password).digest()[:16]
    pass_re = re.compile(
        r"""(?:password|passphrase|secret|passwd)\s*[=:]\s*["']([^'"]{4,64})["']""",
        re.IGNORECASE,
    )
    for m in pass_re.finditer(code):
        passphrase = m.group(1).encode("utf-8")
        import hashlib
        # Try SHA-256 truncated to 16/32 bytes (most common)
        sha256 = hashlib.sha256(passphrase).digest()
        for key_len in (16, 32):
            derived = sha256[:key_len]
            if derived not in seen:
                keys.append(("sha256_derived", derived))
                seen.add(derived)
        # Try MD5 (16 bytes, common in older malware)
        md5 = hashlib.md5(passphrase).digest()
        if md5 not in seen:
            keys.append(("md5_derived", md5))
            seen.add(md5)

    return keys


def _extract_iv(code: str) -> Optional[bytes]:
    """Extract IV/nonce if present."""
    for m in _IV_RE.finditer(code):
        val = m.group(1)
        if len(val) == 32:  # hex
            return _hex_to_bytes(val)
        raw = _b64_to_bytes(val)
        if raw and len(raw) == 16:
            return raw
    return None


class CryptoDecryptor(BaseTransform):
    """Detect hardcoded AES/RC4 keys and decrypt payloads in source code."""

    name = "crypto_decryptor"
    description = "Extract hardcoded AES/RC4 keys and decrypt encrypted payloads."

    def can_apply(self, code: str, language: str, state: dict) -> bool:
        if not code or len(code) < 20:
            return False
        if not _CRYPTO_CONTEXT_RE.search(code):
            return False
        # Check for any key source: hex, byte array, base64, or passphrase
        has_key = bool(
            _HEX_KEY_RE.search(code)
            or _BYTE_KEY_RE.search(code)
            or _B64_KEY_RE.search(code)
            or re.search(r'(?:password|passphrase|secret|passwd)\s*[=:]\s*["\']', code, re.IGNORECASE)
        )
        return has_key

    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        keys = _extract_keys(code)
        if not keys:
            return TransformResult(
                success=False, output=code, confidence=0.1,
                description="No encryption keys found in code.",
                details={},
            )

        iv = _extract_iv(code)
        decrypted_items: List[Dict[str, Any]] = []
        new_code = code

        # Find encrypted payloads and try each key
        payloads: List[Tuple[re.Match, bytes]] = []

        for m in _ENCRYPTED_PAYLOAD_RE.finditer(code):
            raw = _b64_to_bytes(m.group(1))
            if raw and len(raw) >= 16:
                payloads.append((m, raw))

        # CryptoJS pattern (key is passphrase, may need hashing)
        for m in _CRYPTOJS_RE.finditer(code):
            raw = _b64_to_bytes(m.group(1))
            passphrase = m.group(2).encode("utf-8")
            if raw:
                # CryptoJS with passphrase uses OpenSSL key derivation
                # Try direct passphrase as key (common in simple usage)
                for try_key in [passphrase[:16], passphrase[:24], passphrase[:32]]:
                    if len(try_key) in (16, 24, 32):
                        result = _try_aes_decrypt(try_key, raw, iv)
                        if result:
                            decrypted_items.append({
                                "method": "CryptoJS.AES",
                                "key_format": "passphrase",
                                "plaintext": result[:500],
                            })
                            new_code = new_code.replace(m.group(0), f'"{result[:200]}"')
                            break

        # Try all key/payload combinations
        for m, raw_payload in payloads:
            for key_fmt, key_bytes in keys:
                # Try AES
                result = _try_aes_decrypt(key_bytes, raw_payload, iv)
                if result:
                    decrypted_items.append({
                        "method": "AES",
                        "key_format": key_fmt,
                        "key_length": len(key_bytes) * 8,
                        "plaintext": result[:500],
                    })
                    new_code = new_code.replace(
                        m.group(1), result[:200]
                    )
                    break

                # Try RC4
                result = _try_rc4_decrypt(key_bytes, raw_payload)
                if result:
                    decrypted_items.append({
                        "method": "RC4",
                        "key_format": key_fmt,
                        "key_length": len(key_bytes) * 8,
                        "plaintext": result[:500],
                    })
                    new_code = new_code.replace(
                        m.group(1), result[:200]
                    )
                    break

        success = len(decrypted_items) > 0
        confidence = min(0.5 + len(decrypted_items) * 0.1, 0.9) if success else 0.2
        return TransformResult(
            success=success,
            output=new_code if success else code,
            confidence=confidence,
            description=(
                f"Decrypted {len(decrypted_items)} payload(s) using extracted keys "
                f"({len(keys)} key(s) found)."
                if success else
                f"Found {len(keys)} key(s) but could not decrypt any payloads."
            ),
            details={
                "keys_found": len(keys),
                "decrypted_count": len(decrypted_items),
                "items": decrypted_items[:10],
                "detected_techniques": (
                    ["aes_encryption"] if any(d["method"] == "AES" for d in decrypted_items)
                    else ["rc4_encryption"] if any(d["method"] == "RC4" for d in decrypted_items)
                    else ["symmetric_encryption"]
                ) if success else [],
                "decoded_strings": [
                    {"encoded": "encrypted_payload", "decoded": d["plaintext"]}
                    for d in decrypted_items[:5]
                ],
            },
        )
