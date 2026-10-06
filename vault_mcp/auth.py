#!/usr/bin/env python3
"""
auth.py — password hashing, TOTP (RFC 6238) and session tokens.

All primitives are from the standard library so the project stays dependency-light
and auditable. Passwords use scrypt; TOTP uses HMAC-SHA1 (Google Authenticator
compatible); session tokens are HMAC-signed with an expiry.
"""

import os
import time
import hmac
import hashlib
import base64
import struct
import secrets


# --------------------------------------------------------------------------
# Password hashing (scrypt, stdlib)
# --------------------------------------------------------------------------
def hash_password(password: str, salt: bytes | None = None,
                  n: int = 16384, r: int = 8, p: int = 1) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                        n=n, r=r, p=p, dklen=64)
    return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        dk = base64.b64decode(dk_b64)
        test = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                              n=int(n), r=int(r), p=int(p), dklen=64)
        return hmac.compare_digest(test, dk)
    except Exception:
        return False


# --------------------------------------------------------------------------
# TOTP (RFC 6238, Google Authenticator compatible)
# --------------------------------------------------------------------------
def generate_totp_secret() -> str:
    """Return a base32 (RFC 4648, unpadded) 160-bit secret."""
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def totp_uri(secret: str, account: str, issuer: str = "VaultMCP") -> str:
    return (f"otpauth://totp/{issuer}:{account}?secret={secret}"
            f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30")


def _b32decode(secret: str) -> bytes:
    s = secret.upper().replace(" ", "")
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s)


def totp_at(secret: str, for_time: int | None = None,
            period: int = 30, digits: int = 6) -> str:
    for_time = for_time if for_time is not None else int(time.time())
    counter = for_time // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(_b32decode(secret), msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"


def verify_totp(secret: str, code: str, period: int = 30, window: int = 1) -> bool:
    if not secret or not code:
        return False
    code = str(code).strip()
    t = int(time.time())
    for w in range(-window, window + 1):
        if totp_at(secret, t + w * period) == code:
            return True
    return False


# --------------------------------------------------------------------------
# Session tokens (HMAC-signed, expiring)
# --------------------------------------------------------------------------
_SESSION_SECRET = None


def _session_secret() -> bytes:
    global _SESSION_SECRET
    if _SESSION_SECRET is None:
        s = os.environ.get("VAULT_SESSION_SECRET")
        if s:
            _SESSION_SECRET = s.encode("utf-8")
        elif os.environ.get("VAULT_MASTER_PASSWORD"):
            _SESSION_SECRET = hashlib.sha256(
                os.environ["VAULT_MASTER_PASSWORD"].encode("utf-8")).digest()
        else:
            _SESSION_SECRET = os.urandom(32)  # ephemeral; invalid after restart
    return _SESSION_SECRET


def issue_session(username: str, expires_in: int = 3600) -> str:
    exp = int(time.time()) + expires_in
    body = f"{username}.{exp}"
    sig = hmac.new(_session_secret(), body.encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_session(token: str | None) -> str | None:
    if not token:
        return None
    try:
        body, sig = token.rsplit(".", 1)
        username, exp = body.split(".")
        exp = int(exp)
        expect = hmac.new(_session_secret(), body.encode("utf-8"),
                          hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return None
        if int(time.time()) > exp:
            return None
        return username
    except Exception:
        return None


def gen_token(bytes_len: int = 24) -> str:
    return secrets.token_hex(bytes_len)
