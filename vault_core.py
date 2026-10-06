#!/usr/bin/env python3
"""
vault_core.py — encrypted credential storage (multi-user, portable).

Security model
--------------
* Master key:
    - Windows (default): OS-native DPAPI (CryptProtectData). Zero-config, bound
      to the current Windows user account.
    - Linux / forced (VAULT_FORCE_PBKDF2=1): PBKDF2-HMAC-SHA256 of
      VAULT_MASTER_PASSWORD (600k iters) -> KEK. The server holds the master
      password, so a trusted server can decrypt every user's vault. This is the
      intended mode for a remote/deployable deployment.
* Per record: AES-256-GCM, random 12-byte nonce.
* Per user (namespace): a random 256-bit DEK, wrapped (encrypted) by the master
  key. Only the wrapped DEK is persisted under each user's directory, so users
  are isolated on disk. Access control (who may open which namespace) is enforced
  by the server layer, not here.

On-disk layout (under VAULT_DIR):
    <ns>/meta.json            # {mode, wrapped_dek}
    <ns>/secrets/<slug>.json  # {name, note, created, updated, blob}
    .kek_salt                 # random salt for PBKDF2 KEK (pbkdf2 mode only)
"""

import os
import sys
import json
import base64
import hashlib
import logging
import ctypes
import ctypes.wintypes
from pathlib import Path
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vault")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_DIR = Path(os.environ.get(
    "VAULT_DIR",
    os.path.join(os.path.expanduser("~"), ".workbuddy", "vault"),
))
FORCE_PBKDF2 = os.environ.get("VAULT_FORCE_PBKDF2") == "1"
PBKDF2_ITERS = int(os.environ.get("VAULT_PBKDF2_ITERS", "600000"))
GLOBAL_NS = "__global__"


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


# --------------------------------------------------------------------------
# Windows DPAPI (zero-config OS-native keychain)
# --------------------------------------------------------------------------
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_protect(data: bytes) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    out = _DATA_BLOB()
    if ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(_DATA_BLOB(len(data), buf)), None, None, None, None, 0,
            ctypes.byref(out)) == 0:
        raise ctypes.WinError()
    return ctypes.string_at(out.pbData, out.cbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    out = _DATA_BLOB()
    if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(_DATA_BLOB(len(data), buf)), None, None, None, None, 0,
            ctypes.byref(out)) == 0:
        raise ctypes.WinError()
    return ctypes.string_at(out.pbData, out.cbData)


def _dpapi_available() -> bool:
    return sys.platform == "win32" and not FORCE_PBKDF2


# --------------------------------------------------------------------------
# PBKDF2 KEK (Linux / forced)
# --------------------------------------------------------------------------
def _kek_salt_path() -> Path:
    return VAULT_DIR / ".kek_salt"


def _kek() -> bytes:
    pw = os.environ.get("VAULT_MASTER_PASSWORD")
    if not pw:
        raise RuntimeError(
            "VAULT_MASTER_PASSWORD is required in PBKDF2 mode "
            "(VAULT_FORCE_PBKDF2=1 on non-Windows).")
    salt_path = _kek_salt_path()
    if not salt_path.exists():
        salt_path.write_bytes(os.urandom(16))
        salt_path.chmod(0o600)
    salt = salt_path.read_bytes()
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=PBKDF2_ITERS).derive(pw.encode())


# --------------------------------------------------------------------------
# Per-namespace vault state
# --------------------------------------------------------------------------
_VAULTS: dict = {}


def open_vault(namespace: str | None = None) -> dict:
    ns = namespace or GLOBAL_NS
    if ns in _VAULTS:
        return _VAULTS[ns]

    base = VAULT_DIR if namespace is None else (VAULT_DIR / namespace)
    secrets_dir = base / "secrets"
    meta_path = base / "meta.json"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta["mode"] == "dpapi":
            dek = _dpapi_unprotect(_b64d(meta["wrapped_dek"]))
        else:
            dek = _aes_gcm_decrypt(_kek(), _b64d(meta["wrapped_dek"]))
    else:
        dek = os.urandom(32)
        if _dpapi_available():
            wrapped = _dpapi_protect(dek)
            meta = {"mode": "dpapi", "wrapped_dek": _b64e(wrapped)}
        else:
            wrapped = _aes_gcm_encrypt(_kek(), dek)
            meta = {"mode": "pbkdf2", "wrapped_dek": _b64e(wrapped)}
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        meta_path.chmod(0o600)

    state = {"ns": ns, "dek": dek, "meta": meta,
             "dir": base, "secrets": secrets_dir}
    _VAULTS[ns] = state
    log.info("Vault '%s' opened in '%s' mode", ns, meta["mode"])
    return state


def vault_mode(namespace: str | None = None) -> str:
    return open_vault(namespace)["meta"]["mode"]


def _slug(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]


def _secret_path(v: dict, name: str) -> Path:
    return v["secrets"] / f"{_slug(name)}.json"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------
def save_credential(namespace: str | None, name: str, value: str, note: str = "") -> dict:
    v = open_vault(namespace)
    path = _secret_path(v, name)
    created = _ts()
    if path.exists():
        created = json.loads(path.read_text(encoding="utf-8")).get("created", created)
    blob = _aes_gcm_encrypt(v["dek"], value.encode("utf-8"))
    rec = {"name": name, "note": note, "created": created,
           "updated": _ts(), "blob": _b64e(blob)}
    path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return {"name": name, "note": note, "created": created, "updated": rec["updated"]}


def get_credential(namespace: str | None, name: str) -> str:
    v = open_vault(namespace)
    path = _secret_path(v, name)
    if not path.exists():
        raise KeyError(f"credential '{name}' not found")
    rec = json.loads(path.read_text(encoding="utf-8"))
    return _aes_gcm_decrypt(v["dek"], _b64d(rec["blob"])).decode("utf-8")


def list_credentials(namespace: str | None) -> list:
    v = open_vault(namespace)
    items = []
    for f in v["secrets"].glob("*.json"):
        rec = json.loads(f.read_text(encoding="utf-8"))
        items.append({"name": rec["name"], "note": rec.get("note", ""),
                      "created": rec.get("created", ""),
                      "updated": rec.get("updated", "")})
    return items


def delete_credential(namespace: str | None, name: str) -> bool:
    v = open_vault(namespace)
    path = _secret_path(v, name)
    if not path.exists():
        return False
    path.unlink()
    return True
