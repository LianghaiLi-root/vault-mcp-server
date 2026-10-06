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


def rename_namespace(old: str, new: str) -> bool:
    """Rename a user's vault directory so credentials follow the account.

    The data-encryption key is wrapped inside that directory, so moving the
    whole tree preserves it — no re-encryption needed. Returns False when the
    source has no on-disk vault yet (nothing to move).
    """
    if not old or not new or old == new:
        return False
    src = VAULT_DIR / old
    dst = VAULT_DIR / new
    if not src.exists():
        return src.exists() and False
    if dst.exists():
        raise FileExistsError(f"目标命名空间已存在: {new}")
    # Drop any cached handle so later reads reopen from the new path.
    _VAULTS.pop(old, None)
    _VAULTS.pop(new, None)
    src.rename(dst)
    return True


def _slug(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]


def _secret_path(v: dict, name: str) -> Path:
    return v["secrets"] / f"{_slug(name)}.json"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------
# Primary secret field per type — returned by get_credential() for AI tools
# (vault_get / vault_http use this so the "main" secret is what the model sees).
PRIMARY_FIELD = {
    "generic": "value",
    "ssh": "password",
    "web": "password",
    "api": "token",
    "db": "password",
}


def _encrypt_fields(dek: bytes, fields: dict) -> str:
    pt = json.dumps(fields, ensure_ascii=False).encode("utf-8")
    return _b64e(_aes_gcm_encrypt(dek, pt))


def _decrypt_fields(dek: bytes, blob_b64: str) -> dict:
    pt = _aes_gcm_decrypt(dek, _b64d(blob_b64))
    try:
        obj = json.loads(pt.decode("utf-8"))
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    # Legacy record: a raw string was stored as the secret -> generic shape.
    return {"value": pt.decode("utf-8")}


def save_credential(namespace: str | None, name: str, type_: str,
                   fields: dict, note: str = "") -> dict:
    """Persist a credential of a given `type_` with a dict of `fields`.

    Non-secret fields (host, port, url, ...) and secret fields are all stored
    inside the single AES-256-GCM `blob`; only `name`, `type` and `note` stay
    in plaintext metadata so the list view never exposes values.
    """
    v = open_vault(namespace)
    path = _secret_path(v, name)
    created = _ts()
    if path.exists():
        created = json.loads(path.read_text(encoding="utf-8")).get("created", created)
    rec = {
        "name": name,
        "type": type_,
        "note": note,
        "created": created,
        "updated": _ts(),
        "blob": _encrypt_fields(v["dek"], fields),
    }
    path.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"name": name, "type": type_, "note": note,
            "created": created, "updated": rec["updated"]}


def load_record(namespace: str | None, name: str) -> dict:
    """Return the full record with decrypted `fields` (for editing)."""
    v = open_vault(namespace)
    path = _secret_path(v, name)
    if not path.exists():
        raise KeyError(f"credential '{name}' not found")
    rec = json.loads(path.read_text(encoding="utf-8"))
    return {
        "name": rec["name"],
        "type": rec.get("type", "generic"),
        "note": rec.get("note", ""),
        "fields": _decrypt_fields(v["dek"], rec["blob"]),
        "created": rec.get("created", ""),
        "updated": rec.get("updated", ""),
    }


def get_fields(namespace: str | None, name: str) -> dict:
    return load_record(namespace, name)["fields"]


def get_credential(namespace: str | None, name: str) -> str:
    """Return the primary secret of a credential (for AI tools / vault_http)."""
    r = load_record(namespace, name)
    f = r["fields"]
    prim = PRIMARY_FIELD.get(r["type"], "value")
    if f.get(prim) not in (None, ""):
        return f[prim]
    for val in f.values():          # fallback: first non-empty field
        if val not in (None, ""):
            return val
    return ""


def list_credentials(namespace: str | None) -> list:
    v = open_vault(namespace)
    items = []
    for p in v["secrets"].glob("*.json"):
        rec = json.loads(p.read_text(encoding="utf-8"))
        items.append({
            "name": rec.get("name"),
            "type": rec.get("type", "generic"),
            "note": rec.get("note", ""),
            "created": rec.get("created", ""),
            "updated": rec.get("updated", ""),
        })
    return items


def delete_credential(namespace: str | None, name: str) -> bool:
    v = open_vault(namespace)
    path = _secret_path(v, name)
    if not path.exists():
        return False
    path.unlink()
    return True
