#!/usr/bin/env python3
"""
config.py — load server configuration (YAML preferred, JSON fallback).

The config file is where an operator pre-provisions users. Example:

    vault:
      dir: /var/lib/vault-mcp/vault
      force_pbkdf2: true          # required on Linux
    server:
      host: 0.0.0.0
      port: 8080
    users:
      - username: admin
        password_hash: "scrypt$16384$8$1$<salt>$<hash>"
        mcp_token: "<long-random-token>"   # used by remote MCP clients
        totp_secret: null                  # set after 2FA enrollment
"""

import os
import json
import hmac
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def _default_vault_dir() -> str:
    return os.environ.get(
        "VAULT_DIR",
        os.path.join(os.path.expanduser("~"), ".workbuddy", "vault"),
    )


def _users_state_path() -> Path:
    return Path(_default_vault_dir()) / ".users_state.json"


def config_path(path: str | None = None) -> str:
    return path or os.environ.get("VAULT_CONFIG", "config.yaml")


def load_config(path: str | None = None) -> dict:
    path = config_path(path)
    with open(path, "r", encoding="utf-8") as f:
        if yaml is not None and path.endswith((".yaml", ".yml")):
            return yaml.safe_load(f) or {}
        return json.load(f)


def save_config(cfg: dict, path: str | None = None) -> None:
    """Atomically rewrite the operator config (used by admin user management)."""
    path = config_path(path)
    is_yaml = yaml is not None and path.endswith((".yaml", ".yml"))
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        if is_yaml:
            yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)
        else:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def add_or_update_user(cfg: dict, username: str, password_hash: str,
                       mcp_token: str | None = None, role: str | None = None) -> dict:
    """Insert or replace a user record in-place; returns the record."""
    users = cfg.setdefault("users", [])
    for u in users:
        if u.get("username") == username:
            u["password_hash"] = password_hash
            if mcp_token:
                u["mcp_token"] = mcp_token
            if role:
                u["role"] = normalize_role(role)
            return u
    rec = {"username": username, "password_hash": password_hash,
           "mcp_token": mcp_token or "", "role": normalize_role(role),
           "totp_secret": None}
    users.append(rec)
    return rec


def rename_user(cfg: dict, old: str, new: str) -> bool:
    """Change a user's username in-place. Returns False if `old` is unknown."""
    for u in get_users(cfg):
        if u.get("username") == old:
            u["username"] = new
            return True
    return False


# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------
# `admin`  — the single super-user: may rename itself, add/rename/delete other
#            users, and see the whole user list.
# `user`   — an ordinary account: may only manage itself. It must NEVER learn
#            that other users exist, so anything user-scoped is filtered by the
#            caller's own namespace and the user list is never rendered.
ROLE_ADMIN = "admin"
ROLE_USER = "user"


def normalize_role(role: str | None) -> str:
    return ROLE_ADMIN if str(role or "").strip().lower() == ROLE_ADMIN else ROLE_USER


def user_role(cfg: dict, username: str) -> str:
    u = find_user(cfg, username)
    return normalize_role(u.get("role") if u else None)


def is_admin(cfg: dict, username: str) -> bool:
    return user_role(cfg, username) == ROLE_ADMIN


def admin_count(cfg: dict) -> int:
    return sum(1 for u in get_users(cfg) if normalize_role(u.get("role")) == ROLE_ADMIN)


def set_user_role(cfg: dict, username: str, role: str) -> bool:
    for u in get_users(cfg):
        if u.get("username") == username:
            u["role"] = normalize_role(role)
            return True
    return False


# --------------------------------------------------------------------------
# Web hardening (admin-managed, persisted in config.yaml under `security`)
# --------------------------------------------------------------------------
DEFAULT_SECURITY = {
    # Reject HTTP requests that did not pass through a Cloudflare Access policy.
    # When on, every request must carry the Cloudflare Access JWT header (or the
    # CF_Authorization cookie) — i.e. the edge already authenticated the visitor.
    "require_cloudflare_access": False,
    # User-defined extra header the edge must inject (e.g. a shared secret set by
    # an nginx `add_header X-Edge-Secret ...` rule). Empty = not enforced.
    "required_edge_header": "",
    "required_edge_header_value": "",
    # Force the session cookie to be Secure (only meaningful behind HTTPS).
    "force_secure_cookie": False,
    # Simple in-process login throttle.
    "login_max_failures": 8,
    "login_lockout_seconds": 300,
}


def security_settings(cfg: dict) -> dict:
    s = dict(DEFAULT_SECURITY)
    s.update(cfg.get("security", {}) or {})
    return s


# --------------------------------------------------------------------------
# Human verification on the login form (admin-managed, config.yaml `captcha`)
# --------------------------------------------------------------------------
DEFAULT_CAPTCHA = {
    # off | numeric | image | turnstile
    "mode": "off",
    # number of glyphs for the image-based modes (3-8)
    "length": 4,
    # Cloudflare Turnstile credentials. Both are REQUIRED before mode may be
    # switched to "turnstile" — enforced by validate_captcha() below.
    "turnstile_site_key": "",
    "turnstile_secret_key": "",
}

CAPTCHA_MODES = ("off", "numeric", "image", "turnstile")


def captcha_settings(cfg: dict) -> dict:
    c = dict(DEFAULT_CAPTCHA)
    c.update(cfg.get("captcha", {}) or {})
    return c


def validate_captcha(payload: dict, current: dict) -> tuple[dict | None, str]:
    """Validate an admin-supplied captcha config.

    Returns (settings, "") on success or (None, error_message) on rejection.
    An empty `turnstile_secret_key` means "keep the stored one" so the secret
    never has to be re-sent from the browser; pass clear_secret=true to wipe it.
    """
    mode = str(payload.get("mode") or "off").strip().lower()
    if mode not in CAPTCHA_MODES:
        return None, f"未知的验证方式: {mode}"

    try:
        length = int(payload.get("length") or 4)
    except (TypeError, ValueError):
        return None, "验证码长度必须是数字"
    if not 3 <= length <= 8:
        return None, "验证码长度需在 3–8 之间"

    site = str(payload.get("turnstile_site_key") or "").strip()
    secret = str(payload.get("turnstile_secret_key") or "").strip()
    if payload.get("clear_secret"):
        secret = ""
    elif not secret:
        secret = str(current.get("turnstile_secret_key") or "")

    # The whole point of the feature: an automatic (Cloudflare) challenge cannot
    # work without credentials, so refuse to enable it half-configured.
    if mode == "turnstile":
        missing = [n for n, v in (("Site Key", site), ("Secret Key", secret)) if not v]
        if missing:
            return None, "启用 Cloudflare Turnstile 前必须填写 " + " 与 ".join(missing)

    return {"mode": mode, "length": length,
            "turnstile_site_key": site, "turnstile_secret_key": secret}, ""


def set_password_hash(cfg: dict, username: str, password_hash: str) -> bool:
    for u in get_users(cfg):
        if u.get("username") == username:
            u["password_hash"] = password_hash
            return True
    return False


def set_user_token(cfg: dict, username: str, token: str) -> bool:
    for u in get_users(cfg):
        if u.get("username") == username:
            u["mcp_token"] = token
            return True
    return False


def delete_user(cfg: dict, username: str) -> bool:
    users = get_users(cfg)
    keep = [u for u in users if u.get("username") != username]
    if len(keep) == len(users):
        return False
    cfg["users"] = keep
    return True


def get_users(cfg: dict) -> list:
    return cfg.get("users", []) or []


def find_user(cfg: dict, username: str) -> dict | None:
    for u in get_users(cfg):
        if u.get("username") == username:
            return u
    return None


def server_settings(cfg: dict) -> dict:
    return cfg.get("server", {}) or {}


def find_user_by_token(cfg: dict, token: str) -> str | None:
    if not token:
        return None
    for u in get_users(cfg):
        if u.get("mcp_token") and hmac.compare_digest(str(u["mcp_token"]), str(token)):
            return u.get("username")
    return None


# --------------------------------------------------------------------------
# Per-user runtime state (2FA secret etc.) — separate from the operator's
# config.yaml so web-enrolled 2FA doesn't require hand-editing the config.
# --------------------------------------------------------------------------
def load_user_state(username: str) -> dict:
    p = _users_state_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data.get(username, {})


def save_user_state(username: str, patch: dict) -> None:
    p = _users_state_path()
    data = {}
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    data[username] = {**load_user_state(username), **patch}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        p.chmod(0o600)
    except Exception:
        pass


def clear_user_state(username: str) -> None:
    """Drop a user's runtime state (used to reset 2FA when a user is removed)."""
    p = _users_state_path()
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return
    if username in data:
        del data[username]
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def rename_user_state(old: str, new: str) -> None:
    """Move a user's runtime state (2FA secret etc.) to the new username."""
    p = _users_state_path()
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return
    if old in data:
        data[new] = data.pop(old)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
