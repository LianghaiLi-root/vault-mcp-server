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


def load_config(path: str | None = None) -> dict:
    path = path or os.environ.get("VAULT_CONFIG", "config.yaml")
    with open(path, "r", encoding="utf-8") as f:
        if yaml is not None and path.endswith((".yaml", ".yml")):
            return yaml.safe_load(f) or {}
        return json.load(f)


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
