#!/usr/bin/env python3
"""
vault_cli.py — operator tool to provision users in config.yaml.

Users are pre-provisioned here (the web UI lets them enroll 2FA afterwards).
Never commit real password hashes / tokens; use this tool on the server.

Examples
--------
  python vault_cli.py add-user alice
  python vault_cli.py set-token alice
  python vault_cli.py list-users
"""

import os
import sys
import getpass
import argparse

import yaml
import auth
import config as cfgmod


def _load_raw(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _save_raw(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def add_user(path, username):
    data = _load_raw(path)
    users = data.setdefault("users", [])
    pw = getpass.getpass(f"Password for '{username}': ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("Passwords do not match."); sys.exit(1)
    rec = {
        "username": username,
        "password_hash": auth.hash_password(pw),
        "mcp_token": auth.gen_token(32),
        "totp_secret": None,
    }
    users[:] = [u for u in users if u.get("username") != username]
    users.append(rec)
    _save_raw(path, data)
    print(f"Added user '{username}'. mcp_token: {rec['mcp_token']}")


def set_token(path, username):
    data = _load_raw(path)
    for u in data.get("users", []):
        if u.get("username") == username:
            u["mcp_token"] = auth.gen_token(32)
            _save_raw(path, data)
            print(f"New mcp_token for '{username}': {u['mcp_token']}")
            return
    print(f"User '{username}' not found."); sys.exit(1)


def list_users(path):
    data = _load_raw(path)
    state = {}
    sp = cfgmod._users_state_path()
    if sp.exists():
        try:
            state = __import__("json").loads(sp.read_text(encoding="utf-8"))
        except Exception:
            state = {}
    for u in data.get("users", []):
        uname = u.get("username")
        st = state.get(uname, {})
        totp = "enabled" if st.get("totp_confirmed") else ("pending" if st.get("totp_secret") else "off")
        print(f"  - {uname:20s} mcp_token={'set' if u.get('mcp_token') else 'MISSING':7s} 2FA={totp}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", default=os.environ.get("VAULT_CONFIG", "config.yaml"))
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add-user"); a.add_argument("username")
    t = sub.add_parser("set-token"); t.add_argument("username")
    sub.add_parser("list-users")
    args = p.parse_args()

    if args.cmd == "add-user":
        add_user(args.config, args.username)
    elif args.cmd == "set-token":
        set_token(args.config, args.username)
    elif args.cmd == "list-users":
        list_users(args.config)


if __name__ == "__main__":
    main()
