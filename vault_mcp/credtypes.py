#!/usr/bin/env python3
"""
credtypes.py — credential type catalog and shape rules.

Shared by all three front-ends (web console, remote MCP server, local stdio
server) so they agree on what a credential of a given type looks like, which of
its fields are secret, and what counts as a complete record.

This lives outside server.py on purpose: importing that module builds the
FastAPI app and loads the operator config as a side effect, which a stdio-only
client has no business doing.
"""

# --------------------------------------------------------------------------
# Credential type catalog — drives the web form, the /api/types schema and the
# MCP read path. Each field: key, label, kind (text|password|textarea),
# secret (bool), default. Add new common types here; the UI renders them
# automatically.
# --------------------------------------------------------------------------
CRED_TYPES = {
    "generic": {
        "label": "通用 / 密码",
        "fields": [
            {"key": "value", "label": "秘密 / 密码", "kind": "textarea", "secret": True},
        ],
    },
    "ssh": {
        "label": "SSH 服务器",
        "fields": [
            {"key": "host", "label": "主机 / IP", "kind": "text", "secret": False},
            {"key": "port", "label": "端口", "kind": "text", "secret": False, "default": "22"},
            {"key": "username", "label": "用户名", "kind": "text", "secret": False},
            {"key": "password", "label": "密码", "kind": "password", "secret": True},
            {"key": "private_key", "label": "私钥", "kind": "textarea", "secret": True},
        ],
    },
    "web": {
        "label": "网站 / 账号",
        "fields": [
            {"key": "url", "label": "网址 URL", "kind": "text", "secret": False},
            {"key": "username", "label": "用户名 / 邮箱", "kind": "text", "secret": False},
            {"key": "password", "label": "密码", "kind": "password", "secret": True},
        ],
    },
    "api": {
        "label": "API / Token",
        "fields": [
            {"key": "token", "label": "Token / API Key", "kind": "textarea", "secret": True},
            {"key": "url", "label": "接口地址 URL", "kind": "text", "secret": False},
        ],
    },
    "db": {
        "label": "数据库",
        "fields": [
            {"key": "host", "label": "主机", "kind": "text", "secret": False},
            {"key": "port", "label": "端口", "kind": "text", "secret": False},
            {"key": "database", "label": "数据库名", "kind": "text", "secret": False},
            {"key": "username", "label": "用户名", "kind": "text", "secret": False},
            {"key": "password", "label": "密码", "kind": "password", "secret": True},
        ],
    },
}
TYPE_LABELS = {k: v["label"] for k, v in CRED_TYPES.items()}

# Minimum a credential needs to be usable at all — enforced on write, so a
# record can never land in a shape the read path cannot serve.
REQUIRED_FIELDS = {
    "generic": ("value",),
    "ssh": ("host",),
    "web": ("url",),
    "api": ("token",),
    "db": ("host",),
}

# What "complete" means for a type — reported by vault_list / vault_describe.
# SSH is special-cased below: password OR private_key fills the auth slot.
COMPLETE_FIELDS = {
    "generic": ("value",),
    "ssh": ("host", "port", "username"),
    "web": ("url", "username", "password"),
    "api": ("token",),
    "db": ("host", "port", "database", "username", "password"),
}


def type_spec(type_: str) -> dict:
    spec = CRED_TYPES.get(type_)
    if not spec:
        raise ValueError(
            "unknown credential type '%s'; valid types: %s"
            % (type_, ", ".join(sorted(CRED_TYPES))))
    return spec


def field_keys(type_: str) -> list:
    return [f["key"] for f in type_spec(type_)["fields"]]


def secret_keys(type_: str) -> set:
    return {f["key"] for f in type_spec(type_)["fields"] if f.get("secret")}


def blank(v) -> bool:
    return v is None or (isinstance(v, str) and not v.strip())


def missing_fields(type_: str, fields: dict) -> list:
    """Keys the type expects for a usable record but which hold no value."""
    if type_ not in CRED_TYPES:
        return []          # unknown type: nothing sensible to expect
    expected = COMPLETE_FIELDS.get(type_) or tuple(field_keys(type_))
    missing = [k for k in expected if blank(fields.get(k))]
    if type_ == "ssh" and blank(fields.get("password")) \
            and blank(fields.get("private_key")):
        missing.append("password|private_key")
    return missing


def describe_fields(type_: str, fields: dict) -> dict:
    """Per-field report. Secrets are represented by length only, never a value."""
    known = set(field_keys(type_)) if type_ in CRED_TYPES else set()
    secrets = secret_keys(type_) if type_ in CRED_TYPES else set()
    out = {}
    for k, v in fields.items():
        if blank(v):
            out[k] = {"stored": False}
        elif k in secrets or k not in known:
            # Unknown/custom keys are treated as secret: we cannot prove they
            # are safe to echo, and vault_get(name, field=...) can still read them.
            out[k] = {"stored": True, "secret": True, "length": len(str(v))}
        else:
            out[k] = {"stored": True, "secret": False, "value": v}
    return out


def validate_fields(type_: str, fields: dict) -> str | None:
    """Return a human-readable problem description, or None when the shape is OK.

    Callers prefix their own `ERROR: ` so the wording stays identical across the
    web API, the remote MCP server and the stdio server.
    """
    try:
        type_spec(type_)
    except ValueError as e:
        return str(e)
    unknown = [k for k in fields if k not in field_keys(type_)]
    if unknown:
        return ("unknown field(s) %s for type '%s'. Allowed: %s"
                % (unknown, type_, field_keys(type_)))
    missing = [k for k in REQUIRED_FIELDS.get(type_, ()) if blank(fields.get(k))]
    if missing:
        return ("missing required field(s) %s for type '%s' — nothing was saved."
                % (missing, type_))
    return None
