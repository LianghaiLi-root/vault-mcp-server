#!/usr/bin/env python3
"""
stdio.py — local stdio MCP server (single-user / agent use).

This is the classic stdio transport: the MCP client launches this as a
subprocess and talks JSON-RPC over stdin/stdout. It uses the global vault
namespace (or VAULT_USER if set) and the same encrypted store as the web/deployable
server, so credentials are shared across both front-ends.

Tools: vault_save / vault_get / vault_describe / vault_list / vault_delete

Behaviour deliberately matches the remote server's tool layer (same argument
names, same field-aware reads, same write validation) so a credential behaves
identically whichever transport an agent happens to use. The type rules
themselves live in credtypes.py, shared with server.py — nothing is duplicated
here.
"""

import os
import json
from . import vault_core as V
from .credtypes import blank, describe_fields, missing_fields, validate_fields
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vault-mcp")


def _ns():
    return os.environ.get("VAULT_USER")  # None -> global namespace


@mcp.tool()
def vault_save(name: str, value: str = "", note: str = "", type: str = "generic",
               fields: dict = None) -> str:
    """Save or update a credential in the local encrypted vault.

    `fields` is the structured form, e.g.
    `{"host": "10.0.0.1", "port": "22", "username": "root", "password": "..."}`;
    `value` is the primary secret and may be omitted when `fields` carries it.
    An unknown type, an unknown field name or a missing required field returns
    `ERROR: ...` and saves nothing.
    """
    try:
        f = dict(fields) if fields else {}
        prim = V.PRIMARY_FIELD.get(type, "value")
        if not blank(value) and blank(f.get(prim)):
            f[prim] = value
        problem = validate_fields(type, f)
        if problem:
            return f"ERROR: {problem}"
        r = V.save_credential(_ns(), name, type, f, note)
        gaps = missing_fields(type, f)
        tail = "" if not gaps else " Incomplete: missing %s." % gaps
        return f"Saved credential '{r['name']}' (type={r['type']}).{tail}"
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_get(name: str, field: str | None = None) -> str:
    """Retrieve the primary secret, or one named field of a credential.

    Without `field` the type's primary secret (password / token / value) is
    returned. With `field` — `host`, `port`, `username`, ... — that field is
    returned verbatim; use vault_describe to discover the available keys.
    """
    try:
        if field is None:
            return V.get_credential(_ns(), name)
        rec = V.load_record(_ns(), name)
        fields = rec["fields"]
        if field not in fields:
            return ("ERROR: '%s' has no field '%s'. Available fields: %s"
                    % (name, field, ", ".join(fields) or "(none)"))
        val = fields.get(field)
        if blank(val):
            return "ERROR: field '%s' of '%s' is empty." % (field, name)
        return str(val)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_describe(name: str) -> str:
    """Describe a credential's shape without disclosing its secrets.

    Returns JSON: type, note, timestamps, a per-field map (value for non-secret
    fields, length only for secrets), plus `missing` and `complete`.
    """
    try:
        rec = V.load_record(_ns(), name)
    except Exception as e:
        return f"ERROR: {e}"
    type_ = rec.get("type", "generic")
    fields = rec["fields"]
    missing = missing_fields(type_, fields)
    return json.dumps({
        "name": rec["name"],
        "type": type_,
        "note": rec.get("note", ""),
        "created": rec.get("created", ""),
        "updated": rec.get("updated", ""),
        "fields": describe_fields(type_, fields),
        "missing": missing,
        "complete": not missing,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
def vault_list() -> str:
    """List stored credentials with their field keys and completeness. Never
    returns a secret."""
    try:
        items = []
        for item in V.list_credentials(_ns()):
            try:
                fields = V.load_record(_ns(), item["name"])["fields"]
                missing = missing_fields(item["type"], fields)
            except Exception as e:
                fields, missing = {}, ["<unreadable: %s>" % e]
            items.append({**item, "fields": list(fields),
                          "complete": not missing, "missing": missing})
        return json.dumps(items, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_delete(name: str) -> str:
    """Delete a credential by name."""
    try:
        if V.delete_credential(_ns(), name):
            return f"Deleted credential '{name}'."
        return f"ERROR: '{name}' not found."
    except Exception as e:
        return f"ERROR: {e}"


if __name__ == "__main__":
    mcp.run()
