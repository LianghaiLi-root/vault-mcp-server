#!/usr/bin/env python3
"""
vault_server.py — local stdio MCP server (single-user / agent use).

This is the classic stdio transport: the MCP client launches this as a
subprocess and talks JSON-RPC over stdin/stdout. It uses the global vault
namespace (or VAULT_USER if set) and the same encrypted store as the web/deployable
server, so credentials are shared across both front-ends.

Tools: vault_save / vault_get / vault_list / vault_delete
"""

import os
import json
from . import vault_core as V
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vault-mcp")


def _ns():
    return os.environ.get("VAULT_USER")  # None -> global namespace


@mcp.tool()
def vault_save(name: str, value: str, note: str = "") -> str:
    """Save or update a credential in the local encrypted vault."""
    try:
        r = V.save_credential(_ns(), name, value, note)
        return f"Saved credential '{r['name']}'."
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_get(name: str) -> str:
    """Retrieve a stored credential value by name (plaintext, for immediate use)."""
    try:
        return V.get_credential(_ns(), name)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_list() -> str:
    """List stored credential names/notes/timestamps (never the values)."""
    try:
        return json.dumps(V.list_credentials(_ns()), ensure_ascii=False, indent=2)
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
