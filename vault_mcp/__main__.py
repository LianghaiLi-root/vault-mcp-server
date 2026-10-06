#!/usr/bin/env python3
"""Entry point so ``python -m vault_mcp`` starts the web + remote MCP server."""

from . import server

if __name__ == "__main__":
    server.main()
