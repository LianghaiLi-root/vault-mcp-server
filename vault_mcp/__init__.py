"""vault_mcp — deployable multi-user credential vault with a web console and a remote MCP endpoint.

Package layout
--------------
* ``vault_core`` — encrypted, multi-user credential storage (AES-256-GCM).
* ``auth``       — scrypt password hashing, TOTP (RFC 6238) and HMAC session tokens.
* ``config``     — loads the operator config and persists per-user 2FA state.
* ``server``     — FastAPI app: web console + remote MCP endpoint (``/mcp``).
* ``stdio``      — local stdio MCP transport for agent use on this machine.
* ``cli``        — operator CLI to provision users / tokens.

Run the server with ``python -m vault_mcp`` (or ``uvicorn vault_mcp.server:app``).
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
