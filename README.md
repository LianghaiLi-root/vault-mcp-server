# Vault MCP Server

A deployable, multi-user **credential vault** exposing both:

* a **web console** (login + TOTP 2FA + per-user credential management), and
* a **remote MCP endpoint** (`/mcp`, Streamable HTTP) so an AI client can use
  secrets without them ever being typed into a chat.

Secrets are encrypted at rest with **AES-256-GCM**. The master key is provided
by the platform: **Windows DPAPI** (zero-config, bound to your account) or
**PBKDF2-HMAC-SHA256** of `VAULT_MASTER_PASSWORD` (Linux / servers). Each user
has an isolated namespace; access control is enforced server-side.

> ⚠️ On a remote/trusted server the host holds `VAULT_MASTER_PASSWORD` and can
> decrypt every user's vault. That is the intended trade-off of a *hosted* vault
> vs. the purely local DPAPI model. Protect that password like a root key.

## Layout

| File | Purpose |
|------|---------|
| `vault_core.py` | Crypto + per-user encrypted storage (stdlib + `cryptography`) |
| `auth.py` | scrypt password hashing, TOTP (RFC 6238), HMAC session tokens |
| `config.py` | Loads `config.yaml`, user lookup, 2FA state persistence |
| `server.py` | FastAPI app: web console + remote MCP (`/mcp`) |
| `vault_server.py` | Local **stdio** MCP server (agent use on this machine) |
| `vault_cli.py` | Operator CLI to provision users / tokens |

## Quick start (Linux server)

```bash
pip install -r requirements.txt

# 0. create your working config from the example
cp config.example.yaml config.yaml

# 1. set the master password (the server can decrypt all vaults with this)
export VAULT_MASTER_PASSWORD="$(openssl rand -hex 32)"
export VAULT_FORCE_PBKDF2=1
export VAULT_DIR=/var/lib/vault-mcp/vault

# 2. provision a user (writes config.yaml with a scrypt hash + mcp_token)
python vault_cli.py add-user admin

# 3. run (behind TLS / reverse proxy in production)
VAULT_COOKIE_SECURE=1 uvicorn server:app --host 0.0.0.0 --port 8080
```

Open `http://<host>:8080/`, log in, and (optionally) enable Google
Authenticator under **两步验证**.

## Docker

```bash
echo "VAULT_MASTER_PASSWORD=$(openssl rand -hex 32)" > .env
python vault_cli.py add-user admin          # generates config.yaml + token
docker compose up --build
```

Mount your own `config.yaml` and a volume for `/data` (the vault store).

## Remote MCP client

Point your MCP client at `http://<host>:8080/mcp` and authenticate with the
user's `mcp_token` as a **Bearer** token. The four tools — `vault_save`,
`vault_get`, `vault_list`, `vault_delete` — operate only on that user's
namespace. Example `mcp.json` snippet for WorkBuddy:

```json
{
  "mcpServers": {
    "vault-remote": {
      "url": "http://<host>:8080/mcp",
      "headers": { "Authorization": "Bearer <admin mcp_token>" }
    }
  }
}
```

> Note: your client must support *remote* (URL-based) MCP. If it only supports
> local stdio, run `vault_server.py` on the server and connect over stdio, or
> put a local stdio↔HTTP shim in front.

## Security checklist

- [ ] `VAULT_MASTER_PASSWORD` from a secret manager, never committed.
- [ ] TLS in front (reverse proxy / Cloudflare); set `VAULT_COOKIE_SECURE=1`.
- [ ] `config.yaml` (hashes + tokens) not committed; `.gitignore`d.
- [ ] Per-user 2FA enabled after first login.
- [ ] Rate-limit / WAF the `/login` and `/mcp` endpoints.

## License

MIT — see `LICENSE`.
