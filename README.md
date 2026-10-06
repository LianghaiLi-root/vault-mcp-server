> 🇨🇳 [中文文档](README.zh.md)

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

| Path | Purpose |
|------|---------|
| `vault_mcp/vault_core.py` | Crypto + per-user encrypted storage (stdlib + `cryptography`) |
| `vault_mcp/auth.py` | scrypt password hashing, TOTP (RFC 6238), HMAC session tokens |
| `vault_mcp/config.py` | Loads `config.yaml`, user lookup, 2FA state persistence |
| `vault_mcp/server.py` | FastAPI app: web console + remote MCP (`/mcp`) |
| `vault_mcp/stdio.py` | Local **stdio** MCP server (agent use on this machine) |
| `vault_mcp/cli.py` | Operator CLI to provision users / tokens |
| `vault_mcp/__main__.py` | `python -m vault_mcp` entry point (runs the server) |
| `pyproject.toml` | Package metadata, dependencies, console entry points |
| `deploy/` | systemd unit, nginx TLS proxy, `.env` template |
| `config.example.yaml` | Operator config template (users + server + vault dir) |

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
python -m vault_mcp.cli add-user admin

# 3. run (behind TLS / reverse proxy in production)
VAULT_COOKIE_SECURE=1 uvicorn vault_mcp.server:app --host 0.0.0.0 --port 8080
#    or simply:  python -m vault_mcp
```

Open `http://<host>:8080/`, log in, and (optionally) enable Google
Authenticator under **两步验证**.

## Docker

```bash
echo "VAULT_MASTER_PASSWORD=$(openssl rand -hex 32)" > .env
python -m vault_mcp.cli add-user admin          # generates config.yaml + token
docker compose up --build
```

Mount your own `config.yaml` and a volume for `/data` (the vault store).

## Remote MCP client

Point your MCP client at `http://<host>:8080/mcp` and authenticate with the
user's `mcp_token` as a **Bearer** token. The four tools — `vault_save`,
`vault_get`, `vault_list`, `vault_delete` — operate only on that user's
namespace. There is also an **AI-blind** tool:

* **`vault_http(name, url, method, headers, body, secret_header)`** — the server
  fetches `url` with the stored secret injected server-side (placeholder
  `{{secret}}` in headers/body, or a named `secret_header`), and returns only the
  HTTP response. The secret is **never** returned to the model and is redacted
  from the response. Only `https` is allowed; optional `http.allow_hosts`
  restricts destinations. Use this instead of `vault_get` whenever the AI only
  needs to *call* an API, not see the secret.

Example `mcp.json` snippet for WorkBuddy:

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
> local stdio, run `python -m vault_mcp.stdio` on the server and connect over
> stdio, or put a local stdio↔HTTP shim in front.

## Production deployment (systemd + nginx)

Files in [`deploy/`](deploy/) wire the server behind TLS on a Linux box:

```bash
# 1. install as a dedicated, unprivileged user
useradd --system --home /opt/vault-mcp-server --create-home vault
git clone <your-repo> /opt/vault-mcp-server
cd /opt/vault-mcp-server && python -m venv .venv && .venv/bin/pip install -r requirements.txt

# 2. provision config + secrets
cp config.example.yaml config.yaml
.venv/bin/python -m vault_mcp.cli add-user admin
cp deploy/env.example .env
#   edit .env: set VAULT_MASTER_PASSWORD (openssl rand -hex 32) and chmod 600 .env

# 3. systemd
cp deploy/vault-mcp.service /etc/systemd/system/
mkdir -p /var/lib/vault-mcp && chown -R vault:vault /var/lib/vault-mcp
systemctl daemon-reload && systemctl enable --now vault-mcp

# 4. nginx (TLS)
cp deploy/nginx-vault-mcp.conf /etc/nginx/sites-available/vault-mcp.conf
ln -s /etc/nginx/sites-available/vault-mcp.conf /etc/nginx/sites-enabled/
#   edit server_name + certificate paths, then: nginx -t && systemctl reload nginx
```

The unit binds uvicorn to `127.0.0.1:8080` only; nginx terminates TLS and
proxies `/` (web console) and `/mcp` (remote MCP). `VAULT_COOKIE_SECURE=1`
must be set once behind TLS.

## Security checklist

- [ ] `VAULT_MASTER_PASSWORD` from a secret manager, never committed.
- [ ] TLS in front (reverse proxy / Cloudflare); set `VAULT_COOKIE_SECURE=1`.
- [ ] `config.yaml` (hashes + tokens) not committed; `.gitignore`d.
- [ ] Per-user 2FA enabled after first login.
- [ ] Rate-limit / WAF the `/login` and `/mcp` endpoints.

## License

MIT — see `LICENSE`.
