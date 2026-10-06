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

## Features

**Role model (important)**

| Role | Permissions |
|------|-------------|
| `admin` | Super-user. May rename itself, add / rename / delete any user, reset anyone's password & 2FA, re-issue tokens, and sees the full user list plus the global hardening switches. |
| `user` | Ordinary account. **Manages only itself.** It cannot see the user list, has no *Ops / Users* tab, and every `/api/admin/*` route returns **404** (not 403) so the endpoints' existence is never confirmed. |

An account without a `role` key is treated as `user`. Always keep at least one
`admin`; the last remaining admin cannot be deleted.

**Web console** (glassmorphism UI, tabs shown per role)

| Tab | Visible to | What you can do |
|-----|-----------|-----------------|
| **凭据管理** Credentials | everyone | Add / edit / delete typed credentials (SSH / web / API / DB / generic). The form renders the fields for the selected type automatically. |
| **安全设置** Security | everyone | Enroll / reset TOTP 2FA, view & regenerate your MCP token, change your login password. |
| **运维 / 用户** Ops | `admin` only | Server status; **user management** (add user, **rename user**, reset password, reset 2FA, re-issue MCP token, delete user) written straight back to `config.yaml`; **web hardening**; credential-store integrity check. |

**Web hardening** (admin-only, persisted under the `security` key of `config.yaml`)

- **Cloudflare Access pre-check** — when on, every browser request must carry a
  Cloudflare Access JWT (`Cf-Access-Jwt-Assertion` header or `CF_Authorization`
  cookie). Requests without it get **403** before the login page even renders.
  Pair it with Cloudflare Zero Trust for a "before login" access layer.
- **Force secure cookie** — adds the `Secure` flag to the session cookie.
- **Custom edge header** — a shared secret injected by your own nginx / CDN
  (e.g. `add_header X-Edge-Secret "xxx";`); a mismatch is 403.
- **Login throttling** — N failures from one source locks it out for M seconds (429).

> `/mcp` is exempt from the edge check: it authenticates with its own Bearer
> token and is machine-facing rather than browser-facing.

**MCP tools:** `vault_save`, `vault_get`, `vault_list`, `vault_delete`, and
`vault_http` (AI-blind HTTP call — the secret is injected server-side and never
returned to the model).

## Layout

| Path | Purpose |
|------|---------|
| `vault_mcp/vault_core.py` | Crypto + per-user encrypted storage (stdlib + `cryptography`) |
| `vault_mcp/auth.py` | scrypt password hashing, TOTP (RFC 6238), HMAC session tokens |
| `vault_mcp/config.py` | Loads/writes `config.yaml`, user CRUD, **role checks**, web-hardening settings, 2FA state persistence |
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
python -m vault_mcp.cli add-user admin --role admin
#    later accounts default to the ordinary role:
# python -m vault_mcp.cli add-user alice

# 3. run (behind TLS / reverse proxy in production)
VAULT_COOKIE_SECURE=1 uvicorn vault_mcp.server:app --host 0.0.0.0 --port 8080
#    or simply:  python -m vault_mcp
```

Open `http://<host>:8080/`, log in, and (optionally) enable Google
Authenticator under **两步验证**.

## Docker

```bash
echo "VAULT_MASTER_PASSWORD=$(openssl rand -hex 32)" > .env
python -m vault_mcp.cli add-user admin --role admin   # generates config.yaml + token
docker compose up --build
```

Mount your own `config.yaml` and a volume for `/data` (the vault store).

## Credential types

Every credential carries a **type** that drives its input fields in the web
console (and tells an AI client which field is the *primary* secret returned by
`vault_get` / `vault_http`):

| Type | Fields |
|------|--------|
| `generic` | 秘密 / 密码 |
| `ssh` | 主机/IP · 端口 · 用户名 · 密码 · 私钥 |
| `web` | 网址 URL · 用户名/邮箱 · 密码 |
| `api` | Token / API Key · 接口地址 URL |
| `db` | 主机 · 端口 · 数据库名 · 用户名 · 密码 |

The list view shows a type badge, and each entry has **修改** (edit) and
**删除** (delete) actions. Editing prefills every field; renaming an entry
replaces the old record with the new name. All fields are encrypted at rest in a
single AES-256-GCM blob — only `name`, `type` and `note` live in plaintext
metadata, so the list (and `vault_list`) never expose values.

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

### DNS-rebinding protection

The `/mcp` endpoint validates the `Host` header and answers **HTTP 421** for
anything not whitelisted. List your public domain(s) in `config.yaml`:

```yaml
mcp:
  allowed_hosts:
    - test.example.com
    - 127.0.0.1:8080
    - localhost:8080
```

`allowed_origins` defaults to `https://<each allowed_host>`. The protection is
never disabled — it is a deliberate anti-DNS-rebinding guard.

Example `mcp.json` snippet for WorkBuddy:

```json
{
  "mcpServers": {
    "vault-remote": {
      "url": "https://test.example.com/mcp",
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
.venv/bin/python -m vault_mcp.cli add-user admin --role admin
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
