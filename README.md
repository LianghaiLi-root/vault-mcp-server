# Vault MCP Server

> Other languages: [Chinese](README.zh.md)

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
> versus the purely local DPAPI model. Protect that password like a root key.

---

## Requirements

**Runtime**

| Item | Requirement |
|------|-------------|
| Python | **3.10 or newer** (`requires-python = ">=3.10"`) |
| Operating system | Linux, macOS, or Windows |
| Disk | A few MB for the code plus the encrypted store (grows with your data) |
| Network | Outbound HTTPS only if you enable Cloudflare Turnstile or use `vault_http` |

**Python packages** — installed automatically from `requirements.txt`:

| Package | Purpose |
|---------|---------|
| `cryptography` | AES-256-GCM, PBKDF2 |
| `fastapi`, `uvicorn[standard]` | HTTP server |
| `python-multipart`, `jinja2` | Form parsing and HTML templates |
| `pyyaml` | `config.yaml` |
| `mcp==1.30.0`, `sse-starlette` | Remote MCP transport |
| `Pillow` *(optional)* | Renders the image CAPTCHA |

**Optional extras**

* **Pillow** — needed for the `numeric` and `image` CAPTCHA modes. Without it
  those modes degrade to an arithmetic question rather than failing open.
* **nginx** (or another TLS terminator) — required for a production deployment.
* **Cloudflare** — only if you want the Access edge gate or Turnstile.

> On **Windows** the vault uses DPAPI and needs no master password.
> On **Linux / macOS / Docker** you must set `VAULT_FORCE_PBKDF2=1` and supply
> `VAULT_MASTER_PASSWORD`.

---

## Installation

### 1. Get the code

```bash
git clone https://github.com/LianghaiLi-root/vault-mcp-server.git
cd vault-mcp-server
```

### 2. Create a virtual environment and install

```bash
python3 -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Or install it as a package, which also gives you the `vault-mcp-server` and
`vault-mcp-cli` commands:

```bash
pip install .
```

### 3. Create your configuration

```bash
cp config.example.yaml config.yaml
```

Open `config.yaml` and set the public hostname(s) you will serve under
`mcp.allowed_hosts` — the remote MCP endpoint rejects any other `Host` header
with HTTP 421 (this is deliberate anti-DNS-rebinding protection).

### 4. Set the environment

```bash
export VAULT_MASTER_PASSWORD="$(openssl rand -hex 32)"   # Linux / macOS only
export VAULT_FORCE_PBKDF2=1
export VAULT_DIR=/var/lib/vault-mcp/vault
```

### 5. Provision your first user

```bash
python -m vault_mcp.cli add-user admin --role admin
```

This writes a scrypt password hash and a fresh MCP token into `config.yaml`.
Later accounts default to the ordinary role:

```bash
python -m vault_mcp.cli add-user alice
```

### 6. Run

```bash
VAULT_COOKIE_SECURE=1 uvicorn vault_mcp.server:app --host 0.0.0.0 --port 8080
# or simply:
python -m vault_mcp
```

Open `http://<host>:8080/`, log in, and optionally enable Google Authenticator
under **Two-factor authentication**. Set `VAULT_COOKIE_SECURE=1` only when the
site is served over HTTPS.

### Docker

```bash
echo "VAULT_MASTER_PASSWORD=$(openssl rand -hex 32)" > .env
python -m vault_mcp.cli add-user admin --role admin   # generates config.yaml + token
docker compose up --build
```

Mount your own `config.yaml` and a volume for `/data` (the vault store).

---

## Features

### Role model

| Role | Permissions |
|------|-------------|
| `admin` | Super-user. May rename itself, add / rename / delete any user, reset anyone's password and 2FA, re-issue tokens, and sees the full user list plus the global hardening switches. |
| `user` | Ordinary account. **Manages only itself.** It cannot see the user list, has no *Ops / Users* tab, and every `/api/admin/*` route returns **404** (not 403) so the endpoints' existence is never confirmed. |

An account without a `role` key is treated as `user`. Always keep at least one
`admin`; the last remaining admin cannot be deleted.

### Web console

Glassmorphism UI; tabs are shown according to your role.

| Tab | Visible to | What you can do |
|-----|-----------|-----------------|
| **Credentials** | everyone | Add / edit / delete typed credentials (SSH / web / API / DB / generic). The form renders the fields for the selected type automatically. |
| **Security** | everyone | Enroll / reset TOTP 2FA, view and regenerate your MCP token, change your login password. |
| **Ops / Users** | `admin` only | Server status; **user management** (add user, **rename user**, reset password, reset 2FA, re-issue MCP token, delete user) written straight back to `config.yaml`; **web hardening**; **human verification**; credential-store integrity check. |

### Web hardening

Admin-only, persisted under the `security` key of `config.yaml`.

- **Cloudflare Access pre-check** — when on, every browser request must carry a
  Cloudflare Access JWT (`Cf-Access-Jwt-Assertion` header or `CF_Authorization`
  cookie). Requests without it get **403** before the login page even renders.
  Pair it with Cloudflare Zero Trust for a "before login" access layer.
- **Force secure cookie** — adds the `Secure` flag to the session cookie.
- **Custom edge header** — a shared secret injected by your own nginx / CDN
  (e.g. `add_header X-Edge-Secret "xxx";`); a mismatch is 403.
- **Login throttling** — N failures from one source locks it out for M seconds (429).

> **Edge-check exemptions:** `/mcp` and **any request carrying a valid Bearer
> token** skip the edge check. The former is machine-facing and authenticates on
> its own; the latter is a machine credential a casual visitor cannot forge.
>
> This exemption is what keeps the feature safe to use: the hardening switches
> are themselves configured through `POST /api/admin/security` (which accepts a
> Bearer token). If the gate also blocked that call, enabling Cloudflare Access
> would lock the admin out of every authenticated path — including the one
> needed to switch it back off — leaving hand-editing `config.yaml` on the host
> as the only recovery. The UI asks for confirmation before enabling the gate so
> you configure the Cloudflare Access application first.

### Human verification

Login-page CAPTCHA, admin-only, persisted under the `captcha` key of
`config.yaml`. It blocks automated credential-stuffing *before* the password
comparison. Pick one mode:

| Mode | What it is |
|------|------------|
| `off` | Disabled |
| `numeric` | Digits only, rendered as an image |
| `image` | Letters + digits, rendered as an image with noise |
| `turnstile` | **Cloudflare Turnstile** — automatic, usually just a checkbox |

- Images are rendered to PNG with Pillow, deliberately **not** SVG — text inside
  an SVG is plain markup a bot can read, which would defeat the purpose. Without
  Pillow the mode degrades to an arithmetic question; it **never** degrades to
  "no challenge". The admin card warns you when that happens.
- **Turnstile cannot be enabled without credentials.** Both the site key and the
  secret key are required, and a save missing either is rejected with a message
  naming what is absent. The secret is **never echoed back** to the browser — the
  UI only reports whether one is stored. Send a new value to replace it, or use
  "clear secret" to wipe it.
- Answers stay **server-side**: the browser only receives an opaque id. Answers
  live in memory, expire after 5 minutes and are **single-use**, so a captured id
  cannot be replayed. Failed challenges count toward the login throttle.
- A wrong key produces a readable error on the login page (including the
  Cloudflare error code) instead of a silent blank box.

### MCP tools

`vault_save`, `vault_get`, `vault_list`, `vault_delete`, and `vault_http`
(an AI-blind HTTP call — the secret is injected server-side and never returned
to the model).

---

## Credential types

Every credential carries a **type** that drives its input fields in the web
console, and tells an AI client which field is the *primary* secret returned by
`vault_get` / `vault_http`:

| Type | Fields |
|------|--------|
| `generic` | Secret / password |
| `ssh` | Host / IP · port · username · password · private key |
| `web` | URL · username / e-mail · password |
| `api` | Token / API key · endpoint URL |
| `db` | Host · port · database · username · password |

The list view shows a type badge, and each entry has **Edit** and **Delete**
actions. Editing prefills every field; renaming an entry replaces the old record
with the new name. All fields are encrypted at rest in a single AES-256-GCM
blob — only `name`, `type` and `note` live in plaintext metadata, so the list
(and `vault_list`) never expose values.

---

## Remote MCP client

Point your MCP client at `http://<host>:8080/mcp` and authenticate with the
user's `mcp_token` as a **Bearer** token. The four tools — `vault_save`,
`vault_get`, `vault_list`, `vault_delete` — operate only on that user's
namespace. There is also an **AI-blind** tool:

* **`vault_http(name, url, method, headers, body, secret_header)`** — the server
  fetches `url` with the stored secret injected server-side (placeholder
  `{{secret}}` in headers/body, or a named `secret_header`), and returns only the
  HTTP response. The secret is **never** returned to the model and is redacted
  from the response. Only `https` is allowed; the optional `http.allow_hosts`
  setting restricts destinations. Use this instead of `vault_get` whenever the AI
  only needs to *call* an API, not see the secret.

### DNS-rebinding protection

The `/mcp` endpoint validates the `Host` header and answers **HTTP 421** for
anything not whitelisted. List your public domain(s) in `config.yaml`:

```yaml
mcp:
  allowed_hosts:
    - vault.example.com
    - 127.0.0.1:8080
    - localhost:8080
```

`allowed_origins` defaults to `https://<each allowed_host>`. This protection is
never disabled — it is a deliberate anti-DNS-rebinding guard.

Example `mcp.json` snippet for WorkBuddy:

```json
{
  "mcpServers": {
    "vault-remote": {
      "url": "https://vault.example.com/mcp",
      "headers": { "Authorization": "Bearer <admin mcp_token>" }
    }
  }
}
```

> Note: your client must support *remote* (URL-based) MCP. If it only supports
> local stdio, run `python -m vault_mcp.stdio` on the server and connect over
> stdio, or put a local stdio-to-HTTP shim in front.

---

## Layout

| Path | Purpose |
|------|---------|
| `vault_mcp/vault_core.py` | Crypto + per-user encrypted storage (stdlib + `cryptography`) |
| `vault_mcp/auth.py` | scrypt password hashing, TOTP (RFC 6238), HMAC session tokens |
| `vault_mcp/config.py` | Loads/writes `config.yaml`, user CRUD, role checks, web-hardening and CAPTCHA settings, 2FA state persistence |
| `vault_mcp/captcha.py` | Login human verification: image rendering, single-use answer store, Cloudflare Turnstile verification |
| `vault_mcp/server.py` | FastAPI app: web console + remote MCP (`/mcp`) |
| `vault_mcp/stdio.py` | Local **stdio** MCP server (agent use on this machine) |
| `vault_mcp/cli.py` | Operator CLI to provision users / tokens |
| `vault_mcp/__main__.py` | `python -m vault_mcp` entry point (runs the server) |
| `pyproject.toml` | Package metadata, dependencies, console entry points |
| `deploy/` | systemd unit, nginx TLS proxy, `.env` template |
| `config.example.yaml` | Operator config template (users + server + vault dir) |

> ⚠️ **Read this before editing the web templates**
>
> `DASH_TPL_SRC` / `LOGIN_TPL_SRC` in `vault_mcp/server.py` are **non-raw**
> triple-quoted Python strings with JavaScript inside. A `\n` written in them is
> compiled by Python into a **real newline**, which splits the JS string literal
> and makes the whole `<script>` block fail with
> `SyntaxError: Invalid or unexpected token` — every event handler on the page
> dies silently (dead tabs, an apparently-empty type dropdown). **It bites in
> comments too.**
>
> Write `\\n` instead, or build the string as `['a','b'].join(NL)` with an
> explicit `const NL='\\n';`.
>
> To stop this regressing, the server runs a self-check **at import time**: it
> reads the `.py` source and scans inside `<script>...</script>` for the raw
> sequence, raising with an exact line number on a hit. Note this bug **cannot**
> be detected by inspecting a runtime string — after compilation the backslash is
> already gone — so the guard must look at the raw source.

---

## Production deployment (systemd + nginx)

Files in [`deploy/`](deploy/) wire the server behind TLS on a Linux box:

```bash
# 1. install as a dedicated, unprivileged user
useradd --system --home /opt/vault-mcp-server --create-home vault
git clone https://github.com/LianghaiLi-root/vault-mcp-server.git /opt/vault-mcp-server
cd /opt/vault-mcp-server
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 2. provision config + secrets
cp config.example.yaml config.yaml
.venv/bin/python -m vault_mcp.cli add-user admin --role admin
cp deploy/env.example .env
#   edit .env: set VAULT_MASTER_PASSWORD (openssl rand -hex 32), then chmod 600 .env

# 3. systemd
cp deploy/vault-mcp.service /etc/systemd/system/
mkdir -p /var/lib/vault-mcp && chown -R vault:vault /var/lib/vault-mcp
systemctl daemon-reload && systemctl enable --now vault-mcp

# 4. nginx (TLS)
cp deploy/nginx-vault-mcp.conf /etc/nginx/sites-available/vault-mcp.conf
ln -s /etc/nginx/sites-available/vault-mcp.conf /etc/nginx/sites-enabled/
#   edit server_name + certificate paths, then: nginx -t && systemctl reload nginx
```

The unit binds uvicorn to `127.0.0.1:8080` only; nginx terminates TLS and proxies
both `/` (web console) and `/mcp` (remote MCP). Set `VAULT_COOKIE_SECURE=1` once
TLS is in place.

> **systemd sandbox note.** The shipped unit uses `ProtectSystem=full` with
> `ReadWritePaths=/var/lib/vault-mcp /opt/vault-mcp-server` and pins the code
> directory read-only via `ReadOnlyPaths`. Do **not** switch to
> `ProtectSystem=strict`: it remounts the whole filesystem read-only and systemd
> silently drops a `ReadWritePaths` entry nested inside an already read-only
> tree, which breaks every admin write with
> `[Errno 30] Read-only file system: '.../config.yaml.tmp'`.

---

## Security checklist

- [ ] `VAULT_MASTER_PASSWORD` from a secret manager, never committed.
- [ ] TLS in front (reverse proxy / Cloudflare); set `VAULT_COOKIE_SECURE=1`.
- [ ] `config.yaml` (hashes + tokens) not committed; `.gitignore`d.
- [ ] Per-user 2FA enabled after first login.
- [ ] Rate-limit / WAF the `/login` and `/mcp` endpoints.
- [ ] Consider a CAPTCHA mode if the login page is reachable from the internet.

---

## License

MIT — see [`LICENSE`](LICENSE).
