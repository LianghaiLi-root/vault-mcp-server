> 🌐 [English](README.md)

# Vault MCP Server（凭据库服务）

一个可部署、多用户的**凭据保险库**，同时提供：

* 一个 **Web 控制台**（登录 + TOTP 双因素认证 + 每用户凭据管理），以及
* 一个 **远程 MCP 端点**（`/mcp`，基于 Streamable HTTP），让 AI 客户端可以使用秘密，而秘密永远不需要被手动敲进聊天框。

秘密在静态存储时使用 **AES-256-GCM** 加密。主密钥由平台提供：**Windows DPAPI**（零配置，绑定你的账户）或 **PBKDF2-HMAC-SHA256**（由 `VAULT_MASTER_PASSWORD` 派生，用于 Linux / 服务器）。每个用户拥有相互隔离的命名空间；访问控制由服务端强制执行。

> ⚠️ 在远程 / 可信服务器上，宿主持有 `VAULT_MASTER_PASSWORD`，因此可以解密每个用户的保险库。这是*托管型*保险库相对于纯本地 DPAPI 模型的固有取舍。请像对待根密钥一样保护这个密码。

## 功能特性

**角色模型（重要）**

| 角色 | 权限 |
|------|------|
| `admin` | 超级用户。可自定义用户名、新增 / 重命名 / 删除任意用户、重置他人密码与 2FA、重签 Token，并查看完整用户列表与全局加固开关。 |
| `user` | 普通账号。**只能管理自己**。看不到用户列表、看不到「运维 / 用户」标签页，访问任何 `/api/admin/*` 均返回 **404**（而不是 403，避免暴露这些接口的存在）。 |

配置里未写 `role` 的账号按 `user` 处理。请务必至少保留一个 `admin`（最后一个管理员无法被删除）。

**Web 控制台**（毛玻璃风格，标签页按角色显示）

| 标签页 | 可见性 | 能力 |
|--------|--------|------|
| **凭据管理** | 所有人 | 新增 / 修改 / 删除带类型的凭据（SSH / 网站 / API / 数据库 / 通用）。表单会按所选类型自动渲染对应字段。 |
| **安全设置** | 所有人 | 启用 / 重置 TOTP 双因素、查看与重新生成 MCP Token、修改登录密码。 |
| **运维 / 用户** | 仅 `admin` | 服务器状态；**用户管理**（新增用户、**修改用户名**、重置密码、重置 2FA、重签 MCP Token、删除用户，直接写回 `config.yaml`）；**Web 访问加固**；凭据存储完整性校验。 |

**Web 访问加固**（仅 `admin` 可改，写入 `config.yaml` 的 `security` 段）

- **Cloudflare Access 前置校验** —— 开启后，所有浏览器请求必须带 Cloudflare Access 的 JWT（`Cf-Access-Jwt-Assertion` 头或 `CF_Authorization` Cookie），否则直接 **403**，连登录页都不渲染。适合配合 Cloudflare Zero Trust 做一层“登录前”的访问控制。
- **强制 HTTPS Cookie** —— 给会话 Cookie 加 `Secure` 标记。
- **自定义边缘校验头** —— 自建 nginx / 其他 CDN 注入的共享密钥（如 `add_header X-Edge-Secret "xxx";`），不匹配即 403。
- **登录失败限流** —— 同一来源连续失败 N 次后锁定 M 秒（返回 429）。

> `/mcp` 不经过上述边缘校验：它用独立的 Bearer Token 鉴权，面向机器而非浏览器。

**MCP 工具：** `vault_save`、`vault_get`、`vault_list`、`vault_delete`，以及
`vault_http`（AI 盲调 HTTP —— 秘密由服务端注入，永不返回给模型）。

## 目录结构

| 路径 | 作用 |
|------|------|
| `vault_mcp/vault_core.py` | 加密 + 多用户加密存储（标准库 + `cryptography`） |
| `vault_mcp/auth.py` | scrypt 密码哈希、TOTP（RFC 6238）、HMAC 会话令牌 |
| `vault_mcp/config.py` | 加载 `config.yaml`、用户查找、**角色判定**、Web 加固设置、2FA 状态持久化 |
| `vault_mcp/server.py` | FastAPI 应用：Web 控制台 + 远程 MCP（`/mcp`） |
| `vault_mcp/stdio.py` | 本地 **stdio** MCP 服务（本机上的智能体使用） |
| `vault_mcp/cli.py` | 运维 CLI，用于预置用户 / 令牌 |
| `vault_mcp/__main__.py` | `python -m vault_mcp` 入口（启动服务） |
| `pyproject.toml` | 包元数据、依赖、控制台入口 |
| `deploy/` | systemd 单元、nginx TLS 反向代理、`.env` 模板 |
| `config.example.yaml` | 运维配置模板（用户 + 服务 + 保险库目录） |

## 快速开始（Linux 服务器）

```bash
pip install -r requirements.txt

# 0. 从示例创建你的工作配置
cp config.example.yaml config.yaml

# 1. 设置主密码（服务器可凭此解密所有保险库）
export VAULT_MASTER_PASSWORD="$(openssl rand -hex 32)"
export VAULT_FORCE_PBKDF2=1
export VAULT_DIR=/var/lib/vault-mcp/vault

# 2. 预置一个用户（向 config.yaml 写入 scrypt 哈希 + mcp_token）
python -m vault_mcp.cli add-user admin --role admin
#    后续账号默认是普通用户：
# python -m vault_mcp.cli add-user alice

# 3. 运行（生产环境请置于 TLS / 反向代理之后）
VAULT_COOKIE_SECURE=1 uvicorn vault_mcp.server:app --host 0.0.0.0 --port 8080
#    或者更简单：python -m vault_mcp
```

打开 `http://<host>:8080/`，登录后（可选）在 **两步验证** 下启用 Google 身份验证器。

## Docker

```bash
echo "VAULT_MASTER_PASSWORD=$(openssl rand -hex 32)" > .env
python -m vault_mcp.cli add-user admin --role admin   # 生成 config.yaml + token
docker compose up --build
```

挂载你自己的 `config.yaml`，并为 `/data`（保险库存储）挂载卷。

## 凭据类型

每条凭据都带有一个**类型**，它会决定 Web 控制台里显示的输入框（也决定 AI 客户端通过 `vault_get` / `vault_http` 拿到的*主*秘密字段）：

| 类型 | 字段 |
|------|------|
| `generic` | 秘密 / 密码 |
| `ssh` | 主机/IP · 端口 · 用户名 · 密码 · 私钥 |
| `web` | 网址 URL · 用户名/邮箱 · 密码 |
| `api` | Token / API Key · 接口地址 URL |
| `db` | 主机 · 端口 · 数据库名 · 用户名 · 密码 |

列表页会显示类型徽标，每条记录都有 **修改** 与 **删除** 按钮。修改会预填所有字段；重命名条目会用新名称替换旧记录。所有字段都以单个 AES-256-GCM 密文加密落盘——只有 `name`、`type`、`note` 以明文元数据存在，因此列表与 `vault_list` 永远不会泄露秘密值。

## 远程 MCP 客户端

将你的 MCP 客户端指向 `http://<host>:8080/mcp`，并使用用户的 `mcp_token` 作为 **Bearer** 令牌进行认证。四个工具——`vault_save`、`vault_get`、`vault_list`、`vault_delete`——只在该用户的命名空间内操作。此外还有一个 **对 AI 不可见（AI-blind）** 的工具：

* **`vault_http(name, url, method, headers, body, secret_header)`** —— 服务端以存储的秘密发起对 `url` 的请求（在 headers / body 中使用占位符 `{{secret}}`，或使用具名的 `secret_header`），仅返回 HTTP 响应。秘密**永远不会**回传给模型，并且会从响应中被擦除。只允许 `https`；可选的 `http.allow_hosts` 用于限制目标地址。当 AI 只需要*调用*某个 API 而不需要看见秘密时，请使用它代替 `vault_get`。

### DNS 重绑定防护

`/mcp` 端点会校验 `Host` 请求头，未列入白名单的请求返回 **HTTP 421**。请在 `config.yaml` 中登记你的公网域名：

```yaml
mcp:
  allowed_hosts:
    - test.example.com
    - 127.0.0.1:8080
    - localhost:8080
```

`allowed_origins` 默认取 `https://<每个 allowed_host>`。该防护不会被关闭——它是一道刻意保留的反 DNS 重绑定防线。

WorkBuddy 的 `mcp.json` 配置示例：

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

> 注意：你的客户端必须支持*远程*（基于 URL 的）MCP。如果只支持本地 stdio，可以在服务器上运行 `python -m vault_mcp.stdio` 并通过 stdio 连接，或者在前面加一个本地 stdio↔HTTP 转换层。

## 生产部署（systemd + nginx）

[`deploy/`](deploy/) 里的文件用于将服务挂载在 Linux 机器的 TLS 之后：

```bash
# 1. 以专用的非特权用户安装
useradd --system --home /opt/vault-mcp-server --create-home vault
git clone <your-repo> /opt/vault-mcp-server
cd /opt/vault-mcp-server && python -m venv .venv && .venv/bin/pip install -r requirements.txt

# 2. 预置配置 + 密钥
cp config.example.yaml config.yaml
.venv/bin/python -m vault_mcp.cli add-user admin --role admin
cp deploy/env.example .env
#   编辑 .env：设置 VAULT_MASTER_PASSWORD（openssl rand -hex 32）并执行 chmod 600 .env

# 3. systemd
cp deploy/vault-mcp.service /etc/systemd/system/
mkdir -p /var/lib/vault-mcp && chown -R vault:vault /var/lib/vault-mcp
systemctl daemon-reload && systemctl enable --now vault-mcp

# 4. nginx（TLS）
cp deploy/nginx-vault-mcp.conf /etc/nginx/sites-available/vault-mcp.conf
ln -s /etc/nginx/sites-available/vault-mcp.conf /etc/nginx/sites-enabled/
#   编辑 server_name + 证书路径，然后：nginx -t && systemctl reload nginx
```

该单元仅将 uvicorn 绑定到 `127.0.0.1:8080`；nginx 终止 TLS 并代理 `/`（Web 控制台）和 `/mcp`（远程 MCP）。在 TLS 之后必须设置 `VAULT_COOKIE_SECURE=1`。

## 安全清单

- [ ] `VAULT_MASTER_PASSWORD` 来自密钥管理器，绝不提交进仓库。
- [ ] 前置 TLS（反向代理 / Cloudflare）；设置 `VAULT_COOKIE_SECURE=1`。
- [ ] `config.yaml`（哈希 + 令牌）不提交，已被 `.gitignore` 忽略。
- [ ] 首次登录后为用户启用 2FA。
- [ ] 对 `/login` 和 `/mcp` 端点做速率限制 / WAF。

## 许可证

MIT —— 见 `LICENSE`。
