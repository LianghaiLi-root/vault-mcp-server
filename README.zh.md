# Vault MCP Server · 凭据保险库

> 其他语言：[英文文档](README.md)

一个可自行部署的**多用户凭据保险库**，同时提供两种使用方式：

* **Web 控制台** —— 登录、TOTP 双因素、按用户隔离的凭据管理；
* **远程 MCP 接口**（`/mcp`，Streamable HTTP）—— 让 AI 客户端直接调用凭据，**秘密无需输入到对话中**。

凭据在落盘时以 **AES-256-GCM** 加密。主密钥由运行平台提供：Windows 上使用 **DPAPI**（零配置，与当前账户绑定），Linux / 服务器上使用 `VAULT_MASTER_PASSWORD` 经 **PBKDF2-HMAC-SHA256** 派生。每个用户拥有独立命名空间，权限校验全部在服务端完成。

> ⚠️ 部署在远程服务器时，主机持有 `VAULT_MASTER_PASSWORD`，因而可以解密所有用户的保险库。
> 这是"托管型保险库"相对"纯本机 DPAPI 模式"必须付出的代价。请像保管 root 密钥一样保管这个口令。

---

## 环境要求

**运行环境**

| 项目 | 要求 |
|------|------|
| Python | **3.10 及以上**（`requires-python = ">=3.10"`） |
| 操作系统 | Linux、macOS 或 Windows |
| 磁盘 | 程序本身仅几 MB，另加加密数据目录（随数据量增长） |
| 网络 | 仅在使用 Cloudflare Turnstile 或 `vault_http` 时需要出站 HTTPS |

**Python 依赖** —— 由 `requirements.txt` 自动安装：

| 依赖 | 用途 |
|------|------|
| `cryptography` | AES-256-GCM、PBKDF2 |
| `fastapi`、`uvicorn[standard]` | HTTP 服务 |
| `python-multipart`、`jinja2` | 表单解析与 HTML 模板 |
| `pyyaml` | 读取 `config.yaml` |
| `mcp==1.30.0`、`sse-starlette` | 远程 MCP 传输 |
| `Pillow`（可选） | 渲染图片验证码 |

**可选组件**

* **Pillow** —— 数字验证码与图形验证码需要它。未安装时这两种模式会自动降级为「算术题」，而**不会**变成「不验证」。
* **nginx**（或其他 TLS 终结组件）—— 生产部署必需。
* **Cloudflare** —— 仅在需要边缘访问校验或 Turnstile 时使用。

> **Windows** 下使用 DPAPI，无需主口令。
> **Linux / macOS / Docker** 下必须设置 `VAULT_FORCE_PBKDF2=1` 并提供 `VAULT_MASTER_PASSWORD`。

---

## 安装

### 1. 获取代码

```bash
git clone https://github.com/LianghaiLi-root/vault-mcp-server.git
cd vault-mcp-server
```

### 2. 创建虚拟环境并安装依赖

```bash
python3 -m venv .venv
. .venv/bin/activate            # Windows：.venv\Scripts\activate
pip install -r requirements.txt
```

也可以按包安装，这样还会得到 `vault-mcp-server` 与 `vault-mcp-cli` 两个命令：

```bash
pip install .
```

### 3. 创建配置文件

```bash
cp config.example.yaml config.yaml
```

打开 `config.yaml`，在 `mcp.allowed_hosts` 中填写你实际对外使用的域名。远程 MCP 接口会对未列入白名单的 `Host` 头返回 **HTTP 421** —— 这是刻意的防 DNS 重绑定保护。

### 4. 设置环境变量

```bash
export VAULT_MASTER_PASSWORD="$(openssl rand -hex 32)"   # 仅 Linux / macOS 需要
export VAULT_FORCE_PBKDF2=1
export VAULT_DIR=/var/lib/vault-mcp/vault
```

### 5. 创建第一个用户

```bash
python -m vault_mcp.cli add-user admin --role admin
```

该命令会把 scrypt 口令哈希与一个新的 MCP Token 写入 `config.yaml`。之后创建的用户默认为普通角色：

```bash
python -m vault_mcp.cli add-user alice
```

### 6. 启动服务

```bash
VAULT_COOKIE_SECURE=1 uvicorn vault_mcp.server:app --host 0.0.0.0 --port 8080
# 或者更简单：
python -m vault_mcp
```

打开 `http://<主机>:8080/` 登录，可在「安全设置」中启用 Google Authenticator 双因素。`VAULT_COOKIE_SECURE=1` 仅在站点通过 HTTPS 提供服务时设置。

### Docker 方式

```bash
echo "VAULT_MASTER_PASSWORD=$(openssl rand -hex 32)" > .env
python -m vault_mcp.cli add-user admin --role admin   # 生成 config.yaml 与 Token
docker compose up --build
```

请自行挂载 `config.yaml` 以及用于 `/data`（加密数据目录）的卷。

---

## 功能说明

### 角色模型

| 角色 | 权限 |
|------|------|
| `admin` | 超级用户。可修改自己的用户名，新增 / 重命名 / 删除任意用户，重置他人密码与双因素，重签 Token，并可查看完整用户列表与全局加固开关。 |
| `user` | 普通账号。**只能管理自己**。看不到用户列表，没有「运维 / 用户」标签页，且所有 `/api/admin/*` 接口一律返回 **404**（而非 403），连"接口是否存在"都不会泄露。 |

配置项中未写 `role` 的账号按 `user` 处理。系统始终保留至少一个 `admin`，最后一个管理员无法被删除。

### Web 控制台

界面为毛玻璃风格，标签页按角色显示。

| 标签页 | 可见范围 | 可进行的操作 |
|--------|----------|--------------|
| **凭据管理** | 所有人 | 新增 / 修改 / 删除带类型的凭据（SSH / 网站 / API / 数据库 / 通用）。表单会按所选类型自动渲染对应字段。 |
| **安全设置** | 所有人 | 启用或重置 TOTP 双因素、查看与重新生成 MCP Token、修改登录密码。 |
| **运维 / 用户** | 仅 `admin` | 服务器状态；**用户管理**（新增用户、**修改用户名**、重置密码、重置双因素、重签 Token、删除用户，直接写回 `config.yaml`）；**Web 访问加固**；**人机验证**；凭据存储完整性校验。 |

### Web 访问加固

仅管理员可修改，保存在 `config.yaml` 的 `security` 段。

* **Cloudflare Access 前置校验** —— 开启后所有浏览器请求必须携带 Cloudflare Access 的 JWT（`Cf-Access-Jwt-Assertion` 头或 `CF_Authorization` Cookie），否则直接返回 **403**，连登录页都不会渲染。可配合 Cloudflare Zero Trust 实现"登录前"的访问控制。
* **强制 HTTPS Cookie** —— 给会话 Cookie 加上 `Secure` 标记。
* **自定义边缘校验头** —— 由自建 nginx 或其他 CDN 注入的共享密钥（例如 `add_header X-Edge-Secret "xxx";`），不匹配即返回 403。
* **登录失败限流** —— 同一来源连续失败 N 次后锁定 M 秒（返回 429）。

> **边缘校验的豁免规则**：`/mcp` 以及**任何携带有效 Bearer Token 的请求**都不经过边缘校验。
> 前者面向机器、自带鉴权；后者是机器凭据，随手访客伪造不了。
>
> 这条豁免是本功能**不会被锁死**的关键：加固开关本身是通过 `POST /api/admin/security`（可携带 Bearer Token）配置的。
> 如果连这个调用也被拦截，那么一旦开启 Cloudflare Access，管理员就会失去所有已认证路径 —— 包括用来关闭它的那一个，只剩登服务器手改 `config.yaml` 一条路。
> 因此界面在启用该开关前会二次确认，提醒你先在 Cloudflare 侧配置好 Access 应用。

### 人机验证

作用于登录页，仅管理员可配置，保存在 `config.yaml` 的 `captcha` 段。
它在**校验密码之前**拦截自动化撞库。四种方式任选其一：

| 方式 | 说明 |
|------|------|
| `off` | 关闭 |
| `numeric` | 数字验证码 —— 图片形式，纯数字 |
| `image` | 图形验证码 —— 字母加数字，带干扰线与噪点 |
| `turnstile` | **Cloudflare Turnstile 自动验证** —— 通常只需勾选，无需输入 |

* 图片由 Pillow 渲染为 PNG，**刻意不使用 SVG** —— SVG 中的文字是明文标记，脚本可直接读取，那样验证码就形同虚设。未安装 Pillow 时会降级为「算术题」，**绝不会**降级成「不验证」，管理端会给出提示。
* **Turnstile 必须填齐密钥才能启用**：Site Key 与 Secret Key 缺一不可，只填一个会被拒绝，并明确提示缺少哪一项。Secret Key **不会回显**到浏览器，界面只显示「是否已设置」；要更换直接填新的，要清空用「清除 Secret」。
* 答案保存在**服务端**：浏览器只拿到一个不透明 id。答案存于内存，5 分钟过期，且**一次性消费** —— 截获的 id 无法重放。验证失败会计入登录失败限流。
* 密钥填写错误时，登录页会显示可读的提示（含 Cloudflare 错误码），而不是一个空白框。

### MCP 工具

`vault_save`、`vault_get`、`vault_list`、`vault_delete`，以及 `vault_http`
（AI 盲调 HTTP —— 秘密由服务端注入，永不返回给模型）。

---

## 凭据类型

每条凭据都有一个**类型**，它决定 Web 控制台中的输入字段，也告诉 AI 客户端
`vault_get` / `vault_http` 返回的**主秘密**是哪一个字段：

| 类型 | 字段 |
|------|------|
| `generic` | 秘密 / 密码 |
| `ssh` | 主机 / IP · 端口 · 用户名 · 密码 · 私钥 |
| `web` | 网址 URL · 用户名 / 邮箱 · 密码 |
| `api` | Token / API Key · 接口地址 URL |
| `db` | 主机 · 端口 · 数据库名 · 用户名 · 密码 |

列表会显示类型徽标，每条记录都带**修改**与**删除**操作。编辑时会自动填入全部字段；重命名会把旧记录替换为新名称。所有字段都加密保存在单个 AES-256-GCM 数据块中 —— 明文元数据只有 `name`、`type` 和 `note`，因此列表页（以及 `vault_list`）永远不会泄露凭据内容。

---

## 远程 MCP 客户端

将 MCP 客户端指向 `http://<主机>:8080/mcp`，并以用户的 `mcp_token` 作为 **Bearer** 令牌鉴权。四个工具 —— `vault_save`、`vault_get`、`vault_list`、`vault_delete` —— 只作用于该用户自己的命名空间。此外还有一个**AI 盲调**工具：

* **`vault_http(name, url, method, headers, body, secret_header)`** —— 服务端取出凭据后注入请求（在请求头或请求体中使用 `{{secret}}` 占位符，或指定 `secret_header`），代发请求并只返回 HTTP 响应内容。秘密**永远不会**返回给模型，并且会从响应中被抹除。仅允许 `https`；可选配置 `http.allow_hosts` 限制目标主机。当 AI 只需要"调用"某个 API 而不需要看到秘密时，应使用此工具而非 `vault_get`。

### 防 DNS 重绑定

`/mcp` 接口会校验 `Host` 头，未列入白名单的请求返回 **HTTP 421**。请在 `config.yaml` 中填写你的对外域名：

```yaml
mcp:
  allowed_hosts:
    - vault.example.com
    - 127.0.0.1:8080
    - localhost:8080
```

`allowed_origins` 默认等于 `https://<每个 allowed_host>`。该保护**不可关闭** —— 它是刻意设置的防 DNS 重绑定措施。

WorkBuddy 的 `mcp.json` 配置示例：

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

> 注意：客户端必须支持**远程（URL 型）MCP**。若只支持本地 stdio，可在服务器上运行 `python -m vault_mcp.stdio` 后通过 stdio 连接，或在前面加一层本地 stdio 转 HTTP 的代理。

---

## 目录结构

| 路径 | 作用 |
|------|------|
| `vault_mcp/vault_core.py` | 加密与多用户加密存储（标准库 + `cryptography`） |
| `vault_mcp/auth.py` | scrypt 口令哈希、TOTP（RFC 6238）、HMAC 会话令牌 |
| `vault_mcp/config.py` | 读写 `config.yaml`、用户增删改查、角色判定、Web 加固与人机验证设置、双因素状态持久化 |
| `vault_mcp/captcha.py` | 登录人机验证：图片渲染、一次性答案存储、Cloudflare Turnstile 校验 |
| `vault_mcp/server.py` | FastAPI 应用：Web 控制台 + 远程 MCP（`/mcp`） |
| `vault_mcp/stdio.py` | 本地 **stdio** MCP 服务（供本机智能体使用） |
| `vault_mcp/cli.py` | 运维命令行，用于预置用户与令牌 |
| `vault_mcp/__main__.py` | `python -m vault_mcp` 入口（启动服务） |
| `pyproject.toml` | 包元数据、依赖、命令行入口 |
| `deploy/` | systemd 单元、nginx TLS 反向代理、`.env` 模板 |
| `config.example.yaml` | 运维配置模板（用户 + 服务 + 保险库目录） |

> ⚠️ **修改 Web 模板前必读**
>
> `vault_mcp/server.py` 中的 `DASH_TPL_SRC` / `LOGIN_TPL_SRC` 是**非 raw** 的三引号
> Python 字符串，内部嵌有 JavaScript。在其中写入 `\n` 会被 Python 编译成**真实换行**，
> 从而劈开 JS 字符串字面量，使整段 `<script>` 报
> `SyntaxError: Invalid or unexpected token` —— 页面上所有事件处理器会静默失效
> （表现为标签页点不动、类型下拉看着是空的）。**注释里的 `\n` 同样会中招。**
>
> 请写成 `\\n`，或改用 `['a','b'].join(NL)` 并显式定义 `const NL='\\n';`。
>
> 为防止再次复发，服务会在 **import 阶段**执行一次自检：读取 `.py` 源文件，
> 在 `<script>……</script>` 区域内扫描该序列，命中即抛错并给出精确行号。
> 注意这个错误**无法**通过检查运行时字符串发现（编译后反斜杠已消失），
> 因此自检必须查看原始源码。

---

## 生产部署（systemd + nginx）

[`deploy/`](deploy/) 目录下的文件可把服务部署到 Linux 服务器并由 TLS 保护：

```bash
# 1. 以专用的非特权用户安装
useradd --system --home /opt/vault-mcp-server --create-home vault
git clone https://github.com/LianghaiLi-root/vault-mcp-server.git /opt/vault-mcp-server
cd /opt/vault-mcp-server
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 2. 生成配置与密钥
cp config.example.yaml config.yaml
.venv/bin/python -m vault_mcp.cli add-user admin --role admin
cp deploy/env.example .env
#   编辑 .env：设置 VAULT_MASTER_PASSWORD（openssl rand -hex 32），然后 chmod 600 .env

# 3. systemd
cp deploy/vault-mcp.service /etc/systemd/system/
mkdir -p /var/lib/vault-mcp && chown -R vault:vault /var/lib/vault-mcp
systemctl daemon-reload && systemctl enable --now vault-mcp

# 4. nginx（TLS）
cp deploy/nginx-vault-mcp.conf /etc/nginx/sites-available/vault-mcp.conf
ln -s /etc/nginx/sites-available/vault-mcp.conf /etc/nginx/sites-enabled/
#   修改 server_name 与证书路径，然后执行：nginx -t && systemctl reload nginx
```

systemd 单元只把 uvicorn 绑定在 `127.0.0.1:8080`；nginx 负责终结 TLS，并反向代理 `/`（Web 控制台）与 `/mcp`（远程 MCP）。启用 TLS 后应设置 `VAULT_COOKIE_SECURE=1`。

> **systemd 沙箱注意事项**：随附的单元使用 `ProtectSystem=full`，并通过
> `ReadWritePaths=/var/lib/vault-mcp /opt/vault-mcp-server` 授予写权限，
> 再用 `ReadOnlyPaths` 把代码目录单独钉为只读。**请勿改成 `ProtectSystem=strict`**：
> 它会把整个文件系统重新挂载为只读，而 systemd 会**静默忽略**嵌套在只读树内部的
> `ReadWritePaths` 条目，导致所有管理端写操作失败并报
> `[Errno 30] Read-only file system: '.../config.yaml.tmp'`。

---

## 安全清单

- [ ] `VAULT_MASTER_PASSWORD` 由密钥管理系统提供，绝不提交到代码仓库。
- [ ] 前置 TLS（反向代理 / Cloudflare）；设置 `VAULT_COOKIE_SECURE=1`。
- [ ] `config.yaml`（含口令哈希与 Token）不提交，已在 `.gitignore` 中排除。
- [ ] 首次登录后为每个用户启用双因素。
- [ ] 对 `/login` 与 `/mcp` 接口做限流 / WAF。
- [ ] 若登录页可被公网访问，建议启用一种人机验证方式。

---

## 许可证

MIT —— 详见 [`LICENSE`](LICENSE)。
