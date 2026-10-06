#!/usr/bin/env python3
"""
server.py — deployable Vault MCP server (FastAPI).

One process serves BOTH:
  * a multi-user web console  (login + 2FA + per-user credential management)
  * a remote MCP endpoint     (/mcp, Streamable HTTP) for AI clients

Users are pre-provisioned in config.yaml (username + scrypt password_hash +
mcp_token). After login a user may enroll a TOTP second factor (Google
Authenticator compatible); the enrolled secret is stored in the runtime user
state file, not the operator config.

Security notes
--------------
* The MCP endpoint requires `Authorization: Bearer <mcp_token>`; the token maps
  to a user, and every MCP tool only ever touches that user's vault namespace.
* The web console issues HMAC-signed, HttpOnly session cookies. Set
  VAULT_COOKIE_SECURE=1 behind TLS in production.
* The server is trusted: on Linux it runs in PBKDF2 mode and can decrypt every
  user's vault (that is the point of a hosted vault). Protect VAULT_MASTER_PASSWORD.
"""

import os
import json
import hmac
import asyncio
import contextlib
import contextvars
import urllib.request
import urllib.error
import urllib.parse

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from jinja2 import Template
from mcp.server.fastmcp import FastMCP

from . import auth, vault_core
from . import config
from . import __version__

auth_user_ctx = contextvars.ContextVar("auth_user", default=None)

cfg = config.load_config()


# --------------------------------------------------------------------------
# Credential type catalog — drives both the web form and the /api/types schema.
# Each field: key, label, kind (text|password|textarea), secret (bool), default.
# Add new common types here; the UI renders them automatically.
# --------------------------------------------------------------------------
CRED_TYPES = {
    "generic": {
        "label": "通用 / 密码",
        "fields": [
            {"key": "value", "label": "秘密 / 密码", "kind": "textarea", "secret": True},
        ],
    },
    "ssh": {
        "label": "SSH 服务器",
        "fields": [
            {"key": "host", "label": "主机 / IP", "kind": "text", "secret": False},
            {"key": "port", "label": "端口", "kind": "text", "secret": False, "default": "22"},
            {"key": "username", "label": "用户名", "kind": "text", "secret": False},
            {"key": "password", "label": "密码", "kind": "password", "secret": True},
            {"key": "private_key", "label": "私钥", "kind": "textarea", "secret": True},
        ],
    },
    "web": {
        "label": "网站 / 账号",
        "fields": [
            {"key": "url", "label": "网址 URL", "kind": "text", "secret": False},
            {"key": "username", "label": "用户名 / 邮箱", "kind": "text", "secret": False},
            {"key": "password", "label": "密码", "kind": "password", "secret": True},
        ],
    },
    "api": {
        "label": "API / Token",
        "fields": [
            {"key": "token", "label": "Token / API Key", "kind": "textarea", "secret": True},
            {"key": "url", "label": "接口地址 URL", "kind": "text", "secret": False},
        ],
    },
    "db": {
        "label": "数据库",
        "fields": [
            {"key": "host", "label": "主机", "kind": "text", "secret": False},
            {"key": "port", "label": "端口", "kind": "text", "secret": False},
            {"key": "database", "label": "数据库名", "kind": "text", "secret": False},
            {"key": "username", "label": "用户名", "kind": "text", "secret": False},
            {"key": "password", "label": "密码", "kind": "password", "secret": True},
        ],
    },
}
TYPE_LABELS = {k: v["label"] for k, v in CRED_TYPES.items()}


# --------------------------------------------------------------------------
# Templates (inline, autoescaped)
# --------------------------------------------------------------------------
# Shared modern "glassmorphism" design system, used by both templates.
GLASS_CSS = """
:root{
  color-scheme:dark;
  --bg:#0b0f16;
  --panel:rgba(255,255,255,.055);
  --panel-strong:rgba(255,255,255,.085);
  --stroke:rgba(255,255,255,.12);
  --stroke-soft:rgba(255,255,255,.07);
  --txt:#eaeef6;
  --txt-dim:#9aa6b8;
  --txt-mute:#6b7688;
  --accent:#5b8cff;
  --accent-2:#8b5cf6;
  --ok:#5ee2a0;
  --err:#ff8f9c;
  --radius:18px;
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;color:var(--txt);
  font-family:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  background:var(--bg);
  -webkit-font-smoothing:antialiased;
}
/* animated aurora backdrop */
body::before{
  content:"";position:fixed;inset:-25%;z-index:-2;pointer-events:none;
  background:
    radial-gradient(38% 42% at 18% 22%, rgba(91,140,255,.42), transparent 68%),
    radial-gradient(34% 38% at 82% 26%, rgba(139,92,246,.34), transparent 68%),
    radial-gradient(42% 44% at 62% 84%, rgba(20,196,190,.26), transparent 70%);
  filter:blur(70px) saturate(135%);
  animation:drift 26s ease-in-out infinite alternate;
}
body::after{
  content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:linear-gradient(180deg,rgba(8,11,17,.5),rgba(8,11,17,.86));
}
@keyframes drift{
  0%{transform:translate3d(0,0,0) scale(1)}
  50%{transform:translate3d(2.5%,-2%,0) scale(1.07)}
  100%{transform:translate3d(-2%,2.5%,0) scale(1.03)}
}
@media (prefers-reduced-motion:reduce){body::before{animation:none}}

.glass{
  background:var(--panel);
  border:1px solid var(--stroke);
  border-radius:var(--radius);
  backdrop-filter:blur(22px) saturate(150%);
  -webkit-backdrop-filter:blur(22px) saturate(150%);
  box-shadow:0 18px 48px rgba(0,0,0,.44), inset 0 1px 0 rgba(255,255,255,.09);
}
h1,h2,h3{font-weight:650;letter-spacing:.2px}
a{color:#a9c6ff;text-decoration:none}
a:hover{text-decoration:underline}
label{display:block;font-size:12.5px;color:var(--txt-dim);margin:12px 0 6px;font-weight:500}
input[type=text],input[type=password],input[type=email],textarea,select{
  width:100%;background:rgba(9,12,18,.62);border:1px solid var(--stroke-soft);
  color:var(--txt);border-radius:11px;padding:11px 12px;font-size:14px;
  outline:none;transition:border-color .18s,box-shadow .18s,background .18s;
  font-family:inherit;
}
input:focus,textarea:focus,select:focus{
  border-color:rgba(91,140,255,.72);
  box-shadow:0 0 0 3px rgba(91,140,255,.17);
  background:rgba(9,12,18,.8);
}
textarea{resize:vertical;min-height:64px}
select{appearance:none;background-image:linear-gradient(45deg,transparent 50%,#8b95a1 50%),linear-gradient(135deg,#8b95a1 50%,transparent 50%);background-position:calc(100% - 18px) 50%,calc(100% - 13px) 50%;background-size:5px 5px,5px 5px;background-repeat:no-repeat;padding-right:34px}
button{
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  color:#fff;border:0;border-radius:11px;padding:10px 18px;font-size:14px;
  font-weight:600;cursor:pointer;font-family:inherit;
  transition:transform .14s,box-shadow .18s,filter .18s;
  box-shadow:0 8px 22px rgba(91,140,255,.28);
}
button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:active{transform:translateY(0)}
button.ghost{
  background:var(--panel-strong);color:var(--txt);border:1px solid var(--stroke);
  box-shadow:none;font-weight:500;
}
button.ghost:hover{background:rgba(255,255,255,.13)}
button.del{background:rgba(255,90,110,.14);color:var(--err);border:1px solid rgba(255,90,110,.28);padding:6px 12px;font-size:12px;box-shadow:none;font-weight:500}
button.del:hover{background:rgba(255,90,110,.24)}
button.mini{background:var(--panel-strong);color:#a9c6ff;border:1px solid var(--stroke);padding:6px 12px;font-size:12px;box-shadow:none;font-weight:500}
button.mini:hover{background:rgba(255,255,255,.13)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:11px 10px;border-bottom:1px solid var(--stroke-soft)}
th{color:var(--txt-mute);font-weight:600;font-size:11.5px;letter-spacing:.6px;text-transform:uppercase}
tbody tr{transition:background .16s}
tbody tr:hover{background:rgba(255,255,255,.04)}
tbody tr:last-child td{border-bottom:0}
code{color:#8fd3ff;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
pre{background:rgba(9,12,18,.68);border:1px solid var(--stroke-soft);padding:12px;border-radius:11px;overflow:auto;font-size:12px;color:#8fd3ff;margin:8px 0}
.muted{color:var(--txt-mute)}
.ok{color:var(--ok)}
.err{color:var(--err)}
.msg{font-size:13px;min-height:18px;margin-top:8px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.badge{
  display:inline-block;background:rgba(91,140,255,.16);color:#a9c6ff;
  border:1px solid rgba(91,140,255,.28);border-radius:999px;padding:3px 11px;
  font-size:11.5px;font-weight:600;letter-spacing:.3px;
}
.badge.ssh{background:rgba(94,226,160,.14);color:#7ce8b4;border-color:rgba(94,226,160,.3)}
.badge.web{background:rgba(139,92,246,.16);color:#c4a8ff;border-color:rgba(139,92,246,.32)}
.badge.api{background:rgba(255,190,90,.14);color:#ffd08a;border-color:rgba(255,190,90,.3)}
.badge.db{background:rgba(20,196,190,.14);color:#7ce4e0;border-color:rgba(20,196,190,.3)}
.empty{padding:26px;text-align:center;color:var(--txt-mute);font-size:14px}
"""

LOGIN_TPL = Template("""
<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>凭据库 · 登录</title>
<style>""" + GLASS_CSS + """
 .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
 .box{width:100%;max-width:380px;padding:34px 30px}
 .brand{display:flex;align-items:center;gap:11px;margin-bottom:6px}
 .logo{
   width:40px;height:40px;border-radius:12px;display:grid;place-items:center;font-size:20px;
   background:linear-gradient(135deg,var(--accent),var(--accent-2));
   box-shadow:0 8px 22px rgba(91,140,255,.36);
 }
 h1{font-size:19px;margin:0}
 .sub{color:var(--txt-mute);font-size:12.5px;margin:2px 0 22px}
 button[type=submit]{width:100%;margin-top:22px;padding:12px}
 .alert{
   display:none;background:rgba(255,90,110,.13);border:1px solid rgba(255,90,110,.3);
   color:var(--err);border-radius:11px;padding:10px 13px;font-size:13px;margin-top:18px;
 }
 .alert.show{display:block}
 .foot{margin-top:20px;text-align:center;font-size:11.5px;color:var(--txt-mute)}
</style></head><body>
<div class="wrap"><div class="glass box">
 <div class="brand">
   <div class="logo">🔐</div>
   <div><h1>凭据库</h1></div>
 </div>
 <div class="sub">加密凭据管理 · 多用户隔离</div>
 <form method="post" action="/login">
  <label>用户名</label><input name="username" autocomplete="username" required autofocus>
  <label>密码</label><input name="password" type="password" autocomplete="current-password" required>
  <label>2FA 验证码（已启用时必填）</label><input name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="6 位数字" maxlength="6">
  <button type="submit">登 录</button>
 </form>
 <div class="alert {{ 'show' if error else '' }}">{{ error }}</div>
 <div class="foot">AES-256-GCM · scrypt · TOTP</div>
</div></div></body></html>""", autoescape=True)


DASH_TPL = Template("""
<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>凭据库 · {{ user }}</title>
<style>""" + GLASS_CSS + """
 .shell{max-width:1020px;margin:0 auto;padding:26px 20px 56px}
 header.bar{
   display:flex;align-items:center;justify-content:space-between;gap:14px;
   padding:15px 20px;margin-bottom:20px;flex-wrap:wrap;
 }
 .brand{display:flex;align-items:center;gap:12px}
 .logo{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:18px;
   background:linear-gradient(135deg,var(--accent),var(--accent-2));
   box-shadow:0 8px 20px rgba(91,140,255,.34)}
 .brand h1{font-size:17px;margin:0}
 .brand .who{font-size:12px;color:var(--txt-mute);margin-top:2px}
 .card{padding:20px;margin-bottom:18px}
 .card h2{font-size:14.5px;margin:0 0 4px;display:flex;align-items:center;gap:8px}
 .card .hint{font-size:12.5px;color:var(--txt-mute);margin-bottom:14px}
 .tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
 .tab{
   padding:8px 15px;border-radius:11px;font-size:13.5px;cursor:pointer;border:1px solid transparent;
   color:var(--txt-dim);background:transparent;box-shadow:none;font-weight:500;
 }
 .tab:hover{background:rgba(255,255,255,.07);filter:none;transform:none}
 .tab.on{background:var(--panel-strong);border-color:var(--stroke);color:var(--txt);font-weight:600}
 .tab.on:hover{background:var(--panel-strong)}
 .pane{display:none} .pane.on{display:block}
 .grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}
 @media (max-width:640px){.grid2{grid-template-columns:1fr}}
 .tablewrap{overflow-x:auto;margin:-4px -6px;padding:0 6px}
 #editbanner{
   display:none;background:rgba(91,140,255,.14);border:1px solid rgba(91,140,255,.3);
   color:#a9c6ff;border-radius:11px;padding:9px 13px;margin-bottom:14px;font-size:13px;
 }
 .kv{display:flex;justify-content:space-between;gap:10px;padding:9px 0;border-bottom:1px solid var(--stroke-soft);font-size:13.5px}
 .kv:last-child{border-bottom:0}
 .kv .k{color:var(--txt-mute)}
 .danger-zone{border-color:rgba(255,90,110,.26)}
 .switchrow{display:flex;align-items:center;gap:10px;font-size:13.5px;color:var(--txt-dim)}
</style></head><body>
<div class="shell">

 <header class="glass bar">
  <div class="brand">
    <div class="logo">🔐</div>
    <div>
      <h1>凭据库</h1>
      <div class="who"><code>{{ user }}</code> · 模式 <code>{{ mode }}</code></div>
    </div>
  </div>
  <div class="row">
    <a href="/mcp" target="_blank" class="muted" style="font-size:12.5px">MCP 端点</a>
    <form method="post" action="/logout" style="margin:0">
      <button class="ghost" type="submit">退出登录</button>
    </form>
  </div>
 </header>

 <div class="tabs">
   <button class="tab on" data-pane="vault">凭据管理</button>
   <button class="tab" data-pane="security">安全设置</button>
   <button class="tab" data-pane="ops">运维 / 用户</button>
 </div>

 <!-- ============ 凭据管理 ============ -->
 <section id="pane-vault" class="pane on">
  <div class="glass card">
   <h2>➕ 添加 / 修改凭据</h2>
   <div class="hint">选择类型后自动显示对应字段；填写时敏感项会以密文存储。</div>
   <div id="editbanner"></div>
   <form id="add">
    <input type="hidden" id="original_name" value="">
    <div class="grid2">
      <div><label>标识名（唯一，如 github_pat / myserver）</label>
        <input type="text" id="f_name" required placeholder="myserver" autocomplete="off"></div>
      <div><label>类型</label><select id="type"></select></div>
    </div>
    <div id="dynfields"></div>
    <label>备注（明文，可选）</label>
    <input type="text" id="f_note" placeholder="例如：生产环境跳板机" autocomplete="off">
    <div style="margin-top:16px" class="row">
      <button type="submit" id="submitbtn">加密保存</button>
      <button type="button" class="ghost" id="cancelbtn" style="display:none">取消修改</button>
    </div>
   </form>
   <div class="msg" id="addmsg"></div>
  </div>

  <div class="glass card">
   <h2>📋 已保存凭据</h2>
   <div class="hint">共 {{ items|length }} 条。所有值均以 AES-256-GCM 加密存储。</div>
   <div class="tablewrap">
   <table><thead><tr><th>标识名</th><th>类型</th><th>备注</th><th>更新时间</th><th style="text-align:right">操作</th></tr></thead>
   <tbody id="rows">
    {% for it in items %}<tr>
      <td><code>{{ it.name }}</code></td>
      <td><span class="badge {{ it.type }}">{{ type_labels.get(it.type, it.type) }}</span></td>
      <td class="muted">{{ it.note }}</td>
      <td class="muted" style="font-size:12.5px">{{ it.updated[:19].replace('T',' ') }}</td>
      <td style="text-align:right;white-space:nowrap">
        <button class="mini" data-name="{{ it.name }}">修改</button>
        <button class="del" data-name="{{ it.name }}">删除</button>
      </td>
    </tr>{% endfor %}
    {% if not items %}<tr><td colspan="5"><div class="empty">暂无凭据，先在上方添加一条吧</div></td></tr>{% endif %}
   </tbody></table>
   </div>
  </div>
 </section>

 <!-- ============ 安全设置 ============ -->
 <section id="pane-security" class="pane">
  <div class="glass card">
   <h2>🔑 两步验证 (2FA)</h2>
   <div class="hint">使用 Google Authenticator / Authy 等应用扫描或手动录入密钥。</div>
   {% if totp_confirmed %}
    <div class="kv"><span class="k">状态</span><span class="ok">✓ 已启用</span></div>
    <div style="margin-top:14px">
      <button class="ghost" id="reset2fa">重置 2FA 密钥</button>
      <div class="msg" id="totpmsg"></div>
    </div>
   {% elif totp_secret %}
    <div class="kv"><span class="k">状态</span><span style="color:#ffd08a">待验证</span></div>
    <label style="margin-top:14px">otpauth 链接（可粘贴到验证器）</label>
    <pre>{{ totp_uri }}</pre>
    <label>手动密钥</label>
    <pre>{{ totp_secret }}</pre>
    <div class="row" style="margin-top:14px">
      <input type="text" id="totpcode" placeholder="6 位验证码" inputmode="numeric" maxlength="6" style="max-width:170px">
      <button id="confirm2fa">验证并启用</button>
    </div>
    <div class="msg" id="totpmsg"></div>
   {% else %}
    <div class="kv"><span class="k">状态</span><span class="muted">未启用</span></div>
    <div style="margin-top:14px">
      <button id="enroll2fa">启用 Google 身份验证器</button>
      <div class="msg" id="totpmsg"></div>
    </div>
   {% endif %}
  </div>

  <div class="glass card">
   <h2>🔒 会话与令牌</h2>
   <div class="hint">MCP 客户端使用 Bearer Token 访问 /mcp 端点。</div>
   <div class="kv"><span class="k">当前用户</span><code>{{ user }}</code></div>
   <div class="kv"><span class="k">MCP Token</span>
     <span><code id="tokview">••••••••••••••••</code>
     <button class="mini" id="toktoggle" style="margin-left:8px">显示</button></span></div>
   <div class="row" style="margin-top:14px">
     <button class="mini" id="tokregen">重新生成 Token</button>
     <button class="mini" id="tokcopy">复制</button>
   </div>
   <div class="msg" id="tokmsg"></div>
  </div>

  <div class="glass card">
   <h2>🔐 修改登录密码</h2>
   <label>当前密码</label><input type="password" id="pw_cur" autocomplete="current-password">
   <div class="grid2">
     <div><label>新密码</label><input type="password" id="pw_new" autocomplete="new-password"></div>
     <div><label>确认新密码</label><input type="password" id="pw_new2" autocomplete="new-password"></div>
   </div>
   <div style="margin-top:16px"><button id="pwsubmit">更新密码</button></div>
   <div class="msg" id="pwmsg"></div>
  </div>
 </section>

 <!-- ============ 运维 / 用户 ============ -->
 <section id="pane-ops" class="pane">
  <div class="glass card">
   <h2>🖥️ 服务器状态</h2>
   <div class="hint">后端运行信息一览。</div>
   <div class="kv"><span class="k">存储模式</span><code>{{ mode }}</code></div>
   <div class="kv"><span class="k">凭据总数</span><code>{{ items|length }}</code></div>
   <div class="kv"><span class="k">用户总数</span><code>{{ users|length }}</code></div>
   <div class="kv"><span class="k">服务版本</span><code>{{ version }}</code></div>
   <div class="kv"><span class="k">运行平台</span><code>{{ platform }}</code></div>
   <div style="margin-top:14px"><button class="mini" id="oprefresh">刷新</button></div>
  </div>

  <div class="glass card">
   <h2>👥 用户管理</h2>
   <div class="hint">添加用户、重置密码、重置 2FA、重新签发 MCP Token。变更立即写入 config.yaml。</div>
   <div class="tablewrap">
   <table><thead><tr><th>用户名</th><th>MCP Token</th><th>2FA</th><th style="text-align:right">操作</th></tr></thead>
   <tbody id="userrows">
    {% for u in users %}<tr data-user="{{ u.username }}">
      <td><code>{{ u.username }}</code>{% if u.username == user %} <span class="badge">当前</span>{% endif %}</td>
      <td class="muted" style="font-size:12.5px">{{ '已配置' if u.has_token else '缺失' }}</td>
      <td>{% if u.totp == 'enabled' %}<span class="ok">已启用</span>{% elif u.totp == 'pending' %}<span style="color:#ffd08a">待验证</span>{% else %}<span class="muted">未启用</span>{% endif %}</td>
      <td style="text-align:right;white-space:nowrap">
        <button class="mini" data-act="pw" data-user="{{ u.username }}">改密码</button>
        <button class="mini" data-act="2fa" data-user="{{ u.username }}">重置2FA</button>
        <button class="mini" data-act="tok" data-user="{{ u.username }}">重签Token</button>
        {% if u.username != user %}<button class="del" data-act="del" data-user="{{ u.username }}">删除</button>{% endif %}
      </td>
    </tr>{% endfor %}
   </tbody></table>
   </div>
   <div style="margin-top:16px" class="row">
     <input type="text" id="newuser" placeholder="新用户名" autocomplete="off" style="max-width:200px">
     <button id="adduser">添加用户</button>
   </div>
   <div class="msg" id="usermsg"></div>
  </div>

  <div class="glass card">
   <h2>⚙️ SSH 快捷运维</h2>
   <div class="hint">生成可直接粘贴到终端执行的命令（不在此处执行远程命令）。</div>
   <div class="grid2">
     <div><label>目标主机 / 别名</label><input type="text" id="ssh_host" placeholder="myserver"></div>
     <div><label>SSH 用户</label><input type="text" id="ssh_user" placeholder="root"></div>
   </div>
   <label>要生成的操作</label>
   <select id="ssh_action">
     <option value="ssh-keygen">初始化 SSH 密钥对 (ssh-keygen)</option>
     <option value="ssh-copy-id">推送公钥到服务器 (ssh-copy-id)</option>
     <option value="ssh-connect">测试连接 (ssh -v)</option>
     <option value="ssh-config">写入 ~/.ssh/config 别名</option>
     <option value="ssh-add">加入 ssh-agent (ssh-add)</option>
     <option value="ssh-useradd">远端新增用户 (useradd + sudo)</option>
     <option value="ssh-passwd">远端修改用户密码 (passwd)</option>
     <option value="ssh-authkeys">远端部署 authorized_keys</option>
     <option value="ssh-disable-pw">远端关闭 SSH 密码登录</option>
   </select>
   <div style="margin-top:16px"><button class="mini" id="sshgen">生成命令</button></div>
   <pre id="sshout" style="display:none"></pre>
   <div class="msg" id="sshmsg"></div>
  </div>

  <div class="glass card danger-zone">
   <h2>🧹 维护操作</h2>
   <div class="hint">清理本命名空间的空记录等维护动作。</div>
   <div class="row">
     <button class="mini" id="repair">校验并整理凭据存储</button>
   </div>
   <div class="msg" id="opsmsg"></div>
  </div>
 </section>

</div>

<script>
(async ()=>{
 const $=id=>document.getElementById(id);
 async function j(url, method, body){
   const opt={method:method||'GET', headers:{'Content-Type':'application/json'}};
   if(body!==undefined) opt.body=JSON.stringify(body);
   const r=await fetch(url, opt);
   let d; try{ d=await r.json(); }catch(e){ d={ok:false, error:'HTTP '+r.status}; }
   return d;
 }
 function say(el, ok, text){ const n=$(el); n.className='msg '+(ok?'ok':'err'); n.textContent=text; }

 // ---- tabs ----
 document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
   document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));
   document.querySelectorAll('.pane').forEach(x=>x.classList.remove('on'));
   t.classList.add('on'); $('pane-'+t.dataset.pane).classList.add('on');
 });

 // ---- credential form ----
 const TYPES = await (await fetch('/api/types')).json();
 const typeFields=t=>(TYPES[t]&&TYPES[t].fields)||[];
 const sel=$('type');
 for(const [k,v] of Object.entries(TYPES)){
   const o=document.createElement('option'); o.value=k; o.textContent=v.label; sel.appendChild(o);
 }
 function renderFields(type, values){
   values=values||{}; const box=$('dynfields'); box.innerHTML='';
   const fs=typeFields(type);
   const wrap=document.createElement('div'); wrap.className = fs.length>2 ? 'grid2' : '';
   fs.forEach(f=>{
     const lab=document.createElement('label'); lab.textContent=f.label;
     const inp=document.createElement(f.kind==='textarea'?'textarea':'input');
     if(f.kind!=='textarea') inp.type=f.secret?'password':'text';
     inp.name=f.key;
     let val=values[f.key]; if(val==null&&f.default!=null) val=f.default;
     if(val!=null) inp.value=val;
     lab.appendChild(inp); wrap.appendChild(lab);
   });
   box.appendChild(wrap);
 }
 function collectFields(){
   const type=sel.value,out={};
   typeFields(type).forEach(f=>{const el=document.querySelector('#dynfields [name="'+f.key+'"]'); if(el) out[f.key]=el.value;});
   return out;
 }
 function resetForm(){
   $('original_name').value=''; $('f_name').value=''; $('f_note').value='';
   sel.value='generic'; renderFields('generic',{});
   $('submitbtn').textContent='加密保存'; $('cancelbtn').style.display='none';
   $('editbanner').style.display='none';
 }
 renderFields('generic',{});
 $('cancelbtn').onclick=resetForm;
 sel.onchange=()=>renderFields(sel.value, collectFields());
 $('add').onsubmit=async e=>{
   e.preventDefault();
   const orig=$('original_name').value;
   const body={name:$('f_name').value.trim(), type:sel.value, fields:collectFields(), note:$('f_note').value};
   if(orig) body.original_name=orig;
   const d=await j('/api/credentials','POST',body);
   say('addmsg', d.ok, d.ok?('✓ 已保存 '+d.name):('错误：'+d.error));
   if(d.ok) setTimeout(()=>location.reload(), 450);
 };
 document.querySelectorAll('button.del[data-name]').forEach(b=>b.onclick=async()=>{
   if(!confirm('确认删除 '+b.dataset.name+' ?')) return;
   const d=await j('/api/credentials/'+encodeURIComponent(b.dataset.name),'DELETE');
   if(d.ok) location.reload(); else alert(d.error);
 });
 document.querySelectorAll('button.mini[data-name]').forEach(b=>b.onclick=async()=>{
   const d=await j('/api/credentials/'+encodeURIComponent(b.dataset.name),'GET');
   if(!d.ok){ alert(d.error); return; }
   $('original_name').value=d.name; $('f_name').value=d.name; $('f_note').value=d.note||'';
   sel.value=d.type; renderFields(d.type, d.fields||{});
   $('submitbtn').textContent='保存修改'; $('cancelbtn').style.display='inline-block';
   const bn=$('editbanner'); bn.style.display='block'; bn.textContent='✎ 正在修改：'+d.name;
   document.querySelector('.tab[data-pane="vault"]').click();
   window.scrollTo({top:0,behavior:'smooth'});
 });

 // ---- 2FA ----
 const en=$('enroll2fa'); if(en) en.onclick=async()=>{const d=await j('/api/totp/enroll','POST',{}); if(d.ok)location.reload(); else say('totpmsg',false,d.error);};
 const cf=$('confirm2fa'); if(cf) cf.onclick=async()=>{
   const d=await j('/api/totp/confirm','POST',{code:$('totpcode').value});
   if(d.ok) location.reload(); else say('totpmsg',false,'验证失败：'+d.error);
 };
 const rs=$('reset2fa'); if(rs) rs.onclick=async()=>{
   if(!confirm('重置后需重新绑定验证器，确认？')) return;
   const d=await j('/api/totp/reset','POST',{});
   if(d.ok) location.reload(); else say('totpmsg',false,d.error);
 };

 // ---- token ----
 let tokRaw=null, tokShown=false;
 const tv=$('tokview'), tt=$('toktoggle');
 if(tt) tt.onclick=async()=>{
   if(tokRaw===null){ const d=await j('/api/token','GET'); if(!d.ok){say('tokmsg',false,d.error);return;} tokRaw=d.token||''; }
   tokShown=!tokShown; tv.textContent = tokShown ? (tokRaw||'(未设置)') : '••••••••••••••••';
   tt.textContent = tokShown ? '隐藏' : '显示';
 };
 const tc=$('tokcopy'); if(tc) tc.onclick=async()=>{
   if(tokRaw===null){ const d=await j('/api/token','GET'); if(d.ok) tokRaw=d.token||''; }
   if(!tokRaw){ say('tokmsg',false,'无 Token 可复制'); return; }
   try{ await navigator.clipboard.writeText(tokRaw); say('tokmsg',true,'✓ 已复制到剪贴板'); }
   catch(e){ say('tokmsg',false,'复制失败，请手动选择'); }
 };
 const tr=$('tokregen'); if(tr) tr.onclick=async()=>{
   if(!confirm('重新生成后，旧 Token 立即失效，需要更新 MCP 客户端配置。继续？')) return;
   const d=await j('/api/token/regenerate','POST',{});
   if(d.ok){ tokRaw=d.token; tokShown=true; tv.textContent=d.token; tt.textContent='隐藏'; say('tokmsg',true,'✓ 已生成新 Token，请立即复制保存'); }
   else say('tokmsg',false,d.error);
 };

 // ---- password ----
 const ps=$('pwsubmit'); if(ps) ps.onclick=async()=>{
   const cur=$('pw_cur').value, n1=$('pw_new').value, n2=$('pw_new2').value;
   if(!n1){ say('pwmsg',false,'新密码不能为空'); return; }
   if(n1!==n2){ say('pwmsg',false,'两次输入的新密码不一致'); return; }
   const d=await j('/api/password','POST',{current:cur, new:n1});
   if(d.ok){ say('pwmsg',true,'✓ 密码已更新'); $('pw_cur').value=$('pw_new').value=$('pw_new2').value=''; }
   else say('pwmsg',false,'失败：'+d.error);
 };

 // ---- user management ----
 const um=$('usermsg');
 document.querySelectorAll('button[data-act]').forEach(b=>b.onclick=async()=>{
   const act=b.dataset.act, uname=b.dataset.user;
   if(act==='pw'){
     const np=prompt('为 '+uname+' 设置新密码：'); if(!np) return;
     const d=await j('/api/admin/users/'+encodeURIComponent(uname)+'/password','POST',{password:np});
     say('usermsg', d.ok, d.ok?('✓ 已更新 '+uname+' 的密码'):('失败：'+d.error));
   } else if(act==='2fa'){
     if(!confirm('重置 '+uname+' 的 2FA 绑定？')) return;
     const d=await j('/api/admin/users/'+encodeURIComponent(uname)+'/2fa-reset','POST',{});
     if(d.ok){ say('usermsg',true,'✓ 已重置 '+uname+' 的 2FA'); setTimeout(()=>location.reload(),450);} else say('usermsg',false,d.error);
   } else if(act==='tok'){
     if(!confirm('为 '+uname+' 重新签发 MCP Token？旧 Token 将失效。')) return;
     const d=await j('/api/admin/users/'+encodeURIComponent(uname)+'/token','POST',{});
     if(d.ok) say('usermsg',true,'✓ 新 Token ('+uname+')：'+d.token); else say('usermsg',false,d.error);
   } else if(act==='del'){
     if(!confirm('删除用户 '+uname+'？其凭据数据将保留在磁盘但无法访问。')) return;
     const d=await j('/api/admin/users/'+encodeURIComponent(uname),'DELETE');
     if(d.ok){ say('usermsg',true,'✓ 已删除 '+uname); setTimeout(()=>location.reload(),450);} else say('usermsg',false,d.error);
   }
 });
 const au=$('adduser'); if(au) au.onclick=async()=>{
   const uname=$('newuser').value.trim(); if(!uname){ say('usermsg',false,'请输入用户名'); return; }
   const d=await j('/api/admin/users','POST',{username:uname});
   if(d.ok){ say('usermsg',true,'✓ 已添加 '+uname+'，初始 Token：'+d.token); $('newuser').value=''; setTimeout(()=>location.reload(),900); }
   else say('usermsg',false,'失败：'+d.error);
 };

 // ---- ssh command generator ----
 // NOTE: every newline inside a JS string literal MUST be written as \\n here,
 // otherwise Python turns it into a real line break and the whole <script>
 // dies with "Invalid or unexpected token" (which kills ALL page handlers).
 $('sshgen').onclick=()=>{
   const h=$('ssh_host').value.trim()||'myserver';
   const u=$('ssh_user').value.trim()||'root';
   const a=$('ssh_action').value;
   const target=u+'@'+h;
   const safe=h.replace(/[^a-zA-Z0-9_.-]/g,'_');
   const kf='~/.ssh/id_ed25519_'+safe;
   const NL='\\n';
   const map={
     'ssh-keygen':[
       'ssh-keygen -t ed25519 -a 100 -C "'+u+'@'+h+'" -f '+kf,
       'chmod 600 '+kf+' '+kf+'.pub',
     ].join(NL),
     'ssh-copy-id':'ssh-copy-id -i '+kf+'.pub '+target,
     'ssh-connect':'ssh -v -p 22 '+target,
     'ssh-config':[
       "cat >> ~/.ssh/config <<'EOF'",
       'Host '+h,
       '    HostName '+h,
       '    User '+u,
       '    IdentityFile '+kf,
       '    ServerAliveInterval 30',
       'EOF',
       'chmod 600 ~/.ssh/config',
     ].join(NL),
     'ssh-add':['ssh-add '+kf, 'ssh-add -l'].join(NL),
     'ssh-useradd':'ssh '+target+' "sudo useradd -m -s /bin/bash NEWUSER && sudo passwd NEWUSER"',
     'ssh-passwd':'ssh '+target+' "sudo passwd TARGETUSER"',
     'ssh-authkeys':'ssh '+target+' "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" < '+kf+'.pub',
     'ssh-disable-pw':'ssh '+target+' "sudo sed -i \\"s/^#*PasswordAuthentication.*/PasswordAuthentication no/\\" /etc/ssh/sshd_config && sudo systemctl restart sshd"',
   };
   $('sshout').style.display='block';
   $('sshout').textContent=map[a]||'';
   say('sshmsg',true,'✓ 已生成，点击代码块复制');
 };

 // ---- ops ----
 const rp=$('repair'); if(rp) rp.onclick=async()=>{
   const d=await j('/api/admin/repair','POST',{});
   say('opsmsg', d.ok, d.ok?('✓ '+d.message):('失败：'+d.error));
 };
})();
</script>
</body></html>""", autoescape=True)


# --------------------------------------------------------------------------
# MCP (remote, Streamable HTTP) — bearer-token authenticated, per-user
# --------------------------------------------------------------------------
# Mounted below at /mcp. Starlette's Mount strips the "/mcp" prefix before the
# sub-app sees the request, so this app must serve its own route at "/".
# (The FastMCP default is "/mcp", which 404s once it is mounted there.)
#
# DNS-rebinding protection stays ON; the allowed Host/Origin values come from
# config (`mcp.allowed_hosts` / `mcp.allowed_origins`) so a reverse-proxied
# deployment can whitelist its public domain instead of disabling the guard.
from mcp.server.transport_security import TransportSecuritySettings

_mcp_cfg = (cfg.get("mcp", {}) or {})
_allowed_hosts = list(_mcp_cfg.get("allowed_hosts", []) or [])
_allowed_origins = list(_mcp_cfg.get("allowed_origins", []) or [])
if _allowed_hosts:
    _allowed_origins = _allowed_origins or [f"https://{h}" for h in _allowed_hosts]

mcp = FastMCP(
    "vault-mcp-server",
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_allowed_hosts,
        allowed_origins=_allowed_origins,
    ),
)


def _ns() -> str | None:
    return auth_user_ctx.get()


@mcp.tool()
def vault_save(name: str, value: str, note: str = "", type: str = "generic",
              fields: dict = None) -> str:
    """Save or update a credential in the caller's encrypted vault namespace.

    `value` is the primary secret for a generic credential. For typed credentials
    (ssh/web/api/db) pass `type` and a `fields` dict instead; `value` then
    becomes the primary secret within `fields` automatically.
    """
    ns = _ns()
    if not ns:
        return "ERROR: unauthorized"
    try:
        f = dict(fields) if fields else {"value": value}
        r = vault_core.save_credential(ns, name, type, f, note)
        return f"Saved credential '{r['name']}' (type={r['type']})."
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_get(name: str) -> str:
    """Retrieve a stored credential value by name (plaintext, for immediate use)."""
    ns = _ns()
    if not ns:
        return "ERROR: unauthorized"
    try:
        return vault_core.get_credential(ns, name)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_list() -> str:
    """List the caller's credential names/notes/timestamps (never the values)."""
    ns = _ns()
    if not ns:
        return "ERROR: unauthorized"
    try:
        return json.dumps(vault_core.list_credentials(ns), ensure_ascii=False, indent=2)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_delete(name: str) -> str:
    """Delete a credential by name from the caller's vault namespace."""
    ns = _ns()
    if not ns:
        return "ERROR: unauthorized"
    try:
        if vault_core.delete_credential(ns, name):
            return f"Deleted credential '{name}'."
        return f"ERROR: '{name}' not found."
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def vault_http(name: str, url: str, method: str = "GET",
               headers: dict = None, body: str = None,
               secret_header: str = None, secret_scheme: str = "Bearer") -> str:
    """AI-BLIND HTTP client: call an API using a stored credential WITHOUT the
    secret ever leaving the server or being returned to you.

    The secret is injected server-side. Two ways to place it:
      * write the literal placeholder `{{secret}}` anywhere in `headers` values
        or `body`; it is replaced with the credential value, or
      * set `secret_header` (e.g. "Authorization") and the secret is sent as
        `<secret_scheme> <secret>` (e.g. "Bearer <secret>") automatically.

    Returns the HTTP status and (truncated) response body. The secret is
    redacted from the response and is never included in the output.

    Guards: only https is allowed; an optional host allow-list may be set in
    config under `http.allow_hosts`; responses are truncated to 64 KiB.
    """
    ns = _ns()
    if not ns:
        return "ERROR: unauthorized"
    try:
        secret = vault_core.get_credential(ns, name)
    except Exception as e:
        return f"ERROR: {e}"

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return "ERROR: only https URLs are allowed"
    allowed = (app.state.cfg.get("http", {}) or {}).get("allow_hosts")
    if allowed and parsed.hostname not in allowed:
        return f"ERROR: host '{parsed.hostname}' not in allow-list"

    hdrs = {k: (v or "").replace("{{secret}}", secret) for k, v in (headers or {}).items()}
    if secret_header:
        hdrs[secret_header] = f"{secret_scheme} {secret}" if secret_scheme else secret
    if body:
        body = body.replace("{{secret}}", secret)

    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    for k, v in hdrs.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        out, status = e.read(), e.code
    except Exception as e:
        return f"ERROR: {e}"

    MAX = 64 * 1024
    text = out.decode("utf-8", "replace")
    text = text.replace(secret, "***REDACTED***")  # never leak the secret back
    if len(text) > MAX:
        text = text[:MAX] + f"\n... (truncated, {len(text)} bytes total)"
    return f"HTTP {status}\n{text}"


mcp_app = mcp.streamable_http_app()      # creates mcp.session_manager lazily


# Starlette's Mount does NOT run a mounted sub-app's lifespan, so the
# StreamableHTTPSessionManager would never be started when we mount the MCP
# app under /mcp. mcp.session_manager is explicitly exposed by FastMCP for
# this "mount into a larger app" use case — drive its run() ourselves.
@contextlib.asynccontextmanager
async def _lifespan(app_: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(title="Vault MCP Server", lifespan=_lifespan)
app.state.cfg = cfg
app.mount("/mcp", mcp_app)


# --------------------------------------------------------------------------
# Auth middleware: resolve the acting user into a contextvar for both the web
# routes (session cookie) and the MCP endpoint (bearer token).
# --------------------------------------------------------------------------
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    user = None
    auth_hdr = request.headers.get("Authorization", "")
    if auth_hdr.startswith("Bearer "):
        user = config.find_user_by_token(app.state.cfg, auth_hdr[7:].strip())
    if user is None:
        sid = request.cookies.get("session")
        if sid:
            user = auth.verify_session(sid)
    auth_user_ctx.set(user)
    return await call_next(request)


def require_user(request: Request) -> str:
    user = auth_user_ctx.get()
    if not user:
        raise HTTPException(status_code=401, detail="unauthorized")
    return user


# --------------------------------------------------------------------------
# Web routes
# --------------------------------------------------------------------------
def _login_html(error: str = "", status_code: int = 200) -> HTMLResponse:
    """Always render the login page as text/html — returning a bare string makes
    FastAPI emit application/json, which the browser shows as escaped garbage."""
    return HTMLResponse(LOGIN_TPL.render(error=error), status_code=status_code)


@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = ""):
    return _login_html(error)


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), totp: str = Form("")):
    user_cfg = config.find_user(app.state.cfg, username)
    if not user_cfg or not auth.verify_password(password, user_cfg.get("password_hash", "")):
        return _login_html("用户名或密码错误", 401)
    state = config.load_user_state(username)
    if state.get("totp_confirmed"):
        if not auth.verify_totp(state.get("totp_secret", ""), totp):
            return _login_html("需要正确的 2FA 验证码", 401)
    token = auth.issue_session(username)
    secure = os.environ.get("VAULT_COOKIE_SECURE") == "1"
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("session", token, httponly=True, samesite="lax", secure=secure)
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("session")
    return resp


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    user = auth_user_ctx.get()
    if not user:
        return RedirectResponse("/login", status_code=303)
    state = config.load_user_state(user)
    secret = state.get("totp_secret")
    items = []
    mode = "n/a"
    try:
        items = vault_core.list_credentials(user)
        mode = vault_core.vault_mode(user)
    except Exception as e:
        items = [{"name": f"(list error: {e})", "note": "", "updated": "", "type": "generic"}]

    users = []
    for u in config.get_users(app.state.cfg):
        uname = u.get("username")
        st = config.load_user_state(uname)
        totp = "enabled" if st.get("totp_confirmed") else ("pending" if st.get("totp_secret") else "off")
        users.append({"username": uname, "has_token": bool(u.get("mcp_token")), "totp": totp})

    totp_uri = auth.totp_uri(secret, user) if secret else ""
    return DASH_TPL.render(
        user=user, items=items, mode=mode, type_labels=TYPE_LABELS, users=users,
        totp_secret=secret or "", totp_confirmed=bool(state.get("totp_confirmed")),
        totp_uri=totp_uri, version=__version__,
        platform=f"{os.uname().sysname} {os.uname().machine}" if hasattr(os, "uname") else os.name,
    )


@app.get("/api/types")
def api_types(request: Request):
    require_user(request)
    return JSONResponse(CRED_TYPES)


@app.get("/api/credentials")
def api_list(request: Request):
    user = require_user(request)
    return JSONResponse(vault_core.list_credentials(user))


@app.get("/api/credentials/{name}")
def api_get(request: Request, name: str):
    user = require_user(request)
    try:
        return JSONResponse(vault_core.load_record(user, name))
    except KeyError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404)


@app.post("/api/credentials")
async def api_add(request: Request):
    user = require_user(request)
    data = await request.json()
    name = data.get("name")
    if not name:
        return JSONResponse({"ok": False, "error": "name is required"}, status_code=400)
    type_ = data.get("type", "generic")
    fields = data.get("fields") or {}
    note = data.get("note", "")
    original = data.get("original_name")
    try:
        # Support rename: delete the old record first if the key changed.
        if original and original != name:
            vault_core.delete_credential(user, original)
        r = vault_core.save_credential(user, name, type_, fields, note)
        return JSONResponse({"ok": True, **r})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.delete("/api/credentials/{name}")
async def api_delete(request: Request, name: str):
    user = require_user(request)
    ok = vault_core.delete_credential(user, name)
    return JSONResponse({"ok": ok})


@app.post("/api/totp/enroll")
async def api_totp_enroll(request: Request):
    user = require_user(request)
    secret = auth.generate_totp_secret()
    config.save_user_state(user, {"totp_secret": secret, "totp_confirmed": False})
    return JSONResponse({"ok": True, "secret": secret, "uri": auth.totp_uri(secret, user)})


@app.post("/api/totp/confirm")
async def api_totp_confirm(request: Request):
    user = require_user(request)
    data = await request.json()
    state = config.load_user_state(user)
    secret = state.get("totp_secret")
    if not secret or not auth.verify_totp(secret, data.get("code", "")):
        return JSONResponse({"ok": False, "error": "无效的验证码"}, status_code=400)
    config.save_user_state(user, {"totp_confirmed": True})
    return JSONResponse({"ok": True})


@app.post("/api/totp/reset")
async def api_totp_reset(request: Request):
    """Disable the caller's own 2FA (keeps the account, drops the secret)."""
    user = require_user(request)
    config.save_user_state(user, {"totp_secret": None, "totp_confirmed": False})
    return JSONResponse({"ok": True})


# --------------------------------------------------------------------------
# Self-service: MCP token & password
# --------------------------------------------------------------------------
@app.get("/api/token")
async def api_token_get(request: Request):
    user = require_user(request)
    u = config.find_user(app.state.cfg, user) or {}
    return JSONResponse({"ok": True, "token": u.get("mcp_token", "")})


@app.post("/api/token/regenerate")
async def api_token_regen(request: Request):
    user = require_user(request)
    token = auth.gen_token(32)
    if not config.set_user_token(app.state.cfg, user, token):
        return JSONResponse({"ok": False, "error": "user not found"}, status_code=404)
    try:
        config.save_config(app.state.cfg)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"写入配置失败: {e}"}, status_code=500)
    return JSONResponse({"ok": True, "token": token})


@app.post("/api/password")
async def api_password(request: Request):
    user = require_user(request)
    data = await request.json()
    cur, new = data.get("current", ""), data.get("new", "")
    u = config.find_user(app.state.cfg, user)
    if not u:
        return JSONResponse({"ok": False, "error": "user not found"}, status_code=404)
    if not auth.verify_password(cur, u.get("password_hash", "")):
        return JSONResponse({"ok": False, "error": "当前密码不正确"}, status_code=400)
    if len(new) < 6:
        return JSONResponse({"ok": False, "error": "新密码至少 6 位"}, status_code=400)
    config.set_password_hash(app.state.cfg, user, auth.hash_password(new))
    try:
        config.save_config(app.state.cfg)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"写入配置失败: {e}"}, status_code=500)
    return JSONResponse({"ok": True})


# --------------------------------------------------------------------------
# Admin: user management (writes back to config.yaml)
# --------------------------------------------------------------------------
def _persist_or_error() -> JSONResponse | None:
    try:
        config.save_config(app.state.cfg)
        return None
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"写入配置失败: {e}"}, status_code=500)


@app.get("/api/admin/users")
async def api_admin_users(request: Request):
    require_user(request)
    out = []
    for u in config.get_users(app.state.cfg):
        st = config.load_user_state(u.get("username"))
        out.append({
            "username": u.get("username"),
            "has_token": bool(u.get("mcp_token")),
            "totp": "enabled" if st.get("totp_confirmed") else ("pending" if st.get("totp_secret") else "off"),
        })
    return JSONResponse({"ok": True, "users": out})


@app.post("/api/admin/users")
async def api_admin_add_user(request: Request):
    require_user(request)
    data = await request.json()
    username = (data.get("username") or "").strip()
    if not username:
        return JSONResponse({"ok": False, "error": "用户名不能为空"}, status_code=400)
    if config.find_user(app.state.cfg, username):
        return JSONResponse({"ok": False, "error": "用户已存在"}, status_code=400)
    password = data.get("password") or auth.gen_token(9)  # random 18-char default
    token = auth.gen_token(32)
    config.add_or_update_user(app.state.cfg, username, auth.hash_password(password), token)
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True, "username": username, "token": token,
                         "initial_password": password if not data.get("password") else None})


@app.post("/api/admin/users/{username}/password")
async def api_admin_set_password(request: Request, username: str):
    require_user(request)
    data = await request.json()
    new = data.get("password") or ""
    if len(new) < 6:
        return JSONResponse({"ok": False, "error": "密码至少 6 位"}, status_code=400)
    if not config.set_password_hash(app.state.cfg, username, auth.hash_password(new)):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True})


@app.post("/api/admin/users/{username}/2fa-reset")
async def api_admin_reset_2fa(request: Request, username: str):
    require_user(request)
    if not config.find_user(app.state.cfg, username):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    config.save_user_state(username, {"totp_secret": None, "totp_confirmed": False})
    return JSONResponse({"ok": True})


@app.post("/api/admin/users/{username}/token")
async def api_admin_regen_token(request: Request, username: str):
    require_user(request)
    token = auth.gen_token(32)
    if not config.set_user_token(app.state.cfg, username, token):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True, "token": token})


@app.delete("/api/admin/users/{username}")
async def api_admin_delete_user(request: Request, username: str):
    me = require_user(request)
    if username == me:
        return JSONResponse({"ok": False, "error": "不能删除当前登录用户"}, status_code=400)
    if not config.delete_user(app.state.cfg, username):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    config.clear_user_state(username)
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True})


@app.post("/api/admin/repair")
async def api_admin_repair(request: Request):
    """Validate the caller's credential store, dropping unreadable records."""
    user = require_user(request)
    healed, broken = 0, []
    try:
        for it in vault_core.list_credentials(user):
            try:
                vault_core.load_record(user, it["name"])
            except Exception:
                broken.append(it["name"])
                vault_core.delete_credential(user, it["name"])
                healed += 1
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    msg = f"校验完成：移除 {healed} 条损坏记录" + (f"（{', '.join(broken)}）" if broken else "")
    return JSONResponse({"ok": True, "message": msg})


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------
def main():
    import uvicorn
    s = config.server_settings(cfg)
    host = s.get("host", os.environ.get("VAULT_HOST", "0.0.0.0"))
    port = int(s.get("port", os.environ.get("VAULT_PORT", "8080")))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
