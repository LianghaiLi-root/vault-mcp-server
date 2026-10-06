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
import time
import asyncio
import contextlib
import contextvars
import re
import urllib.request
import urllib.error
import urllib.parse

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from jinja2 import Template
from mcp.server.fastmcp import FastMCP

from . import auth, vault_core
from . import config
from . import captcha
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

LOGIN_TPL_SRC = """
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
 /* All three credential inputs share one width so the form is a clean column. */
 .box form label{margin-top:14px}
 .box form input{display:block;width:100%}
 button[type=submit]{width:100%;margin-top:22px;padding:12px}
 .alert{
   display:none;background:rgba(255,90,110,.13);border:1px solid rgba(255,90,110,.3);
   color:var(--err);border-radius:11px;padding:10px 13px;font-size:13px;margin-top:18px;
 }
 .alert.show{display:block}
 /* human verification */
 .cap{margin-top:14px}
 .caprow{display:flex;gap:10px;align-items:stretch;margin-top:6px}
 .caprow img,.caprow .capq{
   flex:1;min-width:0;height:52px;border-radius:11px;object-fit:contain;display:block;
   border:1px solid var(--stroke-soft);background:#f6f8fc;
 }
 .caprow .capq{
   display:grid;place-items:center;font-size:19px;font-weight:700;
   color:#20304a;letter-spacing:1.5px;
 }
 .caprow button{flex:0 0 52px;width:52px;padding:0;border-radius:11px;font-size:17px;line-height:1}
 .capnote{font-size:11.5px;color:var(--txt-mute);margin-top:6px}
</style>{% if captcha and captcha.mode == 'turnstile' %}<script>window.capCfError=function(c){var n=document.getElementById('capcfnote');if(!n)return;n.style.display='block';n.style.color='#ff8fa3';n.textContent='人机验证组件加载失败（错误码 '+c+'）。可能是 Site Key 配置有误，请联系管理员。';};window.capCfExpired=function(){var n=document.getElementById('capcfnote');if(!n)return;n.style.display='block';n.style.color='#ffd08a';n.textContent='人机验证已过期，请重新勾选后再登录。';};</script><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>{% endif %}</head><body>
<div class="wrap"><div class="glass box">
 <div class="brand">
   <div class="logo">🔐</div>
   <div><h1>凭据库</h1></div>
 </div>
 <div class="sub">加密凭据管理 · 多用户隔离</div>
 <form method="post" action="/login">
  <label>用户名</label><input name="username" type="text" autocomplete="username" required autofocus>
  <label>密码</label><input name="password" type="password" autocomplete="current-password" required>
  <label>2FA 验证码（已启用时必填）</label><input name="totp" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6 位数字" maxlength="6">
  {% if captcha %}
  <div class="cap">
    <label>人机验证</label>
     {% if captcha.mode == 'turnstile' %}
      <div class="cf-turnstile" data-sitekey="{{ captcha.site_key }}" data-theme="light"
           data-error-callback="capCfError" data-expired-callback="capCfExpired"></div>
      <div class="capnote">由 Cloudflare Turnstile 自动完成验证。</div>
      <div class="capnote" id="capcfnote" style="display:none"></div>
     {% else %}
      <div class="caprow">
        {% if captcha.image %}<img id="capimg" src="{{ captcha['image'] }}" alt="人机验证图片">{% else %}<div id="capq" class="capq">{{ captcha.question }}</div>{% endif %}
        <button type="button" id="capr" title="换一个">&#8635;</button>
      </div>
      <input name="captcha_answer" id="capans" type="text" autocomplete="off" required
             placeholder="{% if captcha.mode == 'math' %}请计算结果{% else %}请输入上方内容（不区分大小写）{% endif %}">
      <input type="hidden" name="captcha_id" id="capid" value="{{ captcha['id'] }}">
    {% endif %}
  </div>
  {% endif %}
  <button type="submit">登 录</button>
 </form>
 <div class="alert {{ 'show' if error else '' }}">{{ error }}</div>
</div></div>
<script>
(function(){
  var r=document.getElementById('capr');
  if(!r) return;
  var img=document.getElementById('capimg'), q=document.getElementById('capq'),
      cid=document.getElementById('capid'), ans=document.getElementById('capans');
  r.onclick=function(){
    r.disabled=true;
    fetch('/api/captcha/new',{cache:'no-store'})
      .then(function(x){ return x.json(); })
      .then(function(d){
        if(!d || !d.ok) return;
        if(cid) cid.value=d.id||'';
        if(ans) ans.value='';
        if(img && d.image){ img.src=d.image; img.style.display='block'; if(q) q.style.display='none'; }
        else if(q && d.question){ q.textContent=d.question; q.style.display='grid'; if(img) img.style.display='none'; }
        if(ans) ans.focus();
      })
      .catch(function(){})
      .then(function(){ r.disabled=false; });
  };
})();
</script>
</body></html>"""

LOGIN_TPL = Template(LOGIN_TPL_SRC, autoescape=True)


DASH_TPL_SRC = """
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
 .switchrow input{width:auto;flex:none}
 .switchcard{display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid var(--stroke-soft)}
 .switchcard:last-of-type{border-bottom:0}
 .switchcard .txt{flex:1}
 .switchcard .txt b{display:block;font-size:13.5px;font-weight:600;margin-bottom:3px}
 .switchcard .txt span{font-size:12px;color:var(--txt-mute);line-height:1.5}
 .toggle{position:relative;flex:none;width:46px;height:26px;border-radius:999px;border:1px solid var(--stroke);
   background:rgba(9,12,18,.7);cursor:pointer;transition:background .2s,border-color .2s;padding:0;margin-top:2px}
 .toggle::after{content:"";position:absolute;top:2px;left:2px;width:20px;height:20px;border-radius:50%;
   background:#8b95a1;transition:transform .2s,background .2s}
 .toggle.on{background:linear-gradient(135deg,var(--accent),var(--accent-2));border-color:transparent}
 .toggle.on::after{transform:translateX(20px);background:#fff}
 .rolebadge{font-size:11.5px;font-weight:600;padding:2px 9px;border-radius:999px;
   background:rgba(255,255,255,.09);border:1px solid var(--stroke);color:var(--txt-dim)}
 .rolebadge.admin{background:rgba(91,140,255,.18);border-color:rgba(91,140,255,.34);color:#a9c6ff}
</style></head><body>
<div class="shell">

 <header class="glass bar">
  <div class="brand">
    <div class="logo">🔐</div>
    <div>
      <h1>凭据库</h1>
      <div class="who"><code>{{ user }}</code> · <span class="rolebadge {{ role }}">{{ '管理员' if is_admin else '普通用户' }}</span></div>
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
   {% if is_admin %}<button class="tab" data-pane="ops">运维 / 用户</button>{% endif %}
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

 <!-- ============ 运维 / 用户（仅管理员可见） ============ -->
 {% if is_admin %}
 <section id="pane-ops" class="pane">
  <div class="glass card">
   <h2>🖥️ 服务器状态</h2>
   <div class="hint">后端运行信息一览。</div>
   <div class="kv"><span class="k">存储模式</span><code>{{ mode }}</code></div>
   <div class="kv"><span class="k">凭据总数（我的）</span><code>{{ items|length }}</code></div>
   <div class="kv"><span class="k">用户总数</span><code>{{ users|length }}</code></div>
   <div class="kv"><span class="k">服务版本</span><code>{{ version }}</code></div>
   <div class="kv"><span class="k">运行平台</span><code>{{ platform }}</code></div>
   <div style="margin-top:14px"><button class="mini" id="oprefresh">刷新</button></div>
  </div>

  <div class="glass card">
   <h2>👥 用户管理</h2>
   <div class="hint">添加用户、修改用户名、重置密码、重置 2FA、重新签发 MCP Token。变更立即写入 config.yaml。</div>
   <div class="tablewrap">
   <table><thead><tr><th>用户名</th><th>角色</th><th>MCP Token</th><th>2FA</th><th style="text-align:right">操作</th></tr></thead>
   <tbody id="userrows">
    {% for u in users %}<tr data-user="{{ u.username }}">
      <td><code>{{ u.username }}</code>{% if u.username == user %} <span class="badge">当前</span>{% endif %}</td>
      <td><span class="rolebadge {{ u.role }}">{{ '管理员' if u.role == 'admin' else '普通用户' }}</span></td>
      <td class="muted" style="font-size:12.5px">{{ '已配置' if u.has_token else '缺失' }}</td>
      <td>{% if u.totp == 'enabled' %}<span class="ok">已启用</span>{% elif u.totp == 'pending' %}<span style="color:#ffd08a">待验证</span>{% else %}<span class="muted">未启用</span>{% endif %}</td>
      <td style="text-align:right;white-space:nowrap">
        <button class="mini" data-act="rename" data-user="{{ u.username }}">改用户名</button>
        <button class="mini" data-act="pw" data-user="{{ u.username }}">改密码</button>
        <button class="mini" data-act="2fa" data-user="{{ u.username }}">重置2FA</button>
        <button class="mini" data-act="tok" data-user="{{ u.username }}">重签Token</button>
        {% if u.username != user %}<button class="del" data-act="del" data-user="{{ u.username }}">删除</button>{% endif %}
      </td>
    </tr>{% endfor %}
   </tbody></table>
   </div>
   <div style="margin-top:16px" class="row">
     <input type="text" id="newuser" placeholder="新用户名（仅小写字母/数字/_/-）" autocomplete="off" style="max-width:240px">
     <button id="adduser">添加用户</button>
   </div>
   <div class="msg" id="usermsg"></div>
  </div>

  <div class="glass card">
   <h2>🛡️ Web 访问加固</h2>
   <div class="hint">在反向代理 / CDN 边缘先做一层访问控制，未通过者连登录页都看不到。仅管理员可修改。</div>

   <div class="switchcard">
     <button class="toggle {{ 'on' if sec.require_cloudflare_access else '' }}" id="tg_cf" data-key="require_cloudflare_access"></button>
     <div class="txt">
       <b>Cloudflare Access 前置校验</b>
       <span>开启后，所有请求必须带 Cloudflare Access 的 JWT 头（<code>Cf-Access-Jwt-Assertion</code>）或 <code>CF_Authorization</code> Cookie，
       说明请求已通过 Cloudflare Zero Trust 的登录策略。未携带则直接 403，登录页也不会渲染。</span>
     </div>
   </div>

   <div class="switchcard">
     <button class="toggle {{ 'on' if sec.force_secure_cookie else '' }}" id="tg_secure_cookie" data-key="force_secure_cookie"></button>
     <div class="txt">
       <b>强制 HTTPS 会话 Cookie</b>
       <span>给会话 Cookie 加 <code>Secure</code> 标记，浏览器只在 HTTPS 下回传，避免明文链路泄露。</span>
     </div>
   </div>

   <label style="margin-top:16px">自定义边缘校验头（可选）</label>
   <div class="grid2">
     <div><label>请求头名</label><input type="text" id="edge_hdr" placeholder="X-Edge-Secret" value="{{ sec.required_edge_header }}"></div>
     <div><label>期望值</label><input type="text" id="edge_val" placeholder="留空则不校验" value="{{ sec.required_edge_header_value }}"></div>
   </div>
   <div class="hint" style="margin-top:10px">用于自建 nginx / 其他 CDN 注入的共享密钥，例如 <code>add_header X-Edge-Secret "xxx";</code>。留空表示不启用该项。</div>

   <div class="grid2" style="margin-top:6px">
     <div><label>登录失败上限（次）</label><input type="text" id="lmax" inputmode="numeric" value="{{ sec.login_max_failures }}"></div>
     <div><label>锁定时间（秒）</label><input type="text" id="lsec" inputmode="numeric" value="{{ sec.login_lockout_seconds }}"></div>
   </div>

   <div style="margin-top:16px" class="row">
     <button id="secsave">保存加固设置</button>
     <button class="mini" id="secrefresh">重新读取</button>
   </div>
   <div class="msg" id="secmsg"></div>
  </div>

  <div class="glass card">
   <h2>🤖 人机验证</h2>
   <div class="hint">登录页需先通过人机验证才能提交，用于阻挡自动化撞库脚本。仅管理员可修改。</div>

   <div class="grid2">
     <div>
       <label>验证方式</label>
       <select id="cap_mode">
         <option value="off">关闭</option>
         <option value="numeric">数字验证 —— 图片数字</option>
         <option value="image">图形验证 —— 字母 + 数字</option>
         <option value="turnstile">Cloudflare Turnstile —— 自动验证</option>
       </select>
     </div>
     <div><label>验证码位数（3–8）</label><input type="text" id="cap_len" inputmode="numeric" value="{{ cap.length }}"></div>
   </div>

   <div id="cap_cf" style="display:none;margin-top:4px">
     <div class="grid2">
       <div><label>Turnstile Site Key</label><input type="text" id="cap_site" placeholder="0x4AAAAAAA..." autocomplete="off" value="{{ cap.turnstile_site_key }}"></div>
       <div><label>Turnstile Secret Key</label><input type="password" id="cap_secret" placeholder="留空 = 不修改" autocomplete="new-password"></div>
     </div>
     <div class="hint" style="margin-top:10px">
       在 Cloudflare 控制台 → Turnstile 创建站点后获得。<strong>Site Key 与 Secret Key 必须同时填写才能启用</strong>，
       否则保存会被拒绝。Secret Key 不会回显，只显示是否已设置。
       <span id="cap_state"></span>
     </div>
   </div>

   <div id="cap_pilwarn" style="display:none;margin-top:10px" class="hint">
     ⚠️ 服务器未安装 <code>Pillow</code>，数字 / 图形验证码将自动降级为「算术题」形式。
     如需图片验证码请执行 <code>pip install Pillow</code>。
   </div>

   <div style="margin-top:16px" class="row">
     <button id="capsave">保存人机验证设置</button>
     <button class="mini" id="capreload">重新读取</button>
     <button class="mini" id="capclearsec">清除 Secret</button>
   </div>
   <div class="msg" id="capmsg"></div>
  </div>

  <div class="glass card danger-zone">
   <h2>🧹 维护操作</h2>
   <div class="hint">校验并整理<strong>当前登录用户</strong>的凭据存储。</div>
   <div class="row">
     <button class="mini" id="repair">校验并整理凭据存储</button>
   </div>
   <div class="msg" id="opsmsg"></div>
  </div>
 </section>
 {% endif %}

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
   // Judge on the data we actually need rather than trusting an `ok` flag, so a
   // missing/oddly-shaped response can never surface a bare "undefined".
   if(!d || !d.name){ alert((d && d.error) || '读取凭据失败'); return; }
   const t=(d.type && typeFields(d.type).length) ? d.type : 'generic';
   $('original_name').value=d.name; $('f_name').value=d.name; $('f_note').value=d.note||'';
   sel.value=t; renderFields(t, d.fields||{});
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

// ---- user management (admin only; the whole block is absent for normal users) ----
const um=$('usermsg');
function adminOnly(){ return !!document.getElementById('adduser'); }
document.querySelectorAll('button[data-act]').forEach(b=>b.onclick=async()=>{
  const act=b.dataset.act, uname=b.dataset.user;
  if(act==='rename'){
    const nn=prompt('把用户 "'+uname+'" 重命名为：', uname); if(nn===null) return;
    const nv=nn.trim();
    if(!nv||nv===uname) return;
    const d=await j('/api/admin/users/'+encodeURIComponent(uname),'PATCH',{new_username:nv});
    if(d.ok){ say('usermsg',true,'✓ 已重命名为 '+d.username+(d.self?'（当前账号，正在重新登录…）':'')); setTimeout(()=>location.reload(),1200); }
    else say('usermsg',false,'失败：'+d.error);
  } else if(act==='pw'){
    const np=prompt('为 '+uname+' 设置新密码（至少 6 位）：'); if(!np) return;
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
  if(d.ok){ say('usermsg',true,'✓ 已添加 '+uname+'，初始密码：'+(d.initial_password||'(自设)')+'，初始 Token：'+d.token); $('newuser').value=''; setTimeout(()=>location.reload(),1600); }
  else say('usermsg',false,'失败：'+d.error);
};

// ---- web hardening (admin only) ----
let wasCfOn = {{ 'true' if sec.require_cloudflare_access else 'false' }};
document.querySelectorAll('.toggle').forEach(t=>t.onclick=()=>{
  t.classList.toggle('on');
});
const ss=$('secsave'); if(ss) ss.onclick=async()=>{
  const turningOn=$('tg_cf').classList.contains('on');
  if(turningOn && !wasCfOn){
    // NOTE: build the message with a real escaped-newline constant. Writing a
    // raw escape sequence of backslash-n inside this (non-raw) triple-quoted
    // Python template gets compiled into an actual newline, which splits the JS
    // string literal and kills the whole script block. Avoid the sequence here
    // too, comments included — it is escaped before JS ever sees it.
    const ok=confirm(['即将启用边缘访问校验。','',
      '启用后，只有携带 Cloudflare Access 凭证的浏览器才能打开登录页；',
      '请在 Cloudflare 侧确认 Access 应用已覆盖本站，否则所有人都将无法登录。','',
      '仍可以用 MCP Bearer Token 调用 API 的方式随时关闭本开关。','',
      '确定启用？'].join(NL));
    if(!ok) return;
  }
  const body={
    require_cloudflare_access: turningOn,
    force_secure_cookie: $('tg_secure_cookie').classList.contains('on'),
    required_edge_header: $('edge_hdr').value.trim(),
    required_edge_header_value: $('edge_val').value.trim(),
    login_max_failures: parseInt($('lmax').value||'0',10)||0,
    login_lockout_seconds: parseInt($('lsec').value||'0',10)||0,
  };
  const d=await j('/api/admin/security','POST',body);
  say('secmsg', d.ok, d.ok?'✓ 加固设置已保存':('失败：'+d.error));
  if(d.ok) wasCfOn=turningOn;
};
const sr=$('secrefresh'); if(sr) sr.onclick=()=>location.reload();

// ---- human verification (admin only) ----
const capModeSel=$('cap_mode'), capCfBox=$('cap_cf');
function capSync(){
  if(capCfBox) capCfBox.style.display=(capModeSel && capModeSel.value==='turnstile')?'block':'none';
}
function capRender(d){
  if(!d) return;
  const c=d.captcha||{};
  if(capModeSel) capModeSel.value=c.mode||'off';
  if($('cap_len')) $('cap_len').value=(c.length||4);
  if($('cap_site')) $('cap_site').value=(c.turnstile_site_key||'');
  if($('cap_state')) $('cap_state').textContent=c.turnstile_secret_set?'（Secret 已设置）':'（尚未设置 Secret）';
  if($('cap_pilwarn')) $('cap_pilwarn').style.display=d.pillow?'none':'block';
  capSync();
}
async function capLoad(){ capRender(await j('/api/admin/captcha')); }
if(capModeSel){ capModeSel.onchange=capSync; capLoad(); }
const caps=$('capsave');
if(caps) caps.onclick=async()=>{
  const body={
    mode:capModeSel.value,
    length:parseInt($('cap_len').value||'4',10)||4,
    turnstile_site_key:$('cap_site')?$('cap_site').value.trim():'',
  };
  if($('cap_secret')) body.turnstile_secret_key=$('cap_secret').value.trim();
  const d=await j('/api/admin/captcha','POST',body);
  say('capmsg', d.ok, d.ok?'✓ 人机验证设置已保存':('失败：'+d.error));
  if(d.ok){ if($('cap_secret')) $('cap_secret').value=''; capRender(d); }
};
const capRel=$('capreload');
if(capRel) capRel.onclick=async()=>{ await capLoad(); say('capmsg',true,'✓ 已重新读取'); };
const capClr=$('capclearsec');
if(capClr) capClr.onclick=async()=>{
  if(!confirm('确定清除已保存的 Turnstile Secret Key 吗？清除后将无法启用自动验证。')) return;
  const d=await j('/api/admin/captcha','POST',{
    mode:capModeSel.value,
    length:parseInt($('cap_len').value||'4',10)||4,
    turnstile_site_key:$('cap_site')?$('cap_site').value.trim():'',
    clear_secret:true,
  });
  say('capmsg', d.ok, d.ok?'✓ Secret 已清除':('失败：'+d.error));
  if(d.ok) capRender(d);
};

// ---- ops ----
const rp=$('repair'); if(rp) rp.onclick=async()=>{
  const d=await j('/api/admin/repair','POST',{});
  say('opsmsg', d.ok, d.ok?('✓ '+d.message):('失败：'+d.error));
};
})();
</script>
</body></html>"""

DASH_TPL = Template(DASH_TPL_SRC, autoescape=True)


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
# Template self-check.
#
# These templates are plain (non-raw) Python triple-quoted strings that embed
# JavaScript. A literal \n written inside one of them is compiled by Python into
# a REAL newline, which splits the JS string literal and makes the whole
# <script> block fail with "SyntaxError: Invalid or unexpected token" — silently
# killing every event handler on the page (tabs stop switching, the type
# dropdown looks empty). This has regressed twice, so guard it at import time:
# any such mistake now fails loudly at boot instead of shipping.
# --------------------------------------------------------------------------
def _selfcheck_templates() -> None:
    """Guard against the 'literal backslash-n in a non-raw template' regression.

    By the time Python has compiled the module the damage is already done: a raw
    ``\\n`` written inside DASH_TPL/LOGIN_TPL becomes a REAL newline in the string
    object, so scanning the live constant can never detect it. The only place the
    mistake is still visible is the raw .py source, so read the file and check the
    template region there.
    """
    import re as _re
    import pathlib

    problems: list[str] = []
    try:
        raw = pathlib.Path(__file__).read_text(encoding="utf-8")
    except Exception as e:  # never let the guard itself break startup
        print(f"[selfcheck] skipped (cannot read source: {e})")
        return

    for name in ("DASH_TPL_SRC", "LOGIN_TPL_SRC"):
        i = raw.find(f"{name} = ")
        if i < 0:
            continue
        # scan until the next top-level assignment or the self-check itself
        j = raw.find("\nLOGIN_TPL = ", i + 1)
        for stop in (raw.find("\nDASH_TPL = ", i + 1),
                     raw.find("\n# ------", i + 1),
                     len(raw)):
            if 0 < stop < (j if j > 0 else len(raw)):
                j = stop
        if j < 0:
            j = len(raw)
        region = raw[i:j]
        # Only look inside the <script> … </script> span.
        for m in _re.finditer(r"<script>(.*?)</script>", region, _re.S):
            body = m.group(1)
            for hit in _re.finditer(r"(?<!\\)\\n", body):
                line = raw[:i + m.start(1) + hit.start()].count("\n") + 1
                ctx = body[max(0, hit.start() - 45):hit.end() + 45].replace("\n", "⏎")
                problems.append(f"{name}: raw \\n at server.py:{line}: ...{ctx}...")

    if problems:
        raise RuntimeError(
            "Template self-check FAILED — the dashboard script would not run:\n  "
            + "\n  ".join(problems)
            + "\n\nFix: write \\\\n, or join an array with a '\\n' constant. Watch out "
              "for the sequence in COMMENTS inside the template too."
        )


_selfcheck_templates()


# --------------------------------------------------------------------------
# Auth middleware: resolve the acting user into a contextvar for both the web
# routes (session cookie) and the MCP endpoint (bearer token). Also enforces
# the admin-managed web hardening rules (edge verification) before anything else.
# --------------------------------------------------------------------------
def _edge_gate(cfg: dict, request: Request) -> Response | None:
    """Return a Response to short-circuit with when the edge check fails."""
    sec = config.security_settings(cfg)
    # The MCP endpoint authenticates with its own Bearer token and is called by
    # machines, not browsers, so the browser-oriented edge gate does not apply.
    if request.url.path.startswith("/mcp"):
        return None
    # A VALID bearer token is a machine credential that a casual browser visitor
    # cannot forge. Exempting it is also what keeps this feature safe: the gate
    # is configured through POST /api/admin/security, so if the gate also blocked
    # bearer calls, an admin who enabled it could never turn it back off again.
    auth_hdr = request.headers.get("Authorization", "")
    if auth_hdr.startswith("Bearer "):
        if config.find_user_by_token(cfg, auth_hdr[7:].strip()):
            return None
    if sec.get("require_cloudflare_access"):
        has_header = bool(request.headers.get("Cf-Access-Jwt-Assertion"))
        has_cookie = bool(request.cookies.get("CF_Authorization"))
        if not (has_header or has_cookie):
            return JSONResponse(
                {"ok": False, "error": "edge verification required (Cloudflare Access)"},
                status_code=403)
    hdr = (sec.get("required_edge_header") or "").strip()
    if hdr:
        expect = sec.get("required_edge_header_value") or ""
        got = request.headers.get(hdr, "")
        if not hmac.compare_digest(got, expect):
            return JSONResponse(
                {"ok": False, "error": "edge verification required"}, status_code=403)
    return None


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # The MCP app is mounted at /mcp/, but clients routinely configure the URL
    # without the trailing slash. Starlette would then answer 307 to /mcp/, and
    # following that redirect makes HTTP clients DROP the Authorization header —
    # the request still arrives, so the handshake and tools/list look fine, but
    # every tool call sees no user and returns "unauthorized" even though the
    # token is perfectly valid. Rewrite the path internally instead of
    # redirecting: same handler, no 307, and the credential survives.
    if request.scope.get("path") == "/mcp":
        request.scope["path"] = "/mcp/"
        request.scope["raw_path"] = b"/mcp/"

    blocked = _edge_gate(app.state.cfg, request)
    if blocked is not None:
        return blocked
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


def require_admin(request: Request) -> str:
    """Gate every user-management route: admin role only.

    A normal user must not merely be denied the *action* — they must not be
    able to enumerate other accounts at all, so this returns 404 rather than
    403 to avoid confirming that the endpoint exists for them.
    """
    user = require_user(request)
    if not config.is_admin(app.state.cfg, user):
        raise HTTPException(status_code=404, detail="not found")
    return user


# --------------------------------------------------------------------------
# Web routes
# --------------------------------------------------------------------------
def _issue_captcha_for_page() -> dict | None:
    """Build a fresh challenge for a rendered login page (None when disabled)."""
    sec = config.captcha_settings(app.state.cfg)
    mode = str(sec.get("mode") or "off")
    if mode == "off":
        return None
    if mode == "turnstile":
        site = str(sec.get("turnstile_site_key") or "").strip()
        # A half-configured automatic challenge must not degrade into no
        # challenge: fall back to a rendered one instead of silently passing.
        if site:
            return {"mode": "turnstile", "site_key": site}
        ch = captcha.issue("image", int(sec.get("length") or 4))
        return ch if ch.get("ok") else None
    ch = captcha.issue(mode, int(sec.get("length") or 4))
    return ch if ch.get("ok") else None


def _login_html(error: str = "", status_code: int = 200) -> HTMLResponse:
    """Always render the login page as text/html — returning a bare string makes
    FastAPI emit application/json, which the browser shows as escaped garbage."""
    return HTMLResponse(
        LOGIN_TPL.render(error=error, captcha=_issue_captcha_for_page()),
        status_code=status_code)


@app.get("/api/captcha/new")
def api_captcha_new():
    """Issue a new challenge. Unauthenticated by design — the login page needs it."""
    sec = config.captcha_settings(app.state.cfg)
    mode = str(sec.get("mode") or "off")
    if mode == "off":
        return JSONResponse({"ok": False, "error": "人机验证未启用"}, status_code=404)
    if mode == "turnstile":
        return JSONResponse({"ok": False, "error": "Turnstile 由浏览器自动刷新"},
                            status_code=400)
    ch = captcha.issue(mode, int(sec.get("length") or 4))
    return JSONResponse(ch, status_code=200 if ch.get("ok") else 500)


@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = ""):
    return _login_html(error)


# In-process login throttle, keyed by client IP. Deliberately simple: the goal
# is to blunt online password guessing, not to be a full WAF (use fail2ban /
# Cloudflare rate limiting for that).
_LOGIN_FAILS: dict[str, list[float]] = {}


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _throttled(ip: str, max_fails: int, window: int) -> int:
    """Return seconds remaining in the lockout, or 0 when not locked out."""
    if max_fails <= 0:
        return 0
    now = time.time()
    fails = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < window]
    _LOGIN_FAILS[ip] = fails
    if len(fails) >= max_fails:
        return int(window - (now - fails[0])) + 1
    return 0


def _note_fail(ip: str) -> None:
    _LOGIN_FAILS.setdefault(ip, []).append(time.time())


def _clear_fails(ip: str) -> None:
    _LOGIN_FAILS.pop(ip, None)


@app.post("/login")
def login(request: Request, username: str = Form(""),
          password: str = Form(""), totp: str = Form(""),
          captcha_id: str = Form(""), captcha_answer: str = Form(""),
          cf_turnstile: str = Form("", alias="cf-turnstile-response")):
    # Declared with empty defaults rather than Form(...): a blank field is
    # dropped by the form parser, which would otherwise surface as a raw 422
    # JSON error instead of the login page. Non-browser clients hit this too.
    if not username or not password:
        return _login_html("请输入用户名和密码", 401)

    sec = config.security_settings(app.state.cfg)
    ip = _client_ip(request)
    wait = _throttled(ip, int(sec.get("login_max_failures") or 0),
                      int(sec.get("login_lockout_seconds") or 300))
    if wait:
        return _login_html(f"尝试过于频繁，请 {wait} 秒后再试", 429)

    # Human verification runs BEFORE the password check so an automated guessing
    # loop never reaches the credential comparison. Failures count toward the
    # throttle, otherwise the captcha would not actually blunt brute force.
    cap = config.captcha_settings(app.state.cfg)
    cap_mode = str(cap.get("mode") or "off")
    if cap_mode == "turnstile":
        ok, why = captcha.verify_turnstile(
            str(cap.get("turnstile_secret_key") or ""), cf_turnstile, ip)
        if not ok:
            _note_fail(ip)
            return _login_html(f"人机验证未通过：{why}", 401)
    elif cap_mode in ("numeric", "image"):
        if not captcha.consume(captcha_id, captcha_answer):
            _note_fail(ip)
            return _login_html("人机验证未通过，请重新输入", 401)

    user_cfg = config.find_user(app.state.cfg, username)
    if not user_cfg or not auth.verify_password(password, user_cfg.get("password_hash", "")):
        _note_fail(ip)
        return _login_html("用户名或密码错误", 401)
    state = config.load_user_state(username)
    if state.get("totp_confirmed"):
        if not auth.verify_totp(state.get("totp_secret", ""), totp):
            _note_fail(ip)
            return _login_html("需要正确的 2FA 验证码", 401)

    _clear_fails(ip)
    token = auth.issue_session(username)
    secure = (os.environ.get("VAULT_COOKIE_SECURE") == "1"
              or bool(sec.get("force_secure_cookie")))
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
    is_admin = config.is_admin(app.state.cfg, user)
    role = config.user_role(app.state.cfg, user)
    state = config.load_user_state(user)
    secret = state.get("totp_secret")
    items = []
    mode = "n/a"
    try:
        items = vault_core.list_credentials(user)
        mode = vault_core.vault_mode(user)
    except Exception as e:
        items = [{"name": f"(list error: {e})", "note": "", "updated": "", "type": "generic"}]

    # DATA ISOLATION: the user list is built ONLY for an admin. For a normal user
    # `users` stays empty so their page cannot reveal that other accounts exist.
    users = []
    if is_admin:
        for u in config.get_users(app.state.cfg):
            uname = u.get("username")
            st = config.load_user_state(uname)
            totp = "enabled" if st.get("totp_confirmed") else ("pending" if st.get("totp_secret") else "off")
            users.append({"username": uname, "has_token": bool(u.get("mcp_token")),
                          "totp": totp, "role": config.normalize_role(u.get("role"))})

    totp_uri = auth.totp_uri(secret, user) if secret else ""
    return DASH_TPL.render(
        user=user, items=items, mode=mode, type_labels=TYPE_LABELS, users=users,
        is_admin=is_admin, role=role, sec=config.security_settings(app.state.cfg),
        totp_secret=secret or "", totp_confirmed=bool(state.get("totp_confirmed")),
        totp_uri=totp_uri, version=__version__,
        cap=config.captcha_settings(app.state.cfg),
        cap_pillow=captcha.pillow_available(),
        platform=f"{os.uname().sysname} {os.uname().machine}" if hasattr(os, "uname") else os.name,
    )


@app.get("/api/types")
def api_types(request: Request):
    """Credential type catalogue.

    Deliberately NOT wrapped in {"ok": true, ...}: the client consumes the body
    itself as the type map (`const TYPES = await fetch('/api/types').json()` then
    `Object.entries(TYPES)`), so adding an `ok` key would render a bogus "ok"
    entry in the type dropdown.
    """
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
        rec = vault_core.load_record(user, name)
    except KeyError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404)
    # Must carry `ok` like every other endpoint: the editor's click handler opens
    # with `if(!d.ok)`, and a bare record made it fire the failure branch with an
    # undefined message — i.e. a stray `undefined` alert on "edit".
    return JSONResponse({"ok": True, **rec})


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
#
# EVERY route here is gated by require_admin(), which returns 404 for a normal
# user — that way an ordinary account cannot even probe for the user list.
# --------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _bad_username(name: str) -> str | None:
    if not name:
        return "用户名不能为空"
    if not USERNAME_RE.match(name):
        return "用户名只能包含字母、数字、下划线、点和连字符（最长 64 位，且以字母或数字开头）"
    return None


def _persist_or_error() -> JSONResponse | None:
    try:
        config.save_config(app.state.cfg)
        return None
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"写入配置失败: {e}"}, status_code=500)


def _user_row(u: dict) -> dict:
    uname = u.get("username")
    st = config.load_user_state(uname)
    return {
        "username": uname,
        "has_token": bool(u.get("mcp_token")),
        "role": config.normalize_role(u.get("role")),
        "totp": "enabled" if st.get("totp_confirmed") else ("pending" if st.get("totp_secret") else "off"),
    }


@app.get("/api/admin/users")
async def api_admin_users(request: Request):
    require_admin(request)
    return JSONResponse({"ok": True, "users": [_user_row(u) for u in config.get_users(app.state.cfg)]})


@app.post("/api/admin/users")
async def api_admin_add_user(request: Request):
    require_admin(request)
    data = await request.json()
    username = (data.get("username") or "").strip()
    if (err := _bad_username(username)):
        return JSONResponse({"ok": False, "error": err}, status_code=400)
    if config.find_user(app.state.cfg, username):
        return JSONResponse({"ok": False, "error": "用户已存在"}, status_code=400)
    gen_password = not data.get("password")
    password = data.get("password") or auth.gen_token(9)
    token = auth.gen_token(32)
    role = config.normalize_role(data.get("role"))
    config.add_or_update_user(app.state.cfg, username, auth.hash_password(password), token, role)
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True, "username": username, "token": token, "role": role,
                         "initial_password": password if gen_password else None})


@app.patch("/api/admin/users/{username}")
async def api_admin_rename_user(request: Request, username: str):
    """Rename a user, carrying their vault namespace and 2FA state along.

    The admin may rename anyone (including itself). Because the session cookie
    encodes the username, renaming yourself invalidates your own session — the
    client is told via `self: true` so it can send the user back to /login.
    """
    me = require_admin(request)
    data = await request.json()
    new = (data.get("new_username") or "").strip()
    if (err := _bad_username(new)):
        return JSONResponse({"ok": False, "error": err}, status_code=400)
    if not config.find_user(app.state.cfg, username):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    if new == username:
        return JSONResponse({"ok": True, "username": new, "self": username == me})
    if config.find_user(app.state.cfg, new):
        return JSONResponse({"ok": False, "error": "目标用户名已存在"}, status_code=400)

    try:
        vault_core.rename_namespace(username, new)   # move the encrypted store
    except FileExistsError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    config.rename_user(app.state.cfg, username, new)
    config.rename_user_state(username, new)
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True, "username": new, "self": username == me})


@app.post("/api/admin/users/{username}/password")
async def api_admin_set_password(request: Request, username: str):
    require_admin(request)
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
    require_admin(request)
    if not config.find_user(app.state.cfg, username):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    config.save_user_state(username, {"totp_secret": None, "totp_confirmed": False})
    return JSONResponse({"ok": True})


@app.post("/api/admin/users/{username}/token")
async def api_admin_regen_token(request: Request, username: str):
    require_admin(request)
    token = auth.gen_token(32)
    if not config.set_user_token(app.state.cfg, username, token):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True, "token": token})


@app.delete("/api/admin/users/{username}")
async def api_admin_delete_user(request: Request, username: str):
    me = require_admin(request)
    if username == me:
        return JSONResponse({"ok": False, "error": "不能删除当前登录用户"}, status_code=400)
    if not config.find_user(app.state.cfg, username):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    if (config.is_admin(app.state.cfg, username)
            and config.admin_count(app.state.cfg) <= 1):
        return JSONResponse({"ok": False, "error": "不能删除唯一的管理员"}, status_code=400)
    if not config.delete_user(app.state.cfg, username):
        return JSONResponse({"ok": False, "error": "用户不存在"}, status_code=404)
    config.clear_user_state(username)
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True})


@app.get("/api/admin/security")
async def api_admin_get_security(request: Request):
    require_admin(request)
    return JSONResponse({"ok": True, "security": config.security_settings(app.state.cfg)})


@app.post("/api/admin/security")
async def api_admin_set_security(request: Request):
    """Persist the web-hardening switches (admin only)."""
    require_admin(request)
    data = await request.json()
    cur = config.security_settings(app.state.cfg)
    patch = {}
    for k in ("require_cloudflare_access", "force_secure_cookie"):
        if k in data:
            patch[k] = bool(data[k])
    for k in ("required_edge_header", "required_edge_header_value"):
        if k in data:
            patch[k] = str(data[k] or "").strip()
    for k in ("login_max_failures", "login_lockout_seconds"):
        if k in data:
            try:
                patch[k] = max(0, int(data[k]))
            except (TypeError, ValueError):
                return JSONResponse({"ok": False, "error": f"{k} 必须是整数"}, status_code=400)
    cur.update(patch)
    app.state.cfg["security"] = cur
    if (err := _persist_or_error()):
        return err
    return JSONResponse({"ok": True, "security": cur})


@app.get("/api/admin/captcha")
async def api_admin_get_captcha(request: Request):
    require_admin(request)
    c = config.captcha_settings(app.state.cfg)
    return JSONResponse({
        "ok": True,
        "captcha": {
            "mode": c["mode"],
            "length": c["length"],
            "turnstile_site_key": c["turnstile_site_key"],
            # The secret is never echoed back to a browser. Report only whether
            # one is stored; send a new value to replace it.
            "turnstile_secret_set": bool(c["turnstile_secret_key"]),
        },
        "pillow": captcha.pillow_available(),
    })


@app.post("/api/admin/captcha")
async def api_admin_set_captcha(request: Request):
    """Persist the human-verification settings (admin only)."""
    require_admin(request)
    try:
        data = await request.json()
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    current = config.captcha_settings(app.state.cfg)
    settings, err = config.validate_captcha(data, current)
    if err:
        return JSONResponse({"ok": False, "error": err}, status_code=400)
    app.state.cfg["captcha"] = settings
    if (e := _persist_or_error()):
        return e
    return JSONResponse({
        "ok": True,
        "captcha": {
            "mode": settings["mode"],
            "length": settings["length"],
            "turnstile_site_key": settings["turnstile_site_key"],
            "turnstile_secret_set": bool(settings["turnstile_secret_key"]),
        },
        "pillow": captcha.pillow_available(),
    })


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
