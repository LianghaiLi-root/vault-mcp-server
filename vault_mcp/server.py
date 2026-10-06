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
import contextvars
import urllib.request
import urllib.error
import urllib.parse

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from jinja2 import Template
from mcp.server.fastmcp import FastMCP

from . import config, auth, vault_core

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
LOGIN_TPL = Template("""
<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>凭据库 · 登录</title>
<style>
 :root{color-scheme:dark}
 body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#15181c;color:#e6e6e6;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
 .box{background:#1d2127;border:1px solid #2a2f37;border-radius:12px;padding:28px;width:320px}
 h1{font-size:18px;margin:0 0 16px}
 label{display:block;font-size:13px;color:#aab2bd;margin:12px 0 4px}
 input{width:100%;box-sizing:border-box;background:#0f1216;border:1px solid #2a2f37;color:#e6e6e6;border-radius:6px;padding:10px;font-size:14px}
 button{width:100%;margin-top:18px;background:#3b82f6;color:#fff;border:0;border-radius:6px;padding:11px;font-size:14px;cursor:pointer}
 .err{color:#ff8a8a;font-size:13px;min-height:16px}
</style></head><body><div class="box">
 <h1>🔐 凭据库登录</h1>
 <form method="post" action="/login">
  <label>用户名</label><input name="username" autocomplete="username" required>
  <label>密码</label><input name="password" type="password" autocomplete="current-password" required>
  <label>2FA 验证码（已启用时必填）</label><input name="totp" inputmode="numeric" placeholder="6 位">
  <div class="err">{{ error }}</div>
  <button type="submit">登录</button>
 </form></div></body></html>""", autoescape=True)


DASH_TPL = Template("""
<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>凭据库 · {{ user }}</title>
<style>
 :root{color-scheme:dark}
 body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#15181c;color:#e6e6e6;margin:0;padding:24px}
 h1{font-size:20px;margin:0 0 4px} .sub{color:#8b95a1;font-size:13px;margin-bottom:18px}
 .card{background:#1d2127;border:1px solid #2a2f37;border-radius:10px;padding:16px;margin-bottom:18px}
 label{display:block;font-size:13px;color:#aab2bd;margin:10px 0 4px}
 input[type=text],input[type=password],textarea,select{width:100%;box-sizing:border-box;background:#0f1216;border:1px solid #2a2f37;color:#e6e6e6;border-radius:6px;padding:9px;font-size:14px}
 textarea{resize:vertical;min-height:60px}
 button{background:#3b82f6;color:#fff;border:0;border-radius:6px;padding:9px 16px;font-size:14px;cursor:pointer}
 button:hover{background:#2f6fd6}
 button.del{background:#3a2226;color:#ff8a8a;padding:5px 10px;font-size:12px}
 button.del:hover{background:#4d2a2f}
 button.edit{background:#23303f;color:#9fd0ff;padding:5px 10px;font-size:12px;margin-right:6px}
 button.edit:hover{background:#2c3e52}
 button.sec{background:#23303f;color:#9fd0ff}
 table{width:100%;border-collapse:collapse;font-size:14px}
 th,td{text-align:left;padding:9px 8px;border-bottom:1px solid #262b32}
 th{color:#8b95a1;font-weight:600;font-size:12px} code{color:#7fd1ff}
 .muted{color:#6b7480} .ok{color:#9fe6a0} .msg{color:#9fe6a0;font-size:13px;min-height:16px}
 .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
 .badge{display:inline-block;background:#23303f;color:#9fd0ff;border-radius:999px;padding:2px 10px;font-size:12px}
 pre{background:#0f1216;padding:10px;border-radius:6px;overflow:auto;font-size:12px;color:#9fe6a0}
 #editbanner{display:none;background:#23303f;color:#9fd0ff;border-radius:8px;padding:8px 12px;margin-bottom:12px;font-size:13px}
</style></head><body>
 <h1>🔐 凭据库</h1>
 <div class="sub">用户：<code>{{ user }}</code> · 存储模式：<code>{{ mode }}</code> · <a href="/logout" style="color:#8b95a1">退出</a></div>

 <div class="card">
  <div id="editbanner"></div>
  <form id="add">
   <input type="hidden" id="original_name" value="">
   <label>标识名（唯一，如 github_pat / myserver）</label>
   <input type="text" id="f_name" required placeholder="github_pat" autocomplete="off">
   <label>类型</label>
   <select id="type"></select>
   <div id="dynfields"></div>
   <label>备注（明文，可选）</label>
   <input type="text" id="f_note" placeholder="例如：GitHub PAT" autocomplete="off">
   <div style="margin-top:12px" class="row">
     <button type="submit" id="submitbtn">加密保存</button>
     <button type="button" id="cancelbtn" style="background:#3a2226;color:#ff8a8a">取消修改</button>
   </div>
  </form>
  <div class="msg" id="addmsg"></div>
 </div>

 <div class="card">
  <table><thead><tr><th>标识名</th><th>类型</th><th>备注</th><th>更新时间</th><th>操作</th></tr></thead>
  <tbody id="rows">
   {% for it in items %}<tr>
     <td><code>{{ it.name }}</code></td>
     <td><span class="badge">{{ type_labels.get(it.type, it.type) }}</span></td>
     <td>{{ it.note }}</td>
     <td>{{ it.updated[:19].replace('T',' ') }}</td>
     <td><button class="edit" data-name="{{ it.name }}">修改</button><button class="del" data-name="{{ it.name }}">删除</button></td>
   </tr>{% endfor %}
  </tbody></table>
 </div>

 <div class="card">
  <h3 style="margin:0 0 8px">两步验证 (2FA)</h3>
  {% if totp_confirmed %}
   <p class="ok">已启用 ✓</p>
  {% elif totp_secret %}
   <p>已生成密钥，请扫码/输入后验证以启用：</p>
   <pre>{{ totp_uri }}</pre>
   <p class="muted">密钥：{{ totp_secret }}</p>
   <div class="row">
     <input type="text" id="totpcode" placeholder="输入 6 位验证码" style="max-width:160px">
     <button class="sec" id="confirm2fa">验证并启用</button>
   </div>
   <div class="msg" id="totpmsg"></div>
  {% else %}
   <button class="sec" id="enroll2fa">启用 Google 身份验证器</button>
   <div class="msg" id="totpmsg"></div>
  {% endif %}
 </div>

<script>
(async ()=>{
 async function j(url, method, body){
   const opt={method:method, headers:{'Content-Type':'application/json'}};
   if(body!==undefined) opt.body=JSON.stringify(body);
   const r=await fetch(url, opt); return r.json();
 }
 const TYPES = await (await fetch('/api/types')).json();
 function typeFields(t){ return (TYPES[t] && TYPES[t].fields) || []; }
 function renderTypeSelect(){
   const sel=document.getElementById('type'); sel.innerHTML='';
   for(const [k,v] of Object.entries(TYPES)){
     const o=document.createElement('option'); o.value=k; o.textContent=v.label; sel.appendChild(o);
   }
 }
 function renderFields(type, values){
   values=values||{}; const box=document.getElementById('dynfields'); box.innerHTML='';
   typeFields(type).forEach(f=>{
     const lab=document.createElement('label'); lab.textContent=f.label;
     const inp=document.createElement(f.kind==='textarea'?'textarea':'input');
     if(f.kind!=='textarea') inp.type = f.secret?'password':'text';
     inp.name=f.key;
     let val=values[f.key]; if(val==null && f.default!=null) val=f.default;
     if(val!=null) inp.value=val;
     lab.appendChild(inp); box.appendChild(lab);
   });
 }
 function collectFields(){
   const type=document.getElementById('type').value; const out={};
   typeFields(type).forEach(f=>{ const el=document.querySelector('#dynfields [name="'+f.key+'"]'); if(el) out[f.key]=el.value; });
   return out;
 }
 function resetForm(){
   document.getElementById('original_name').value='';
   document.getElementById('f_name').value='';
   document.getElementById('f_note').value='';
   document.getElementById('type').value='generic';
   renderFields('generic',{});
   document.getElementById('submitbtn').textContent='加密保存';
   document.getElementById('editbanner').style.display='none';
 }
 renderTypeSelect(); renderFields('generic',{});
 document.getElementById('cancelbtn').onclick=resetForm;
 document.getElementById('type').onchange=()=>renderFields(document.getElementById('type').value, collectFields());
 document.getElementById('add').onsubmit=async(e)=>{
   e.preventDefault();
   const orig=document.getElementById('original_name').value;
   const body={name:document.getElementById('f_name').value, type:document.getElementById('type').value,
               fields:collectFields(), note:document.getElementById('f_note').value};
   if(orig) body.original_name=orig;
   const d=await j('/api/credentials','POST',body);
   document.getElementById('addmsg').textContent = d.ok ? ('已保存 '+d.name) : ('错误：'+d.error);
   if(d.ok){ resetForm(); location.reload(); }
 };
 document.querySelectorAll('button.del').forEach(b=>b.onclick=async()=>{
   if(!confirm('确认删除 '+b.dataset.name+' ?')) return;
   const d=await j('/api/credentials/'+encodeURIComponent(b.dataset.name),'DELETE');
   if(d.ok) location.reload(); else alert(d.error);
 });
 document.querySelectorAll('button.edit').forEach(b=>b.onclick=async()=>{
   const d=await j('/api/credentials/'+encodeURIComponent(b.dataset.name),'GET');
   if(!d.ok){ alert(d.error); return; }
   document.getElementById('original_name').value=d.name;
   document.getElementById('f_name').value=d.name;
   document.getElementById('f_note').value=d.note||'';
   document.getElementById('type').value=d.type;
   renderFields(d.type, d.fields||{});
   document.getElementById('submitbtn').textContent='保存修改';
   const banner=document.getElementById('editbanner'); banner.style.display='block'; banner.textContent='正在修改：'+d.name;
   window.scrollTo({top:0,behavior:'smooth'});
 });
 const enroll=document.getElementById('enroll2fa');
 if(enroll) enroll.onclick=async()=>{ const d=await j('/api/totp/enroll','POST',{}); if(d.ok) location.reload(); };
 const confirm=document.getElementById('confirm2fa');
 if(confirm) confirm.onclick=async()=>{
   const d=await j('/api/totp/confirm','POST',{code:document.getElementById('totpcode').value});
   document.getElementById('totpmsg').textContent = d.ok ? '已启用 2FA' : ('验证失败：'+d.error);
   if(d.ok) location.reload();
 };
})();
</script>
</body></html>""", autoescape=True)


# --------------------------------------------------------------------------
# MCP (remote, Streamable HTTP) — bearer-token authenticated, per-user
# --------------------------------------------------------------------------
mcp = FastMCP("vault-mcp-server")


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


session_manager = mcp.streamable_http_app()


app = FastAPI(title="Vault MCP Server")
app.state.cfg = cfg
app.mount("/mcp", session_manager)


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
@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = ""):
    return LOGIN_TPL.render(error=error)


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), totp: str = Form("")):
    user_cfg = config.find_user(app.state.cfg, username)
    if not user_cfg or not auth.verify_password(password, user_cfg.get("password_hash", "")):
        return LOGIN_TPL.render(error="用户名或密码错误")
    state = config.load_user_state(username)
    if state.get("totp_confirmed"):
        if not auth.verify_totp(state.get("totp_secret", ""), totp):
            return LOGIN_TPL.render(error="需要正确的 2FA 验证码")
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
        items = [{"name": f"(list error: {e})", "note": "", "updated": ""}]
    totp_uri = auth.totp_uri(secret, user) if secret else ""
    return DASH_TPL.render(user=user, items=items, mode=mode, type_labels=TYPE_LABELS,
                           totp_secret=secret or "", totp_confirmed=bool(state.get("totp_confirmed")),
                           totp_uri=totp_uri)


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
