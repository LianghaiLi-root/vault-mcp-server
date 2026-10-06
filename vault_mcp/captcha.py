#!/usr/bin/env python3
"""
captcha.py — human-verification challenges for the web login form.

Modes, chosen by an administrator:

    off        no challenge
    numeric    digits only, rendered as an image
    image      letters + digits, rendered as an image with noise
    turnstile  Cloudflare Turnstile — requires BOTH a site key and a secret key

Rendering uses Pillow when it is importable. If Pillow is missing we do NOT
silently let every login through — that would turn a broken challenge into no
challenge at all. Instead we degrade to an arithmetic question, which needs no
third-party package and still requires a human-ish answer.

Answers never reach the client. The browser receives only an opaque id; the
expected answer is held server-side with a short TTL and is single-use, so a
captured id cannot be replayed.
"""

import base64
import hmac
import io
import json
import os
import random
import time
import urllib.parse
import urllib.request

try:  # optional dependency — see module docstring for the fallback
    from PIL import Image, ImageDraw, ImageFilter, ImageFont

    _PIL = True
except Exception:  # pragma: no cover - exercised on minimal installs
    _PIL = False


# Confusable glyphs (0/O, 1/I/l) are omitted so a human can actually read it.
_DIGITS = "0123456789"
_ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

_TTL = 300.0          # a challenge is valid for 5 minutes
_MAX_ENTRIES = 4000   # hard cap so a flood cannot grow memory without bound

# id -> (expected_answer_lowercased, expires_at)
_ANSWERS: dict[str, tuple[str, float]] = {}

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def pillow_available() -> bool:
    return _PIL


# --------------------------------------------------------------------------
# challenge store
# --------------------------------------------------------------------------
def _cleanup() -> None:
    now = time.time()
    for k in [k for k, v in _ANSWERS.items() if v[1] < now]:
        _ANSWERS.pop(k, None)


def _store(answer: str) -> str:
    _cleanup()
    if len(_ANSWERS) >= _MAX_ENTRIES:
        # evict the entries closest to expiry (oldest first)
        for k in sorted(_ANSWERS, key=lambda k: _ANSWERS[k][1])[: _MAX_ENTRIES // 4]:
            _ANSWERS.pop(k, None)
    cid = os.urandom(16).hex()
    _ANSWERS[cid] = (str(answer).strip().lower(), time.time() + _TTL)
    return cid


def consume(cid: str, answer: str) -> bool:
    """Check and burn a challenge. Single-use by construction."""
    _cleanup()
    if not cid or answer is None:
        return False
    item = _ANSWERS.pop(cid, None)   # pop == burn, even when the answer is wrong
    if not item:
        return False
    expected, expires = item
    if time.time() > expires:
        return False
    return hmac.compare_digest(expected, str(answer).strip().lower())


def pending_count() -> int:
    _cleanup()
    return len(_ANSWERS)


# --------------------------------------------------------------------------
# image rendering (Pillow)
# --------------------------------------------------------------------------
def _font(size: int):
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/arialbd.ttf",
        "C:/Windows/Fonts/consola.ttf",
    ):
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                pass
    try:
        return ImageFont.load_default(size=size)   # Pillow >= 9.2
    except Exception:
        return ImageFont.load_default()


def render_png(text: str, *, lines: int, dots: int, tilt: float = 26.0) -> bytes | None:
    """Render `text` into a PNG. Returns None when Pillow is unavailable."""
    if not _PIL:
        return None

    width = 26 * len(text) + 34
    height = 62
    img = Image.new("RGB", (width, height), (246, 248, 252))
    draw = ImageDraw.Draw(img)

    # noise goes underneath the glyphs
    for _ in range(lines):
        draw.line(
            [(random.randint(0, width), random.randint(0, height)),
             (random.randint(0, width), random.randint(0, height))],
            fill=(random.randint(150, 205),) * 3, width=2,
        )
    for _ in range(dots):
        x, y = random.randint(0, width - 4), random.randint(0, height - 4)
        draw.ellipse([x, y, x + 3, y + 3], fill=(random.randint(155, 215),) * 3)

    span = (width - 30) / max(1, len(text))
    for i, ch in enumerate(text):
        size = random.randint(31, 39)
        tile = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        ImageDraw.Draw(tile).text(
            (32, 32), ch, font=_font(size), anchor="mm",
            fill=(random.randint(20, 85), random.randint(20, 85), random.randint(85, 155)),
        )
        tile = tile.rotate(random.uniform(-tilt, tilt),
                           resample=Image.BICUBIC, expand=False)
        img.paste(tile,
                  (int(12 + i * span + random.uniform(-3, 3)),
                   int((height - 64) / 2 + random.uniform(-7, 7))),
                  tile)

    img = img.filter(ImageFilter.SMOOTH)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# --------------------------------------------------------------------------
# issuing
# --------------------------------------------------------------------------
def _issue_math() -> dict:
    """Zero-dependency fallback used when Pillow is not installed."""
    a, b = random.randint(2, 9), random.randint(2, 9)
    op = random.choice(["+", "+", "-"])
    if op == "-" and b > a:
        a, b = b, a
    answer = a + b if op == "+" else a - b
    return {"ok": True, "mode": "math", "id": _store(str(answer)),
            "question": f"{a} {op} {b} = ?"}


def issue(mode: str, length: int = 4) -> dict:
    """Build a client-facing challenge payload (never contains the answer)."""
    mode = (mode or "off").strip().lower()
    if mode == "off":
        return {"ok": True, "mode": "off"}
    if mode == "turnstile":
        # the widget is rendered by Cloudflare's script; nothing to store here
        return {"ok": True, "mode": "turnstile"}
    if mode not in ("numeric", "image"):
        return {"ok": False, "error": f"未知的验证方式: {mode}"}

    length = max(3, min(8, int(length or 4)))
    if not _PIL:
        return _issue_math()

    alphabet = _DIGITS if mode == "numeric" else _ALNUM
    text = "".join(random.choice(alphabet) for _ in range(length))
    png = render_png(text,
                     lines=0 if mode == "numeric" else 4,
                     dots=28 if mode == "numeric" else 90)
    if png is None:
        return _issue_math()
    return {
        "ok": True, "mode": mode, "id": _store(text),
        "image": "data:image/png;base64," + base64.b64encode(png).decode("ascii"),
    }


# --------------------------------------------------------------------------
# Cloudflare Turnstile
# --------------------------------------------------------------------------
def verify_turnstile(secret: str, token: str, remoteip: str | None = None) -> tuple[bool, str]:
    """POST the widget response to Cloudflare. Returns (ok, reason)."""
    if not secret:
        return False, "未配置 Turnstile Secret Key"
    if not token:
        return False, "缺少 Turnstile 验证响应"
    payload = {"secret": secret, "response": token}
    if remoteip:
        payload["remoteip"] = remoteip
    try:
        req = urllib.request.Request(
            TURNSTILE_VERIFY_URL,
            data=urllib.parse.urlencode(payload).encode("utf-8"),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8") or "{}")
    except Exception as e:
        return False, f"验证请求失败: {e}"
    if data.get("success"):
        return True, ""
    codes = ", ".join(data.get("error-codes") or ["验证未通过"])
    return False, codes
