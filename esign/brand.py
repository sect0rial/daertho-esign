"""White-label branding.

Everything a deployer can change about how the product looks and what it calls itself comes from ESIGN_BRAND_*
environment variables. The browser reads GET /v1/brand (JSON) and GET /brand.css (CSS custom properties); Python code
(emails, the seal reason, the Certificate of Completion) calls name() / legal_name() / support_email().
"""
from __future__ import annotations

import os
import re
from urllib.parse import quote_plus

from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response

router = APIRouter()

_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_FONT = re.compile(r"^[A-Za-z0-9 ]{1,40}$")

DEFAULTS = {
    "name": "Daertho E-Sign",
    "accent": "#111111",
    "accent_ink": "#ffffff",
    "bg": "#f6f5f1",
    "ink": "#111111",
    "font_head": "Fraunces",
    "font_body": "Inter",
}


def _env(key: str) -> str:
    return (os.environ.get("ESIGN_BRAND_" + key) or "").strip()


def _color(key: str, default: str) -> str:
    v = _env(key)
    return v if _HEX.match(v) else default


def _font(key: str, default: str) -> str:
    v = _env(key)
    return v if _FONT.match(v) else default


def name() -> str:
    return (_env("NAME") or DEFAULTS["name"])[:80]


def legal_name() -> str:
    return (_env("LEGAL_NAME") or name())[:120]


def support_email() -> str:
    return _env("SUPPORT_EMAIL")[:200]


def logo_url() -> str:
    v = _env("LOGO_URL")
    # only https:// or a same-origin path; never javascript:/data: URLs
    return v if v.startswith("https://") or (v.startswith("/") and not v.startswith("//")) else ""


def powered_by() -> bool:
    return _env("HIDE_POWERED_BY") != "1"


def as_dict() -> dict:
    return {
        "name": name(),
        "legal_name": legal_name(),
        "logo_url": logo_url(),
        "accent": _color("ACCENT", DEFAULTS["accent"]),
        "accent_ink": _color("ACCENT_INK", DEFAULTS["accent_ink"]),
        "bg": _color("BG", DEFAULTS["bg"]),
        "ink": _color("INK", DEFAULTS["ink"]),
        "font_head": _font("FONT_HEAD", DEFAULTS["font_head"]),
        "font_body": _font("FONT_BODY", DEFAULTS["font_body"]),
        "support_email": support_email(),
        "powered_by": powered_by(),
    }


def css() -> str:
    b = as_dict()
    fams = "&".join("family=" + quote_plus(f) + ":wght@400;500;600;700"
                    for f in dict.fromkeys([b["font_head"], b["font_body"]]))
    return (
        f"@import url('https://fonts.googleapis.com/css2?{fams}&display=swap');\n"
        ":root{"
        f"--brand-accent:{b['accent']};--brand-accent-ink:{b['accent_ink']};"
        f"--brand-bg:{b['bg']};--brand-ink:{b['ink']};"
        f"--brand-font-head:'{b['font_head']}',Georgia,serif;"
        f"--brand-font-body:'{b['font_body']}',system-ui,-apple-system,'Segoe UI',sans-serif;"
        "}\n"
    )


@router.get("/v1/brand")
def brand_json():
    return JSONResponse(as_dict(), headers={"Cache-Control": "public, max-age=300"})


@router.get("/brand.css")
def brand_css():
    return Response(css(), media_type="text/css", headers={"Cache-Control": "public, max-age=300"})
