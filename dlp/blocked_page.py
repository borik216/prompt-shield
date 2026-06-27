"""Render the HTML page returned (403) when a DLP rule blocks a request.

The addon calls :func:`render_blocked_page` with the provider slug and the DLP result
dict; it gets back a complete HTML document (string) to use as the response body.

Kept defensive like the rest of the DLP layer: if the template file is missing or
anything goes wrong, a minimal inline fallback page is returned so a block never errors.
"""
from __future__ import annotations

import html
import logging
import os

log = logging.getLogger("dlp")

_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "blocked_page.html")

# Provider slug (from providers.yaml `name`) -> human label shown on the page.
PROVIDER_DISPLAY = {
    "chatgpt": "ChatGPT",
    "claude": "Claude",
    "gemini": "Gemini",
    "perplexity": "Perplexity",
    "grok": "Grok",
    "openai_api": "OpenAI API",
}

_MESSAGE = "This request was blocked by your organization's AI security policy."

# Loaded once on first render and cached.
_template_cache: str | None = None


def _load_template() -> str | None:
    global _template_cache
    if _template_cache is None:
        try:
            with open(_TEMPLATE_PATH, encoding="utf-8") as f:
                _template_cache = f.read()
        except Exception as exc:
            log.error("dlp: could not load blocked_page.html (%s); using inline fallback", exc)
            _template_cache = ""  # cache the failure; fall back below
    return _template_cache or None


def _data_types(dlp_result: dict) -> str:
    """Human summary of what was detected, e.g. ``US_SSN, CREDIT_CARD``.

    Prefers the PII ``entity`` (presidio), falls back to the ``rule`` name, and finally
    to a generic phrase so the page always says *something* concrete-ish.
    """
    labels: list[str] = []
    for m in dlp_result.get("matches", []):
        label = m.get("entity") or m.get("rule")
        if label and label not in labels:
            labels.append(label)
    return ", ".join(labels) if labels else "sensitive information"


def render_blocked_page(provider_slug: str, dlp_result: dict) -> str:
    """Return the full HTML document for a blocked request.

    Args:
        provider_slug: provider name from providers.yaml (e.g. ``"chatgpt"``).
        dlp_result: the dict returned by :func:`dlp.engine.check_prompt`.
    """
    provider = PROVIDER_DISPLAY.get(provider_slug, provider_slug or "the AI provider")
    data_types = _data_types(dlp_result or {})

    template = _load_template()
    if template is None:
        return _fallback(provider, data_types)

    # html.escape everything interpolated — provider/entity strings are trusted today,
    # but escaping keeps the page safe if a rule name ever carries markup.
    try:
        return (
            template
            .replace("%%PROVIDER%%", html.escape(provider))
            .replace("%%DATA_TYPES%%", html.escape(data_types))
            .replace("%%MESSAGE%%", html.escape(_MESSAGE))
        )
    except Exception as exc:
        log.error("dlp: blocked page render failed (%s); using inline fallback", exc)
        return _fallback(provider, data_types)


def _fallback(provider: str, data_types: str) -> str:
    """Minimal self-contained page used if the template can't be loaded/rendered."""
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Request Blocked</title>"
        "<style>body{background:#0d1117;color:#e6edf3;font-family:sans-serif;"
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
        "div{max-width:480px;padding:32px;border:1px solid #30363d;border-radius:12px;"
        "background:#161b22}h1{color:#f85149;margin-top:0}</style></head><body><div>"
        f"<h1>Request Blocked</h1><p>{html.escape(_MESSAGE)}</p>"
        f"<p>Going to: <b>{html.escape(provider)}</b><br>"
        f"Detected: <b>{html.escape(data_types)}</b></p></div></body></html>"
    )
