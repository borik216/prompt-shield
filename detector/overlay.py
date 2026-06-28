"""In-page DLP block notification: overlay injection + block-response building.

Pure, dependency-light helpers (no mitmproxy import) so they stay unit-testable
like detector/extract.py and detector/sse.py. The addon (detector/addon.py) is
the only place these touch a live mitmproxy flow.

Two halves:
  * HTML injection — splice a small <script> (promptshield_overlay.js) into
    provider web-app pages so the overlay can patch fetch/XHR and show a toast.
  * Block response — build the provider-neutral 403 JSON body + X-PromptShield-*
    headers the overlay reads when a prompt is blocked.

Only category/metadata strings (provider, rule/entity names) ever reach the
headers or body — never the matched sensitive value. The DLP engine already
redacts match snippets; we additionally only surface rule/entity *labels* here.
"""
from __future__ import annotations

import json
import logging
import os
import re

from dlp.blocked_page import PROVIDER_DISPLAY, _data_types

log = logging.getLogger("dlp")

# Idempotency marker placed on the injected <script>. Its presence anywhere in a
# document means PromptShield already injected, so we skip re-injecting.
OVERLAY_MARKER = "data-promptshield-overlay"

_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "static", "promptshield_overlay.js")

# Response header names (kept in one place; reused by the CORS expose list).
HDR_BLOCKED = "X-PromptShield-Blocked"
HDR_PROVIDER = "X-PromptShield-Provider"
HDR_ACTION = "X-PromptShield-Action"
HDR_REASON = "X-PromptShield-Reason"
HDR_RULE = "X-PromptShield-Rule"
_EXPOSE = ", ".join([HDR_BLOCKED, HDR_PROVIDER, HDR_ACTION, HDR_REASON, HDR_RULE])

_script_cache: str | None = None


def load_overlay_script() -> str:
    """Return the overlay JS text, read once and cached. '' if it can't be read
    (the addon then simply skips injection — fail-open like the DLP layer)."""
    global _script_cache
    if _script_cache is None:
        try:
            with open(_SCRIPT_PATH, encoding="utf-8") as f:
                _script_cache = f.read()
        except Exception as exc:  # pragma: no cover - defensive
            log.error("overlay: could not load promptshield_overlay.js (%s)", exc)
            _script_cache = ""
    return _script_cache


def build_script_tag(script: str | None = None) -> str:
    """Wrap the overlay JS in an inline <script> carrying the idempotency marker."""
    if script is None:
        script = load_overlay_script()
    return f"<script {OVERLAY_MARKER}>\n{script}\n</script>"


def should_inject(content_type: str | None, status_code: int, method: str) -> bool:
    """True only for a successful HTML document fetched by GET.

    Excludes JSON/SSE/JS bundles/images/fonts and all API/XHR-shaped responses,
    so we never rewrite anything but a real page load.
    """
    if (method or "").upper() != "GET":
        return False
    if not (200 <= status_code < 300):
        return False
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    return ctype == "text/html"


def inject_overlay(html_text: str, script_tag: str | None = None) -> str:
    """Splice the overlay <script> into an HTML document.

    Idempotent: if OVERLAY_MARKER is already present the document is returned
    unchanged. The tag is inserted as early as possible so the fetch/XHR patch
    runs before the provider's app bundle: right after the opening <head>, else
    before </head>, else after <body>, else prepended.
    """
    if script_tag is None:
        script_tag = build_script_tag()
    if OVERLAY_MARKER in html_text:
        return html_text  # already injected (or marker present) — leave it be

    # Right after the opening <head ...> tag (earliest in-<head> position).
    m = re.search(r"<head\b[^>]*>", html_text, re.IGNORECASE)
    if m:
        i = m.end()
        return html_text[:i] + script_tag + html_text[i:]

    # Before </head>.
    m = re.search(r"</head\s*>", html_text, re.IGNORECASE)
    if m:
        i = m.start()
        return html_text[:i] + script_tag + html_text[i:]

    # Right after the opening <body ...> tag.
    m = re.search(r"<body\b[^>]*>", html_text, re.IGNORECASE)
    if m:
        i = m.end()
        return html_text[:i] + script_tag + html_text[i:]

    # No head/body at all — just prepend.
    return script_tag + html_text


def _safe_header(value: str) -> str:
    """Keep header values ASCII and single-line. Rule/entity labels are ASCII
    today; this guards against a future label carrying odd characters."""
    cleaned = (value or "").replace("\r", " ").replace("\n", " ").strip()
    return cleaned.encode("ascii", "ignore").decode("ascii")


def build_block_response(provider_slug: str, dlp_result: dict, origin: str = ""):
    """Build the provider-neutral 403 block response.

    Returns ``(body_bytes, headers)`` for ``http.Response.make(403, body, headers)``.
    The overlay reads the X-PromptShield-* headers (preferring them) and falls
    back to the JSON body. No raw prompt text or un-redacted match ever appears.
    """
    provider_label = PROVIDER_DISPLAY.get(provider_slug, provider_slug or "the AI provider")
    reason = _data_types(dlp_result or {})  # e.g. "US_SSN, CREDIT_CARD" (labels only)

    # First blocking rule's name, for the more specific X-PromptShield-Rule header.
    rule_name = ""
    for m in (dlp_result or {}).get("matches", []):
        if m.get("action") == "block":
            rule_name = m.get("rule", "")
            break

    body = {
        "error": "PromptShield blocked this prompt",
        "provider": provider_slug,
        "action": "blocked",
        "reason": reason,
        "rule": rule_name,
        "details": "The request was blocked locally before being sent to the provider.",
    }
    body_bytes = json.dumps(body).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        HDR_BLOCKED: "1",
        HDR_PROVIDER: _safe_header(provider_label),
        HDR_ACTION: "blocked",
        HDR_REASON: _safe_header(reason),
        HDR_RULE: _safe_header(rule_name),
    }
    if origin:
        # Let same-/cross-origin page JS read our custom headers when needed.
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Expose-Headers"] = _EXPOSE

    return body_bytes, headers
