"""Offline tests for the in-page DLP block notification helpers.

Runs without any test framework (same style as tests/test_dlp.py):

    .venv/bin/python tests/test_overlay.py

Covers the pure helpers in detector/overlay.py: HTML injection (incl.
idempotency and the content-type gate) and the provider-neutral block response
(headers, CORS, and a leak guard that no raw secret reaches headers/body).
"""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _REPO_ROOT)

from detector.overlay import (  # noqa: E402
    OVERLAY_MARKER,
    build_block_response,
    build_script_tag,
    inject_overlay,
    should_inject,
)

_PAGE = "<!doctype html><html><head><title>Provider</title></head><body>hi</body></html>"


def test_inject_into_head():
    out = inject_overlay(_PAGE)
    assert OVERLAY_MARKER in out, out
    assert "promptshield" in out.lower(), out
    # Inserted inside <head>, before the page's own <title>.
    assert out.index(OVERLAY_MARKER) < out.index("<title>"), out
    assert out.index("<head>") < out.index(OVERLAY_MARKER), out
    print("OK: overlay injected into <head>")


def test_inject_idempotent():
    once = inject_overlay(_PAGE)
    twice = inject_overlay(once)
    assert twice == once, "re-injection changed the document"
    assert once.count(OVERLAY_MARKER) == 1, once.count(OVERLAY_MARKER)
    print("OK: injection is idempotent")


def test_inject_fallbacks():
    # No <head>: insert after <body>.
    body_only = "<html><body>x</body></html>"
    out = inject_overlay(body_only)
    assert OVERLAY_MARKER in out and out.index("<body>") < out.index(OVERLAY_MARKER), out
    # No head/body at all: prepend.
    bare = "<p>x</p>"
    out2 = inject_overlay(bare)
    assert out2.startswith("<script "), out2
    print("OK: injection falls back to <body> / prepend")


def test_should_inject_gate():
    assert should_inject("text/html; charset=utf-8", 200, "GET")
    assert not should_inject("application/json", 200, "GET"), "JSON must not inject"
    assert not should_inject("text/event-stream", 200, "GET"), "SSE must not inject"
    assert not should_inject("text/html", 200, "POST"), "non-GET must not inject"
    assert not should_inject("text/html", 403, "GET"), "non-2xx must not inject"
    assert not should_inject("application/javascript", 200, "GET"), "JS must not inject"
    print("OK: should_inject gates content-type / status / method")


def test_script_tag_carries_marker():
    tag = build_script_tag("/* overlay */")
    assert tag.startswith("<script " + OVERLAY_MARKER + ">"), tag
    assert tag.rstrip().endswith("</script>"), tag
    print("OK: script tag carries the idempotency marker")


def _dlp_result():
    return {
        "action": "block",
        "blocked": True,
        "matches": [
            {"rule": "email_address", "type": "regex", "action": "block",
             "snippet": "test….com"},
        ],
    }


def test_block_response_headers():
    body, headers = build_block_response("chatgpt", _dlp_result(), origin="")
    assert headers["X-PromptShield-Blocked"] == "1", headers
    assert headers["X-PromptShield-Provider"] == "ChatGPT", headers
    assert headers["X-PromptShield-Action"] == "blocked", headers
    assert headers["X-PromptShield-Reason"] == "email_address", headers
    assert headers["X-PromptShield-Rule"] == "email_address", headers
    assert headers["Content-Type"] == "application/json", headers
    assert headers["Cache-Control"] == "no-store", headers
    # No CORS headers without an Origin.
    assert "Access-Control-Allow-Origin" not in headers, headers
    payload = json.loads(body.decode("utf-8"))
    assert payload["action"] == "blocked", payload
    assert payload["provider"] == "chatgpt", payload
    print("OK: block response carries all PromptShield headers")


def test_block_response_cors_with_origin():
    _, headers = build_block_response("claude", _dlp_result(), origin="https://claude.ai")
    assert headers["Access-Control-Allow-Origin"] == "https://claude.ai", headers
    assert headers["Access-Control-Allow-Credentials"] == "true", headers
    assert "X-PromptShield-Blocked" in headers["Access-Control-Expose-Headers"], headers
    print("OK: CORS headers added when Origin present")


def test_block_response_no_secret_leak():
    # A match whose redaction failed and carries a raw secret + raw prompt text:
    # the response must surface only the rule/category label, never the value.
    secret = "sk-FAKE123456789RAWSECRET"
    leaky = {
        "action": "block",
        "blocked": True,
        "matches": [
            {"rule": "openai_api_key", "type": "regex", "action": "block",
             "snippet": secret},
        ],
    }
    body, headers = build_block_response("grok", leaky, origin="https://grok.com")
    serialized = json.dumps(headers) + body.decode("utf-8")
    assert secret not in serialized, "raw secret leaked into block response!"
    # The safe label is still present.
    assert "openai_api_key" in serialized, serialized
    print("OK: block response leaks no raw secret")


if __name__ == "__main__":
    test_inject_into_head()
    test_inject_idempotent()
    test_inject_fallbacks()
    test_should_inject_gate()
    test_script_tag_carries_marker()
    test_block_response_headers()
    test_block_response_cors_with_origin()
    test_block_response_no_secret_leak()
    print("\nAll overlay tests passed.")
