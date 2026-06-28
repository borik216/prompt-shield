"""Build committed, sanitized minimal fixtures from full local captures.

Reads recorder NDJSON from ``tests/fixtures/local/<provider>.json``, keeps only
the lines the offline harness exercises, redacts identifiers, and writes
``tests/fixtures/<provider>.json``.

    .venv/bin/python tests/build_fixtures.py
"""
from __future__ import annotations

import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_LOCAL = os.path.join(_HERE, "fixtures", "local")
_OUT = os.path.join(_HERE, "fixtures")

_FAKE_UUID = "00000000-0000-0000-0000-000000000001"
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_USER_ID_RE = re.compile(r"user-[A-Za-z0-9]{20,}")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _read_entries(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _sanitize_text(text: str) -> str:
    text = _UUID_RE.sub(_FAKE_UUID, text)
    text = _USER_ID_RE.sub("user-FAKE000000000000000000", text)
    text = _EMAIL_RE.sub("fake.user@example.com", text)
    return text


def _sanitize_entry(entry: dict, ts: float) -> dict:
    out = {}
    for key, value in entry.items():
        if key == "timestamp" and isinstance(value, (int, float)):
            out[key] = ts
        elif isinstance(value, str):
            out[key] = _sanitize_text(value)
        else:
            out[key] = value
    return out


def _pick_chatgpt(entries: list[dict]) -> list[dict]:
    req = next(
        e for e in entries
        if e.get("path") == "/backend-api/f/conversation" and "request_body" in e
    )
    resp = next(
        e for e in entries
        if "response_body" in e
        and "delta_encoding" in (e.get("response_body") or "")
        and reconstruct_ok("chatgpt", e["response_body"])
    )
    return [req, resp]


def _pick_claude(entries: list[dict]) -> list[dict]:
    req = next(
        e for e in entries
        if "request_body" in e and (e.get("path") or "").endswith("/completion")
    )
    resp = next(
        e for e in entries
        if "response_body" in e and "content_block_delta" in (e.get("response_body") or "")
    )
    return [req, resp]


def _pick_gemini(entries: list[dict]) -> list[dict]:
    req_idx = next(
        i for i, e in enumerate(entries)
        if "request_body" in e and "StreamGenerate" in (e.get("path") or "")
    )
    picked = [entries[req_idx]]
    for e in entries[req_idx + 1:]:
        if "request_body" in e and "StreamGenerate" in (e.get("path") or ""):
            break
        if "response_body" in e and "wrb.fr" in (e.get("response_body") or ""):
            picked.append(e)
    return picked


def _pick_perplexity(entries: list[dict]) -> list[dict]:
    req = next(
        e for e in entries
        if e.get("path") == "/rest/sse/perplexity_ask" and "request_body" in e
    )
    resp = next(
        e for e in entries
        if "response_body" in e and "markdown_block" in (e.get("response_body") or "")
    )
    return [req, resp]


def _pick_grok(entries: list[dict]) -> list[dict]:
    reqs = [
        e for e in entries
        if "request_body" in e
        and (
            (e.get("path") or "").endswith("/conversations/new")
            or (e.get("path") or "").endswith("/responses")
        )
    ]
    resps = [
        e for e in entries
        if "response_body" in e and "modelResponse" in (e.get("response_body") or "")
    ]
    # Interleave first new + first response, then follow-up + second response.
    return [reqs[0], resps[0], reqs[1], resps[1]]


def reconstruct_ok(handler: str, body: str) -> bool:
    sys.path.insert(0, os.path.dirname(_HERE))
    from detector.sse import reconstruct_response  # noqa: WPS433
    return bool(reconstruct_response(handler, body))


_PICKERS = {
    "chatgpt": _pick_chatgpt,
    "claude": _pick_claude,
    "gemini": _pick_gemini,
    "perplexity": _pick_perplexity,
    "grok": _pick_grok,
}


def build_provider(name: str) -> int:
    src = os.path.join(_LOCAL, f"{name}.json")
    if not os.path.isfile(src):
        print(f"skip {name}: no local capture at {src}")
        return 0

    picker = _PICKERS[name]
    picked = picker(_read_entries(src))
    dst = os.path.join(_OUT, f"{name}.json")
    with open(dst, "w", encoding="utf-8") as fh:
        for i, entry in enumerate(picked):
            fh.write(json.dumps(_sanitize_entry(entry, 1700000000.0 + i), ensure_ascii=False) + "\n")
    print(f"wrote {dst} ({len(picked)} lines)")
    return len(picked)


def main() -> int:
    if not os.path.isdir(_LOCAL):
        print(f"Missing {_LOCAL} — place full captures there first.", file=sys.stderr)
        return 1

    total = 0
    for name in _PICKERS:
        total += build_provider(name)
    if total == 0:
        print("No fixtures built.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())