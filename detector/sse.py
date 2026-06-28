"""Per-provider reconstruction of streamed (Server-Sent Events) responses.

Each provider streams its answer in a different shape, so reconstruction lives
in code (a small handler per provider) rather than in the YAML config. A handler
takes the raw response body text and returns the assistant's reconstructed text.

ChatGPT, Claude, Gemini, Perplexity, and Grok are implemented against real
captures. OpenAI API is a stub pending a real traffic sample.
"""
from __future__ import annotations

import json
from typing import Callable, Iterator, Optional

# The JSON-pointer ChatGPT uses for the visible assistant text.
_PARTS_POINTER = "/message/content/parts/0"


def _iter_data_payloads(body_text: str) -> Iterator[str]:
    """Yield the raw string after each ``data:`` line in an SSE stream."""
    for line in body_text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            yield line[len("data:"):].strip()


def parse_chatgpt_sse(body_text: str) -> str:
    """Reconstruct the assistant text from ChatGPT's ``delta_encoding "v1"`` stream.

    The protocol streams JSON deltas after ``data:`` lines:
      * a full message object whose ``author.role == "assistant"`` starts the turn;
      * explicit appends ``{"o":"append","p":"/message/content/parts/0","v":"Hey."}``;
      * bare shorthand appends ``{"v":" more"}`` that reuse the last pointer/op;
      * ``{"o":"patch","v":[ ...ops... ]}`` batches.
    We accumulate text written to the parts pointer while the active message is the
    assistant's text message (ignoring system / user / reasoning messages).
    """
    buf: list[str] = []
    capturing = False          # is the active message the assistant text message?
    current_pointer = None     # last pointer written to (for bare {"v": ...} appends)

    def _message_of(delta: dict):
        v = delta.get("v")
        if isinstance(v, dict):
            if isinstance(v.get("message"), dict):
                return v["message"]
            if "author" in v:
                return v
        return None

    for payload in _iter_data_payloads(body_text):
        if not payload or payload == "[DONE]":
            continue
        try:
            delta = json.loads(payload)
        except ValueError:
            continue
        if not isinstance(delta, dict):
            # e.g. the leading `"v1"` encoding marker.
            continue

        # 1. A full message object (re)sets which message we're tracking.
        msg = _message_of(delta)
        if msg is not None:
            role = (msg.get("author") or {}).get("role")
            content_type = (msg.get("content") or {}).get("content_type")
            capturing = role == "assistant" and content_type == "text"
            current_pointer = _PARTS_POINTER if capturing else None
            if capturing:
                parts = (msg.get("content") or {}).get("parts") or []
                if parts and isinstance(parts[0], str) and parts[0]:
                    buf.append(parts[0])
            continue

        op = delta.get("o")

        # 2. Explicit append at a pointer.
        if op == "append" and isinstance(delta.get("v"), str):
            current_pointer = delta.get("p", current_pointer)
            if capturing and current_pointer == _PARTS_POINTER:
                buf.append(delta["v"])
            continue

        # 3. Patch batch: apply each append-to-parts op.
        if op == "patch" and isinstance(delta.get("v"), list):
            for sub in delta["v"]:
                if (
                    isinstance(sub, dict)
                    and sub.get("o") == "append"
                    and sub.get("p") == _PARTS_POINTER
                    and isinstance(sub.get("v"), str)
                    and capturing
                ):
                    buf.append(sub["v"])
            continue

        # 4. Bare shorthand append: reuse the last pointer/op.
        if set(delta.keys()) <= {"v", "c"} and isinstance(delta.get("v"), str):
            if capturing and current_pointer == _PARTS_POINTER:
                buf.append(delta["v"])
            continue

    return "".join(buf)


# --- Implemented against real captured traffic. -------------------------------

def parse_claude_sse(body_text: str) -> str:
    """Reconstruct the assistant text from claude.ai's Anthropic SSE stream.

    The turn streams `event: content_block_delta` records whose data is
    ``{"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}``.
    Extended-thinking blocks arrive as ``thinking_delta`` deltas and are skipped
    so only the visible answer is captured.
    """
    buf: list[str] = []
    for payload in _iter_data_payloads(body_text):
        if not payload:
            continue
        try:
            event = json.loads(payload)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("type") != "content_block_delta":
            continue
        delta = event.get("delta") or {}
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            buf.append(delta["text"])
    return "".join(buf)


def _iter_gemini_wrb_fr(body_text: str) -> Iterator[list]:
    """Yield each parsed ``wrb.fr`` inner array from a Gemini web stream.

    The web app's ``StreamGenerate`` response is Google's chunked format: a
    ``)]}'`` prefix, then repeated ``<length>\\n<JSON array>`` frames. Each frame
    is an array of records like ``["wrb.fr", null, "<inner JSON string>"]`` (plus
    control records such as ``["di", N]`` / ``["af.httprm", ...]``). We decode the
    arrays with ``raw_decode`` (ignoring the numeric length lines, which sidesteps
    that brittle framing) and yield the parsed inner array of each ``wrb.fr``.
    """
    text = body_text
    if text.startswith(")]}'"):
        text = text[len(")]}'"):]
    decoder = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        # Skip whitespace and the numeric length prefix lines between frames.
        while i < n and (text[i].isspace() or text[i].isdigit()):
            i += 1
        if i >= n:
            break
        try:
            obj, end = decoder.raw_decode(text, i)
        except ValueError:
            i += 1
            continue
        i = end
        if not isinstance(obj, list):
            continue
        for record in obj:
            if (
                isinstance(record, list)
                and len(record) >= 3
                and record[0] == "wrb.fr"
                and isinstance(record[2], str)
            ):
                try:
                    yield json.loads(record[2])
                except ValueError:
                    continue


def parse_gemini_sse(body_text: str) -> str:
    """Reconstruct the assistant text from a Gemini web ``StreamGenerate`` stream.

    The stream is cumulative: each ``wrb.fr`` frame resends the full answer so
    far at ``inner[4][0][1][0]`` (rather than appending deltas), so we keep the
    last non-empty candidate. Frames without that shape (e.g. encrypted
    ``batchexecute`` blobs) contribute nothing.
    """
    text = ""
    for inner in _iter_gemini_wrb_fr(body_text):
        try:
            candidate = inner[4][0][1][0]
        except (IndexError, TypeError, KeyError):
            continue
        if isinstance(candidate, str) and candidate:
            text = candidate
    return text


def parse_gemini_model(body_text: str) -> Optional[str]:
    """Read the model display name (e.g. ``"3.5 Flash"``) from a Gemini web
    response. Gemini doesn't send the model in the request, so it's recovered
    here from ``inner[42]`` of the last ``wrb.fr`` frame that carries it."""
    model: Optional[str] = None
    for inner in _iter_gemini_wrb_fr(body_text):
        try:
            candidate = inner[42]
        except (IndexError, TypeError, KeyError):
            continue
        if isinstance(candidate, str) and candidate:
            model = candidate
    return model


def _iter_grok_results(body_text: str) -> Iterator[dict]:
    """Yield the unwrapped inner object of each line in a grok.com web stream.

    The ``/rest/app-chat/conversations`` response is newline-delimited JSON (one
    ``{"result": ...}`` object per physical line), not ``data:``-prefixed SSE. Two
    envelope shapes occur: the ``/new`` stream nests fields under
    ``result.response.*`` while the ``/{id}/responses`` stream puts them directly
    under ``result.*``. We normalize both, yielding the inner dict that carries the
    per-frame ``token`` / ``modelResponse`` / etc.
    """
    for line in body_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        inner = obj.get("result", obj)
        if isinstance(inner, dict) and isinstance(inner.get("response"), dict):
            inner = inner["response"]
        if isinstance(inner, dict):
            yield inner


def parse_grok_sse(body_text: str) -> str:
    """Reconstruct the assistant text from a grok.com web chat stream.

    The visible answer streams as ``{"token":"...","messageTag":"final"}`` frames;
    we concatenate the ``final``-tagged tokens. Reasoning/status tokens carry other
    tags (``header`` / ``thinking_start`` / ``response_start``) and are skipped, so
    only the answer is captured (this join equals the server's consolidated
    ``modelResponse.message``).
    """
    buf: list[str] = []
    for inner in _iter_grok_results(body_text):
        if inner.get("messageTag") == "final" and isinstance(inner.get("token"), str):
            buf.append(inner["token"])
    return "".join(buf)


def parse_grok_model(body_text: str) -> Optional[str]:
    """Read the user-facing selected model (e.g. ``"grok-4-auto"``) from a grok.com
    web response. The request only sends ``modeId: "auto"``, so the model name is
    recovered here from ``modelResponse.requestMetadata.model`` of the last frame
    that carries it (the backing ``modelResponse.model`` may differ, e.g. grok-3)."""
    model: Optional[str] = None
    for inner in _iter_grok_results(body_text):
        meta = (inner.get("modelResponse") or {}).get("requestMetadata") or {}
        candidate = meta.get("model")
        if isinstance(candidate, str) and candidate:
            model = candidate
    return model


def parse_perplexity_sse(body_text: str) -> str:
    """Reconstruct the answer from a Perplexity web ``/rest/sse/perplexity_ask`` stream.

    Standard ``event: message`` / ``data: {json}`` SSE. Each data event carries a
    ``blocks`` array; the visible answer lives in a block's
    ``markdown_block.answer``. The stream consolidates the full text into the final
    message, so we keep the last non-empty ``answer`` (this also covers the
    ``ask_text`` / ``ask_text_0_markdown`` block variants that both carry it).
    """
    answer = ""
    for payload in _iter_data_payloads(body_text):
        if not payload or payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        for block in event.get("blocks") or []:
            markdown = block.get("markdown_block") if isinstance(block, dict) else None
            if isinstance(markdown, dict) and isinstance(markdown.get("answer"), str) and markdown["answer"]:
                answer = markdown["answer"]
    return answer


# --- Stub: needs real captured traffic to implement. --------------------------

def parse_openai_sse(body_text: str) -> str:
    # TODO: needs real capture. OpenAI Chat Completions streams
    # `data: {"choices":[{"delta":{"content":"..."}}]}` until `data: [DONE]`.
    return ""


HANDLERS: dict[str, Callable[[str], str]] = {
    "chatgpt": parse_chatgpt_sse,
    "claude": parse_claude_sse,
    "gemini": parse_gemini_sse,
    "perplexity": parse_perplexity_sse,
    "grok": parse_grok_sse,
    "openai": parse_openai_sse,
}

# Providers that only reveal the model in the response (not the request) register
# a model extractor here; reconstruct_model() returns None for everyone else, so
# providers that carry the model in the request are unaffected.
RESPONSE_MODEL_HANDLERS: dict[str, Callable[[str], Optional[str]]] = {
    "gemini": parse_gemini_model,
    "grok": parse_grok_model,
}


def reconstruct_response(handler: str, body_text: str) -> str:
    """Dispatch to a named SSE handler; unknown/empty handlers yield ''."""
    fn = HANDLERS.get(handler)
    if fn is None or not body_text:
        return ""
    return fn(body_text)


def reconstruct_model(handler: str, body_text: str) -> Optional[str]:
    """Recover the model from the response for providers that don't send it in
    the request; returns None when no such handler is registered."""
    fn = RESPONSE_MODEL_HANDLERS.get(handler)
    if fn is None or not body_text:
        return None
    return fn(body_text)
