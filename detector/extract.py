"""Resolve a prompt/model value out of a parsed JSON request body using a small
dotted-path mini-language.

Path syntax: dotted keys with optional bracketed list indices, e.g.

    messages[-1].content.parts[0]
    contents[-1].parts[0].text
    model

Indices may be negative (``[-1]`` = last element). Any miss (wrong key, index
out of range, type mismatch) resolves to ``None`` rather than raising.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Callable, Optional, Tuple

# Matches a key segment followed by zero or more [index] groups, e.g. "parts[0]".
_SEGMENT = re.compile(r"([^.\[\]]+)((?:\[-?\d+\])*)")
_INDEX = re.compile(r"\[(-?\d+)\]")


def _tokenize(path: str) -> list:
    """Turn a path string into a flat list of keys (str) and indices (int)."""
    tokens: list = []
    for part in path.split("."):
        if not part:
            continue
        m = _SEGMENT.fullmatch(part)
        if not m:
            # Unparseable segment -> treat the whole path as unresolvable.
            return []
        key, indices = m.group(1), m.group(2)
        tokens.append(key)
        for idx in _INDEX.findall(indices):
            tokens.append(int(idx))
    return tokens


def resolve_path(obj: Any, path: str) -> Optional[Any]:
    """Walk ``obj`` following ``path``; return the value or None on any miss."""
    if not path:
        return None
    cur = obj
    for token in _tokenize(path):
        if isinstance(token, int):
            if not isinstance(cur, list):
                return None
            try:
                cur = cur[token]
            except IndexError:
                return None
        else:
            if not isinstance(cur, dict) or token not in cur:
                return None
            cur = cur[token]
    return cur


# --- Per-provider request decoders for bodies that aren't plain JSON. ---------
# Some providers don't send a clean JSON body that the dotted-path language can
# walk. Those get a named handler here (selected by `request_handler` in the
# endpoint config), mirroring the SSE handler registry in sse.py.

def parse_gemini_request(body_text: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract the user prompt from a Gemini web ``StreamGenerate`` request.

    The body is form-encoded (``f.req=<urlencoded JSON>&at=<token>``) and the
    prompt is double-nested: ``f.req`` -> JSON array whose ``[1]`` is itself a
    JSON *string* -> parse that -> ``[0][0]`` is the prompt text. The model is
    not present in the request (it only appears in the response), so it's None.
    Any miss along the way yields ``(None, None)``.
    """
    try:
        form = urllib.parse.parse_qs(body_text)
        freq = form.get("f.req", [None])[0]
        if not freq:
            return None, None
        outer = json.loads(freq)
        inner = json.loads(outer[1])
        prompt = inner[0][0]
    except (ValueError, TypeError, IndexError, KeyError):
        return None, None
    return (prompt if isinstance(prompt, str) else None), None


REQUEST_HANDLERS: dict[str, Callable[[str], Tuple[Optional[str], Optional[str]]]] = {
    "gemini": parse_gemini_request,
}


def extract_prompt(rule, request_body_text: Optional[str]):
    """Return ``(prompt, model)`` extracted from the request body, or
    ``(None, None)`` if the body is missing or unparseable.

    If the rule names a `request_handler`, the body is decoded by that handler
    (for bodies that aren't plain JSON); otherwise the prompt/model are resolved
    via the dotted-path mini-language against the parsed JSON body."""
    if not request_body_text:
        return None, None
    handler = getattr(rule, "request_handler", None)
    if handler:
        fn = REQUEST_HANDLERS.get(handler)
        return fn(request_body_text) if fn else (None, None)
    try:
        body = json.loads(request_body_text)
    except (ValueError, TypeError):
        return None, None
    prompt = resolve_path(body, rule.prompt_path) if rule.prompt_path else None
    model = resolve_path(body, rule.model_path) if rule.model_path else None
    return prompt, model
