"""PromptShield mitmproxy addon: classify live flows by AI provider, scan
outgoing prompts through DLP, extract the prompt + model from the request,
reconstruct the streamed response, and append one clean JSONL record per
conversation turn to ``detected.jsonl``.

Run with:
    .venv/bin/mitmdump -s detector/addon.py

Environment overrides:
    DETECTOR_CONFIG   path to providers.yaml (default: alongside this file)
    DETECTOR_OUTPUT   output JSONL path      (default: detected.jsonl in cwd)
"""
from __future__ import annotations

import json
import logging as _logging
import os
import sys
import tempfile

# mitmproxy loads this file as a top-level script, so the `detector` package
# isn't importable by default. Put the repo root on sys.path and import the
# sibling modules as a package.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from mitmproxy import http  # noqa: E402

from detector.config import DEFAULT_CONFIG, load_providers  # noqa: E402
from detector.extract import extract_prompt  # noqa: E402
from detector.platform_utils import open_path  # noqa: E402
from detector.sse import reconstruct_model, reconstruct_response  # noqa: E402

from dlp.engine import check_prompt  # noqa: E402
from dlp.blocked_page import render_blocked_page  # noqa: E402

_dlp_log = _logging.getLogger("dlp")
_BLOCKED_PAGE_PATH = os.path.join(tempfile.gettempdir(), "promptshield_blocked.html")


def _open_blocked_in_browser(html_body: str) -> None:
    """Write the blocked page to a temp file and open it in the user's default
    browser (WSL/macOS/Linux/Windows; see platform_utils). Fails open: any
    error is logged but never propagates to the proxy.
    """
    try:
        with open(_BLOCKED_PAGE_PATH, "w", encoding="utf-8") as f:
            f.write(html_body)
    except Exception as exc:
        _dlp_log.warning("dlp: could not write blocked page: %s", exc)
        return
    open_path(_BLOCKED_PAGE_PATH)


def _dlp_summary(dlp_result: dict):
    """Compact form for the JSONL record. Returns None when nothing fired."""
    if not dlp_result["matches"]:
        return None
    return {"action": dlp_result["action"], "matches": dlp_result["matches"]}


class LLMDetector:
    def __init__(self):
        config_path = os.environ.get("DETECTOR_CONFIG", DEFAULT_CONFIG)
        self.providers = load_providers(config_path)
        self.output_path = os.environ.get("DETECTOR_OUTPUT", "detected.jsonl")
        # Per-flow scratch keyed by id(flow); populated in request(), read in
        # response(). Flows are short-lived so this stays small.
        self._pending: dict[int, dict] = {}

    def _write_record(self, record: dict) -> None:
        with open(self.output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        path = flow.request.path
        for provider in self.providers:
            rule = provider.classify(host, path)
            if rule is None:
                continue
            prompt, model = extract_prompt(rule, flow.request.text)

            # DLP: scan the outgoing prompt. Every match (block and log_only) is
            # logged by the engine; results are carried forward into the JSONL
            # record so hits are visible in detected.jsonl.
            dlp_result = check_prompt(prompt)
            if dlp_result["blocked"]:
                # Blocked flows never reach response(), so write the record now.
                # response is None because the request never reached the provider.
                self._write_record({
                    "timestamp": flow.request.timestamp_start,
                    "provider": provider.name,
                    "model": model,
                    "prompt": prompt,
                    "response": None,
                    "dlp": _dlp_summary(dlp_result),
                })
                html_body = render_blocked_page(provider.name, dlp_result)
                _open_blocked_in_browser(html_body)
                flow.response = http.Response.make(
                    403,
                    html_body.encode("utf-8"),
                    {"Content-Type": "text/html; charset=utf-8"},
                )
                return

            self._pending[id(flow)] = {
                "timestamp": flow.request.timestamp_start,
                "provider": provider.name,
                "model": model,
                "prompt": prompt,
                "sse_handler": provider.sse_handler,
                "dlp_result": dlp_result,
            }
            return  # first matching provider wins

    def response(self, flow: http.HTTPFlow) -> None:
        info = self._pending.pop(id(flow), None)
        if info is None:
            return

        response_text = ""
        if flow.response is not None:
            # flow.response.text auto-decodes gzip/deflate transfer encodings.
            response_text = flow.response.get_text(strict=False) or ""

        # Most providers carry the model in the request (info["model"]); for the
        # rest (e.g. Gemini) it only appears in the response.
        model = info["model"] or reconstruct_model(info["sse_handler"], response_text)
        self._write_record({
            "timestamp": info["timestamp"],
            "provider": info["provider"],
            "model": model,
            "prompt": info["prompt"],
            "response": reconstruct_response(info["sse_handler"], response_text),
            "dlp": _dlp_summary(info["dlp_result"]),
        })


addons = [LLMDetector()]
