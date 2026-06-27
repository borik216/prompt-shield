"""mitmproxy addon: classify live flows by AI provider, extract the prompt +
model from the request, reconstruct the streamed response, and append one clean
JSONL record per conversation turn to ``detected.jsonl``.

Run with:
    .venv/bin/mitmdump -s detector/addon.py

Environment overrides:
    DETECTOR_CONFIG   path to providers.yaml (default: alongside this file)
    DETECTOR_OUTPUT   output JSONL path      (default: detected.jsonl in cwd)
"""
from __future__ import annotations

import json
import os
import sys

# mitmproxy loads this file as a top-level script, so the `detector` package
# isn't importable by default. Put the repo root on sys.path and import the
# sibling modules as a package.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from mitmproxy import http  # noqa: E402

from detector.config import DEFAULT_CONFIG, load_providers  # noqa: E402
from detector.extract import extract_prompt  # noqa: E402
from detector.sse import reconstruct_model, reconstruct_response  # noqa: E402


class LLMDetector:
    def __init__(self):
        config_path = os.environ.get("DETECTOR_CONFIG", DEFAULT_CONFIG)
        self.providers = load_providers(config_path)
        self.output_path = os.environ.get("DETECTOR_OUTPUT", "detected.jsonl")
        # Per-flow scratch keyed by id(flow); populated in request(), read in
        # response(). Flows are short-lived so this stays small.
        self._pending: dict[int, dict] = {}

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        path = flow.request.path
        for provider in self.providers:
            rule = provider.classify(host, path)
            if rule is None:
                continue
            prompt, model = extract_prompt(rule, flow.request.text)
            self._pending[id(flow)] = {
                "timestamp": flow.request.timestamp_start,
                "provider": provider.name,
                "model": model,
                "prompt": prompt,
                "sse_handler": provider.sse_handler,
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
        record = {
            "timestamp": info["timestamp"],
            "provider": info["provider"],
            "model": model,
            "prompt": info["prompt"],
            "response": reconstruct_response(info["sse_handler"], response_text),
        }
        with open(self.output_path, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


addons = [LLMDetector()]
