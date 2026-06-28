"""Offline replay of the captured chatgpt.json sample through the detector.

Runs without any test framework:

    .venv/bin/python tests/test_detector.py

It exercises three things end-to-end:
  1. The classifier accepts the real prompt endpoint and rejects telemetry noise.
  2. Prompt + model extraction from the request body.
  3. SSE reconstruction of the streamed assistant response.
"""
from __future__ import annotations

import glob
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
_FIXTURES = os.path.join(_HERE, "fixtures")
sys.path.insert(0, _REPO_ROOT)

from detector.config import load_providers
from detector.extract import extract_prompt
from detector.sse import (
    BLOCK_RESPONSE_HANDLERS,
    reconstruct_model,
    reconstruct_response,
    synth_block,
)

SAMPLE = os.path.join(_FIXTURES, "chatgpt.json")
CLAUDE_SAMPLE = os.path.join(_FIXTURES, "claude.json")
GEMINI_SAMPLE = os.path.join(_FIXTURES, "gemini.json")
PERPLEXITY_SAMPLE = os.path.join(_FIXTURES, "perplexity.json")
GROK_SAMPLE = os.path.join(_FIXTURES, "grok.json")


def _read_entries(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _provider(providers, name):
    return next(p for p in providers if p.name == name)


def test_replay():
    providers = load_providers()
    chatgpt = _provider(providers, "chatgpt")

    detections = []          # (rule, request_body) for classified request lines
    classified_paths = []    # paths the classifier accepted
    sse_responses = []        # reconstructed text from streamed response lines

    for entry in _read_entries(SAMPLE):
        if "request_body" in entry:  # a request line
            rule = chatgpt.classify(entry["host"], entry["path"])
            if rule is not None:
                classified_paths.append(entry["path"])
                detections.append((rule, entry["request_body"]))
        elif "response_body" in entry:  # a response line
            body = entry["response_body"]
            if body and "delta_encoding" in body:
                sse_responses.append(reconstruct_response("chatgpt", body))

    # 1. Classifier accepted exactly the real prompt endpoint, nothing else.
    assert classified_paths == ["/backend-api/f/conversation"], classified_paths

    # Negative checks: noise endpoints must NOT classify.
    for host, path in [
        ("chatgpt.com", "/ces/v1/rgstr?k=client-abc"),
        ("chatgpt.com", "/backend-api/sentinel/ping"),
        ("chatgpt.com", "/backend-api/f/conversation/prepare"),
        ("chatgpt.com", "/backend-api/conversation/init"),
        ("example.com", "/backend-api/f/conversation"),  # wrong host
    ]:
        assert chatgpt.classify(host, path) is None, f"should reject {path}"

    # 2. Prompt + model extraction.
    rule, body = detections[0]
    prompt, model = extract_prompt(rule, body)
    assert prompt == "test", repr(prompt)
    assert model == "gpt-5-5", repr(model)

    # 3. SSE reconstruction of the assistant turn.
    answer = next((r for r in sse_responses if r), "")
    assert answer.startswith("Hey."), repr(answer)
    assert "What would you like to do?" in answer, repr(answer)

    print("OK: classified", classified_paths)
    print("OK: prompt =", repr(prompt), "| model =", repr(model))
    print("OK: response =", repr(answer))


def test_claude_replay():
    providers = load_providers()
    claude = _provider(providers, "claude")

    detections = []
    classified_paths = []
    sse_responses = []

    for entry in _read_entries(CLAUDE_SAMPLE):
        if "request_body" in entry:
            rule = claude.classify(entry["host"], entry["path"])
            if rule is not None:
                classified_paths.append(entry["path"])
                detections.append((rule, entry["request_body"]))
        elif "response_body" in entry:
            body = entry["response_body"]
            if body and "content_block_delta" in body:
                sse_responses.append(reconstruct_response("claude", body))

    # 1. Classifier accepted exactly the /completion turn, nothing else.
    assert len(classified_paths) == 1, classified_paths
    assert classified_paths[0].endswith("/completion"), classified_paths

    # Negative checks: noise / wrong host must NOT classify.
    org = "/api/organizations/42760539-e47e-458e-9fb1-1a4943dad87f"
    for host, path in [
        ("claude.ai", f"{org}/chat_conversations/abc/title"),
        ("claude.ai", f"{org}/notification/channels"),
        ("claude.ai", "/cdn-cgi/challenge-platform/h/b/jsd/oneshot/x/0.1"),
        ("api.anthropic.com", "/v1/messages"),  # different host, not in scope yet
    ]:
        assert claude.classify(host, path) is None, f"should reject {path}"

    # 2. Prompt + model extraction.
    rule, body = detections[0]
    prompt, model = extract_prompt(rule, body)
    assert prompt == "test. send me a SLIGHTLY longer response!", repr(prompt)
    assert model == "claude-haiku-4-5-20251001", repr(model)

    # 3. SSE reconstruction: visible text only, thinking excluded.
    answer = next((r for r in sse_responses if r), "")
    assert answer.startswith("Hello!"), repr(answer)
    assert "What can I help you with today?" in answer, repr(answer)
    assert "The user is asking" not in answer, "thinking leaked into response"

    print("OK: classified", classified_paths)
    print("OK: prompt =", repr(prompt), "| model =", repr(model))
    print("OK: response =", repr(answer[:80]) + " ...")


def test_gemini_replay():
    providers = load_providers()
    gemini = _provider(providers, "gemini")

    detections = []
    classified_paths = []
    sse_responses = []
    sse_models = []

    for entry in _read_entries(GEMINI_SAMPLE):
        if "request_body" in entry:
            rule = gemini.classify(entry["host"], entry["path"])
            if rule is not None:
                classified_paths.append(entry["path"])
                detections.append((rule, entry["request_body"]))
        elif "response_body" in entry:
            body = entry["response_body"]
            if body and "wrb.fr" in body:
                sse_responses.append(reconstruct_response("gemini", body))
                sse_models.append(reconstruct_model("gemini", body))

    # 1. Classifier accepted exactly the StreamGenerate turn, nothing else.
    assert len(classified_paths) == 1, classified_paths
    assert "StreamGenerate" in classified_paths[0], classified_paths

    # Negative checks: the batchexecute noise and other hosts must NOT classify.
    for host, path in [
        ("gemini.google.com",
         "/_/BardChatUi/data/batchexecute?rpcids=MaZiqc&source-path=%2Fapp"),
        ("gemini.google.com", "/_/BardChatUi/web-reports?context=eJwVznl"),
        ("play.google.com", "/log?format=json&hasfast=true&authuser=0"),
        ("waa-pa.clients6.google.com",
         "/$rpc/google.internal.waa.v1.Waa/Create"),  # wrong host
    ]:
        assert gemini.classify(host, path) is None, f"should reject {path}"

    # 2. Prompt extraction (form-encoded f.req; model is not in the request).
    rule, body = detections[0]
    prompt, model = extract_prompt(rule, body)
    assert prompt == "hello gemini, test!", repr(prompt)
    assert model is None, repr(model)

    # 3. SSE reconstruction (cumulative wrb.fr stream) + model from the response.
    answer = next((r for r in sse_responses if r), "")
    assert answer == "Hello! Loud and clear. How's everything going today?", repr(answer)
    response_model = next((m for m in sse_models if m), None)
    assert response_model == "3.5 Flash", repr(response_model)

    print("OK: classified", classified_paths)
    print("OK: prompt =", repr(prompt), "| model =", repr(response_model))
    print("OK: response =", repr(answer))


def test_perplexity_replay():
    providers = load_providers()
    perplexity = _provider(providers, "perplexity")

    detections = []
    classified_paths = []
    sse_responses = []

    for entry in _read_entries(PERPLEXITY_SAMPLE):
        if "request_body" in entry:
            rule = perplexity.classify(entry["host"], entry["path"])
            if rule is not None:
                classified_paths.append(entry["path"])
                detections.append((rule, entry["request_body"]))
        elif "response_body" in entry:
            body = entry["response_body"]
            if body and "markdown_block" in body:
                sse_responses.append(reconstruct_response("perplexity", body))

    # 1. Classifier accepted exactly the perplexity_ask turn, nothing else.
    assert classified_paths == ["/rest/sse/perplexity_ask"], classified_paths

    # Negative checks: telemetry/UI noise and wrong host must NOT classify.
    for host, path in [
        ("www.perplexity.ai", "/rest/event/analytics"),
        ("www.perplexity.ai", "/rest/thread/list_pinned_ask_threads?version=2.18&source=default"),
        ("www.perplexity.ai", "/cdn-cgi/challenge-platform/h/b/jsd/oneshot/25e6c66701a0/0.4"),
        ("count.perplexity.ai", "/rest/sse/perplexity_ask"),  # wrong host
    ]:
        assert perplexity.classify(host, path) is None, f"should reject {path}"

    # 2. Prompt + model extraction (clean JSON; model is the requested tier).
    rule, body = detections[0]
    prompt, model = extract_prompt(rule, body)
    assert prompt == '"Default friendly, but shit can get number ten, Messi."', repr(prompt)
    assert model == "turbo", repr(model)

    # 3. SSE reconstruction: the consolidated markdown answer.
    answer = next((r for r in sse_responses if r), "")
    assert answer.startswith("That line is a lyric/reference to Lionel Messi"), repr(answer)
    assert "number 10 shirt" in answer, repr(answer)

    print("OK: classified", classified_paths)
    print("OK: prompt =", repr(prompt), "| model =", repr(model))
    print("OK: response =", repr(answer[:80]) + " ...")


def test_grok_replay():
    providers = load_providers()
    grok = _provider(providers, "grok")

    detections = []
    classified_paths = []
    sse_responses = []
    sse_models = []

    for entry in _read_entries(GROK_SAMPLE):
        if "request_body" in entry:
            rule = grok.classify(entry["host"], entry["path"])
            if rule is not None:
                classified_paths.append(entry["path"])
                detections.append((rule, entry["request_body"]))
        elif "response_body" in entry:
            body = entry["response_body"]
            if body and "modelResponse" in body:
                sse_responses.append(reconstruct_response("grok", body))
                sse_models.append(reconstruct_model("grok", body))

    # 1. Classifier accepted exactly the two chat turns (new + follow-up), nothing else.
    assert len(classified_paths) == 2, classified_paths
    assert classified_paths[0].endswith("/conversations/new"), classified_paths
    assert classified_paths[1].endswith("/responses"), classified_paths
    assert all("/app-chat/conversations/" in p for p in classified_paths), classified_paths

    # Negative checks: telemetry/UI noise and wrong host must NOT classify.
    for host, path in [
        ("grok.com", "/rest/suggestions/stream"),
        ("grok.com", "/monitoring?o=4508179396558848&p=4508493378158592&r=us"),
        ("grok.com", "/api/log_metric"),
        ("grok.com", "/cdn-cgi/challenge-platform/h/b/jsd/oneshot/25e6c66701a0/0.43"),
        ("api.x.ai", "/rest/app-chat/conversations/new"),  # wrong host
    ]:
        assert grok.classify(host, path) is None, f"should reject {path}"

    # 2. Prompt extraction (clean JSON `message`; model isn't in the request).
    rule, body = detections[0]
    prompt, model = extract_prompt(rule, body)
    assert prompt == "hi, this is a test.", repr(prompt)
    assert model is None, repr(model)
    prompt2, _ = extract_prompt(*detections[1])
    assert prompt2 == "give me a slightly longer response.", repr(prompt2)

    # 3. SSE reconstruction (final-tagged tokens, thinking excluded) + model from response.
    answer = next((r for r in sse_responses if r), "")
    assert answer.startswith("Hi! Test received and passed with flying colors."), repr(answer)
    assert "Thinking about your request" not in answer, "thinking leaked into response"
    response_model = next((m for m in sse_models if m), None)
    assert response_model == "grok-4-auto", repr(response_model)

    print("OK: classified", classified_paths)
    print("OK: prompt =", repr(prompt), "| model =", repr(response_model))
    print("OK: response =", repr(answer[:80]) + " ...")


def test_block_synth_roundtrip():
    """Every DLP-block synth stream must reconstruct back to the block text.

    This keeps each synth handler self-consistent with its parse_* inverse: if
    our own parser reads the message back, the synth output is a structurally
    valid stream in that provider's format (the real frontend's prerequisite).
    """
    message = "\U0001F6E1️ PromptShield blocked this prompt — detected: US_SSN."
    for handler in BLOCK_RESPONSE_HANDLERS:
        result = synth_block(handler, message)
        assert result is not None, handler
        body, content_type = result
        assert content_type in ("text/event-stream", "application/json"), (handler, content_type)
        recovered = reconstruct_response(handler, body)
        assert recovered == message, (handler, repr(recovered))
        print(f"OK: {handler} block synth round-trips ({content_type})")

    # Providers without a synth handler (e.g. the openai stub) return None so the
    # addon falls back to the browser page.
    assert synth_block("openai", message) is None


if __name__ == "__main__":
    if not glob.glob(os.path.join(_FIXTURES, "*.json")):
        print(f"No capture fixtures found in {_FIXTURES}.", file=sys.stderr)
        print(
            "Committed samples should be present after clone. To rebuild from full "
            "captures, see tests/fixtures/README.md.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("--- chatgpt ---")
    test_replay()
    print("\n--- claude ---")
    test_claude_replay()
    print("\n--- gemini ---")
    test_gemini_replay()
    print("\n--- perplexity ---")
    test_perplexity_replay()
    print("\n--- grok ---")
    test_grok_replay()
    print("\n--- block synth round-trip ---")
    test_block_synth_roundtrip()
    print("\nAll detector tests passed.")
