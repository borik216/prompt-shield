# PromptShield

**Catch sensitive data before it leaves your browser.** A man-in-the-middle proxy that inspects, scans, and logs your traffic to hosted LLM assistants — ChatGPT, Claude, Gemini, Perplexity, and Grok.


<p align="center">
  <video
    src="https://github.com/user-attachments/assets/6898be6d-589e-4770-a2c6-a572d1f34234"
    controls
    muted
    playsinline
    width="900">
  </video>
</p>

### *PromptShield detects an exposed API key, email address, and private key in a prompt, blocks the request before it reaches the LLM, and logs the incident in real time.*

[![CI](https://github.com/borik216/prompt-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/borik216/prompt-shield/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![mitmproxy](https://img.shields.io/badge/mitmproxy-TLS%20proxy-6E4AFF)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![htmx](https://img.shields.io/badge/htmx-3366CC?logo=htmx&logoColor=white)
![Presidio](https://img.shields.io/badge/Presidio-PII%20detection-0078D4?logo=microsoft&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

Every hosted AI assistant streams its replies in its own undocumented wire format. PromptShield sits in the middle as a TLS-terminating proxy, reverse-engineers five of those formats back into clean text, and scans every outgoing prompt for secrets and PII **before it ever leaves your machine** — so a pasted AWS key or customer record is blocked in the browser instead of landing in someone else's logs. Every captured turn flows into a live dashboard.

Built in a weekend, but not a toy: real TLS interception, real PII detection, and the same techniques enterprise DLP tooling uses for real.

## What makes this hard

**Five streaming formats, none of them documented.** Each provider ships its reply as a stream of tiny fragments in its own wire format — OpenAI/Anthropic-style Server-Sent Events, Google's chunked `wrb.fr` frames, Perplexity's block SSE, and Grok's newline-delimited JSON. ChatGPT alone uses a `delta_encoding "v1"` scheme with init deltas, explicit appends, bare shorthand fragments, *and* batched patches. There's no spec for any of it; every handler was reverse-engineered from captured traffic and has to reassemble the fragments in order, in real time, while dropping the model's hidden reasoning tokens.

**Reading the traffic at all means terminating TLS.** Prompts and responses live inside an encrypted connection — invisible from the network. PromptShield runs as a man-in-the-middle proxy with its own CA certificate installed in the system trust store, so it can decrypt the request, inspect and modify it, and re-encrypt on the way out. That's a deliberate choice, not a shortcut: it's the only vantage point that sees plaintext both ways, and it's exactly what makes blocking *outgoing* data possible — the prompt is scanned and dropped locally before it's ever forwarded to the provider.

**Blocking inside a live chat without wedging it.** A blocked prompt is the hard case. The chat UI is a single-page app waiting on a streaming response it fully expects to succeed; hand it the wrong thing and you get a spinner that never resolves or a broken composer. The clean fix is to *synthesize* a block notice into the provider's own stream format so it renders as a normal assistant turn — implemented as experimental synth handlers in [`detector/sse.py`](detector/sse.py), but not yet safe to wire into the live proxy. The current working solution sidesteps the SPA's state entirely: return a provider-neutral `403` carrying safe metadata headers, then catch it with a small overlay script injected into the page that shows a branded in-page toast (with a full-page block notice as the fallback).

## Supported providers

| Provider   | Web app             | Streaming format                | Status |
| ---------- | ------------------- | ------------------------------- | ------ |
| ChatGPT    | `chatgpt.com`       | SSE, `delta_encoding v1`        | ✅ implemented & tested |
| Claude     | `claude.ai`         | Anthropic SSE                   | ✅ implemented & tested |
| Gemini     | `gemini.google.com` | chunked `wrb.fr` frames         | ✅ implemented & tested |
| Perplexity | `www.perplexity.ai` | block SSE                       | ✅ implemented & tested |
| Grok       | `grok.com`          | newline-delimited JSON          | ✅ implemented & tested |
| OpenAI API | `api.openai.com`    | SSE                             | 🚧 scaffolded |

Each implemented provider is tested against real captured traffic, replayed offline in CI.

## How it works

Two mitmproxy addons and a web dashboard. The detector is the heart of it — for every flow it runs a five-step pipeline:

1. **Classify** the provider + endpoint from `providers.yaml`
2. **Scan** the prompt through the DLP engine (and block here if it hits)
3. **Extract** the prompt + model from the request
4. **Reconstruct** the streamed response back into plain text
5. **Record** one clean line to `detected.jsonl`:

```json
{"timestamp": 1750000000.0, "provider": "grok", "model": "grok-4-auto",
 "prompt": "hi, this is a test.", "response": "Hi! Test received...",
 "dlp": null}
```

### Detector (`detector/`)

The main addon. Classification and extraction are config-driven (`providers.yaml`); the per-provider stream reconstruction in `sse.py` is the reverse-engineering work described above. Request bodies that aren't plain JSON (e.g. Gemini's form-encoded `f.req`) go through named decoders; providers whose model name only appears in the *response* (Gemini, Grok) get a dedicated response-side extractor.

### DLP (`dlp/`)

A config-driven scan run on every outgoing prompt before it leaves. Three rule types — `regex`, `keywords`, and Presidio-backed `presidio` PII detection — each set to `block` or `log_only`. On a block, PromptShield drops the request locally (it never reaches the provider) and returns a provider-neutral `403` tagged with `X-PromptShield-*` headers; the injected overlay reads those headers and shows an in-page toast naming *what* was detected — never the matched value, which is redacted everywhere it could be logged. The engine is defensive throughout: bad rules are skipped at load, and any scan error fails *open* so the proxy never takes your traffic down with it.

<img width="358" height="184" alt="PromptShield in-page block toast" src="https://github.com/user-attachments/assets/7c03ff79-e092-43d9-9e1e-c9f867cd6466" />

Adding a rule needs no code: edit [`dlp/config.yaml`](dlp/config.yaml). Adding a new detection backend is one type entry plus one branch in the engine (there's a `local_llm` scaffold marking the spot).

### Dashboard (`dashboard/`)

A FastAPI + HTMX read-only UI over `detected.jsonl`: live table, sidebar stats, provider/action filters, and a detail modal per record.

<img width="1556" height="741" alt="PromptShield dashboard" src="https://github.com/user-attachments/assets/5caccb9b-58a6-4b43-8ae1-02734e53ff2b" />


### Recorder (`recorder/`)

A blunt NDJSON dump of all non-GET traffic. Not used in normal operation — it's the tool for studying a new provider's wire format before writing detector rules for it.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e .            # installs the `promptshield` command
.venv/bin/promptshield setup          # mint + install the CA cert, print proxy steps
.venv/bin/promptshield run            # start the detector proxy (writes detected.jsonl)
```

`promptshield setup` is the onboarding doctor: it mints the mitmproxy CA cert, best-effort installs it into your OS trust store (macOS/Linux/Windows/WSL), and prints the proxy-configuration steps for your platform. Any privileged step that can't complete falls back to clear manual instructions — and you can always install the cert from `http://mitm.it` while the proxy runs.

To capture traffic, point your browser or system proxy at mitmproxy (default `localhost:8080`). The one CLI replaces the raw `mitmdump`/`uvicorn` invocations:

```bash
promptshield run          # detector proxy → detected.jsonl
promptshield record       # raw recorder  → recorded.json
promptshield dashboard    # FastAPI dashboard
promptshield cert         # (re)mint + install the CA cert
promptshield setup        # full onboarding doctor
```

`promptshield run` passes any extra args through to `mitmdump` (e.g. `promptshield run -p 8081`). Detector environment overrides still apply: `DETECTOR_CONFIG` (path to `providers.yaml`) and `DETECTOR_OUTPUT` (output path, default `detected.jsonl`).

> Prefer the raw addons? They still work directly:
> `.venv/bin/mitmdump -s detector/addon.py` (add `pip install -r requirements.txt`
> for just the proxy; `requirements-dashboard.txt` for the dashboard).

### Dashboard

```bash
promptshield dashboard --port 8000
# → http://localhost:8000
```

By default the dashboard reads `detected.jsonl` from the repo root. Override with `PROMPTSHIELD_DETECTED=/path/to/detected.jsonl`. See [`dashboard/README.md`](dashboard/README.md) for endpoints and layout.

## Tests

```bash
.venv/bin/python tests/test_detector.py   # classifier + extractor + SSE replay
.venv/bin/python tests/test_dlp.py        # DLP regex/keyword smoke tests
```

Both run on every push via GitHub Actions. The detector tests replay sanitized, committed fixtures through the full classify → extract → reconstruct pipeline, one per provider, and pass on a fresh clone. Full recorder captures (session tokens, personal data) stay in gitignored `tests/fixtures/local/` — see [`tests/fixtures/README.md`](tests/fixtures/README.md) to regenerate samples.

## Project structure

```
cli.py                 # `promptshield` entry point (run/record/dashboard/cert/setup)
detector/              # main addon: classify → DLP → extract → reconstruct → JSONL
  providers.yaml       #   per-provider host/endpoint/prompt/model rules
  config.py            #   loads & validates the rules
  extract.py           #   dotted-path prompt/model extraction + request decoders
  sse.py               #   per-provider streamed-response reconstruction (+ block synth)
  overlay.py           #   in-page block notification: HTML injection + 403 JSON
  static/              #   promptshield_overlay.js (the injected toast overlay)
  platform_utils.py    #   WSL/macOS/Linux/Windows: open browser, install CA cert
  addon.py             #   the live mitmproxy addon
dlp/                   # config-driven prompt scanning (regex / keywords / presidio)
recorder/addon.py      # blunt NDJSON capture for studying a new provider
dashboard/             # FastAPI + HTMX UI over detected.jsonl
tests/
  test_detector.py     # offline replay harness
  test_dlp.py          # DLP smoke tests (fake secrets)
  build_fixtures.py    # rebuild committed samples from local/ captures
  fixtures/            # committed sanitized samples (+ local/ for full captures)
.github/workflows/ci.yml
```

## Roadmap

- Flesh out the OpenAI API provider; add more assistants as their traffic is captured.
- Wire the experimental in-stream block synth into the live proxy as the primary block path.
- SSE live updates in the dashboard (replace HTMX polling).

---

PromptShield is for inspecting **your own** LLM traffic on your own machine — don't point it at anyone else's. Licensed under [MIT](LICENSE).
