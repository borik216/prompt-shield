# PromptShield

![CI](https://github.com/borik216/prompt-shield/actions/workflows/ci.yml/badge.svg)

Intercept your browser's traffic to hosted LLM assistants, scan outgoing prompts
for sensitive data, and reconstruct each conversation turn into a clean, structured
record — **provider, model, prompt, and the fully reassembled streamed response**.

Built as a [mitmproxy](https://mitmproxy.org/) addon with a config-driven DLP layer
and a read-only web dashboard over `detected.jsonl`.

> Personal, educational project for inspecting **your own** LLM traffic. Don't use
> it to intercept anyone else's.

## What it does

1. **Detect** — classifies traffic by AI provider and endpoint, extracts the prompt
   and model from the request, and reconstructs the streamed assistant reply
2. **Protect** — DLP scans every outgoing prompt (regex, keywords, Presidio PII)
   and blocks or logs hits before they reach the provider
3. **Record** — appends one JSONL line per conversation turn to `detected.jsonl`
4. **Browse** — live dashboard to filter, search, and inspect detections

## Supported providers

| Provider   | Web app             | Status |
| ---------- | ------------------- | ------ |
| ChatGPT    | `chatgpt.com`       | ✅ implemented & tested |
| Claude     | `claude.ai`         | ✅ implemented & tested |
| Gemini     | `gemini.google.com` | ✅ implemented & tested |
| Perplexity | `www.perplexity.ai` | ✅ implemented & tested |
| Grok       | `grok.com`          | ✅ implemented & tested |
| OpenAI API | `api.openai.com`    | 🚧 scaffolded |

Every provider streams its answer differently — OpenAI/Anthropic SSE, Google's chunked
`wrb.fr` frames, Perplexity's block SSE, Grok's newline-delimited JSON — and each is
reconstructed back to plain text, with hidden reasoning excluded.

## How it works

Two mitmproxy addons and a web dashboard:

- **Detector** (`detector/`) — the main addon. For each flow it
  1. classifies the provider + endpoint from `providers.yaml`,
  2. scans the prompt through the DLP engine,
  3. extracts the prompt + model from the request,
  4. reconstructs the streamed response, and
  5. appends one record to `detected.jsonl`:

  ```json
  {"timestamp": 1750000000.0, "provider": "grok", "model": "grok-4-auto",
   "prompt": "hi, this is a test.", "response": "Hi! Test received...",
   "dlp": null}
  ```

- **Recorder** (`recorder/`) — a blunt NDJSON dump of all non-GET traffic, used to
  study a new provider's wire format before writing detector rules.

- **DLP** (`dlp/`) — config-driven scan on every outgoing prompt. Regex, keyword,
  and Presidio PII rules can block or log-only. On a block PromptShield answers
  the request *in the chat itself* — a synthesized assistant turn in the
  provider's own wire format naming what was detected — so the user sees why
  right where they typed (providers without a synth handler fall back to a
  branded HTML page opened in the default browser). Hits are recorded in the
  `dlp` field of each detection.

- **Dashboard** (`dashboard/`) — FastAPI + HTMX read-only UI over `detected.jsonl`.
  Live table, sidebar stats, provider/action filters, and a detail modal per record.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e .            # installs the `promptshield` command
.venv/bin/promptshield setup          # mint + install the CA cert, print proxy steps
.venv/bin/promptshield run            # start the detector proxy (writes detected.jsonl)
```

`promptshield setup` is the onboarding doctor: it mints the mitmproxy CA cert,
best-effort installs it into your OS trust store (macOS/Linux/Windows/WSL), and
prints the proxy-configuration steps for your platform. Any privileged step that
can't complete falls back to clear manual instructions — and you can always
install the cert from `http://mitm.it` while the proxy runs.

The one CLI replaces the raw `mitmdump`/`uvicorn` invocations:

```bash
promptshield run          # detector proxy → detected.jsonl
promptshield record       # raw recorder  → recorded.json
promptshield dashboard    # FastAPI dashboard
promptshield cert         # (re)mint + install the CA cert
promptshield setup        # full onboarding doctor
```

`promptshield run` passes any extra args through to `mitmdump` (e.g.
`promptshield run -p 8081`). Detector environment overrides still apply:
`DETECTOR_CONFIG` (path to `providers.yaml`), `DETECTOR_OUTPUT` (output path,
default `detected.jsonl`).

> Prefer the raw addons? They still work directly:
> `.venv/bin/mitmdump -s detector/addon.py` (add `pip install -r requirements.txt`
> for just the proxy; `requirements-dashboard.txt` for the dashboard).

### Dashboard

```bash
promptshield dashboard --port 8000
# → http://localhost:8000
```

By default the dashboard reads `detected.jsonl` from the repo root. Override with
`PROMPTSHIELD_DETECTED=/path/to/detected.jsonl`. See [`dashboard/README.md`](dashboard/README.md)
for endpoints and layout.

## Tests

```bash
.venv/bin/python tests/test_detector.py   # classifier + extractor + SSE replay
.venv/bin/python tests/test_dlp.py        # DLP regex/keyword smoke tests
```

Both run on every push via GitHub Actions. Sanitized minimal fixtures are committed
under `tests/fixtures/` and pass on a fresh clone. Full recorder captures (session
tokens, personal data) stay in gitignored `tests/fixtures/local/` — see
[`tests/fixtures/README.md`](tests/fixtures/README.md) to regenerate samples.

## Project structure

```
cli.py                 # `promptshield` entry point (run/record/dashboard/cert/setup)
detector/              # main addon: classify → DLP → extract → reconstruct → JSONL
  providers.yaml       #   per-provider host/endpoint/prompt/model rules
  config.py            #   loads & validates the rules
  extract.py           #   dotted-path prompt/model extraction + request decoders
  sse.py               #   per-provider streamed-response reconstruction (+ block synth)
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
- SSE live updates in the dashboard (replace HTMX polling).