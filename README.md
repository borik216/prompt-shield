# PromptShield

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
  and Presidio PII rules can block (403 + branded HTML page) or log-only. Hits are
  recorded in the `dlp` field of each detection.

- **Dashboard** (`dashboard/`) — FastAPI + HTMX read-only UI over `detected.jsonl`.
  Live table, sidebar stats, provider/action filters, and a detail modal per record.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt      # mitmproxy + optional Presidio

# Run the detector (writes detected.jsonl)
.venv/bin/mitmdump -s detector/addon.py
# .venv/bin/mitmweb  -s detector/addon.py       # same, with the browser UI
# .venv/bin/mitmdump -s recorder/addon.py       # raw recorder → recorded.json
```

Point your browser or system proxy at mitmproxy (default `localhost:8080`) and install
the mitmproxy CA certificate so HTTPS can be decrypted.

Detector environment overrides: `DETECTOR_CONFIG` (path to `providers.yaml`),
`DETECTOR_OUTPUT` (output path, default `detected.jsonl`).

### Dashboard

```bash
.venv/bin/pip install -r requirements-dashboard.txt
.venv/bin/uvicorn dashboard.main:app --reload --port 8000
# → http://localhost:8000
```

By default the dashboard reads `detected.jsonl` from the repo root. Override with
`PROMPTSHIELD_DETECTED=/path/to/detected.jsonl`. See [`dashboard/README.md`](dashboard/README.md)
for endpoints and layout.

## Tests

```bash
.venv/bin/python tests/test_detector.py
```

The harness replays real captures through the classifier, extractor, and stream
reconstructor for every provider — no test framework required. The capture fixtures
are **not committed** (they contain session tokens and personal data); generate your
own with the recorder into `tests/fixtures/` — see
[`tests/fixtures/README.md`](tests/fixtures/README.md). The suite skips cleanly with
a hint when no fixtures are present.

## Project structure

```
detector/              # main addon: classify → DLP → extract → reconstruct → JSONL
  providers.yaml       #   per-provider host/endpoint/prompt/model rules
  config.py            #   loads & validates the rules
  extract.py           #   dotted-path prompt/model extraction + request decoders
  sse.py               #   per-provider streamed-response reconstruction
  addon.py             #   the live mitmproxy addon
dlp/                   # config-driven prompt scanning (regex / keywords / presidio)
recorder/addon.py      # blunt NDJSON capture for studying a new provider
dashboard/             # FastAPI + HTMX UI over detected.jsonl
tests/
  test_detector.py     # offline replay harness
  fixtures/            # capture files (local-only / gitignored)
```

## Roadmap

- Flesh out the OpenAI API provider; add more assistants as their traffic is captured.
- Sanitized public fixtures so the test harness passes on a fresh clone.
- SSE live updates in the dashboard (replace HTMX polling).