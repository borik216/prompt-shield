# LLM Traffic Detector

Intercept your browser's traffic to hosted LLM assistants and reconstruct each conversation
turn into a clean, structured record — **provider, model, prompt, and the fully reassembled
streamed response** — as newline-delimited JSON.

Built as a [mitmproxy](https://mitmproxy.org/) addon: provider classification is config-driven,
and the streamed-response reconstruction is a small, tested handler per provider.

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

Two mitmproxy addons:

- **Detector** (`detector/`) — the main tool. For each flow it
  1. classifies the provider + endpoint from `providers.yaml`,
  2. extracts the prompt + model from the request,
  3. reconstructs the streamed response, and
  4. appends one record to `detected.jsonl`:

  ```json
  {"timestamp": 1750000000.0, "provider": "grok", "model": "grok-4-auto",
   "prompt": "hi, this is a test.", "response": "Hi! Test received and passed..."}
  ```

- **Recorder** (`recorder/`) — a blunt NDJSON dump of all non-GET traffic, used to study a
  new provider's wire format before writing its detector rules.

Internals:

- `detector/providers.yaml` — per-provider host / endpoint / prompt / model rules.
- `detector/config.py` — loads & validates the rules into `Provider` objects.
- `detector/extract.py` — pulls the prompt/model out of the request via a tiny dotted-path
  language (e.g. `messages[-1].content.parts[0]`), with decoders for non-JSON bodies.
- `detector/sse.py` — the per-provider streamed-response reconstructors.
- `detector/addon.py` — the live mitmproxy addon wiring it together.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt      # mitmproxy (ruamel.yaml ships with it)

.venv/bin/mitmdump -s detector/addon.py        # the detector → writes detected.jsonl
# .venv/bin/mitmweb  -s detector/addon.py       # same, with the browser UI
# .venv/bin/mitmdump -s recorder/addon.py       # the raw recorder → writes recorded.json
```

Point your browser or system proxy at mitmproxy (default `localhost:8080`) and install the
mitmproxy CA certificate so HTTPS can be decrypted. **Only decrypt your own traffic.**

Detector environment overrides: `DETECTOR_CONFIG` (path to `providers.yaml`),
`DETECTOR_OUTPUT` (output path, default `detected.jsonl`).

## Tests

```bash
.venv/bin/python tests/test_detector.py
```

The harness replays real captures through the classifier, extractor, and stream reconstructor
for every provider — no test framework required. The capture fixtures are **not committed**
(they contain session tokens and personal data); generate your own with the recorder into
`tests/fixtures/` — see [`tests/fixtures/README.md`](tests/fixtures/README.md). The suite skips
cleanly with a hint when no fixtures are present.

## Project structure

```
detector/            # the main addon: classify → extract → reconstruct → JSONL
  providers.yaml     #   per-provider host/endpoint/prompt/model rules
  config.py          #   loads & validates the rules
  extract.py         #   dotted-path prompt/model extraction + request decoders
  sse.py             #   per-provider streamed-response reconstruction
  addon.py           #   the live mitmproxy addon
recorder/addon.py    # blunt NDJSON capture for studying a new provider
tests/
  test_detector.py   # offline replay harness
  fixtures/          # capture files (local-only / gitignored)
```

## Roadmap

- **Phase 2** — a Flask web UI over `detected.jsonl` to browse and search captured turns.
- Flesh out the OpenAI API provider; add more assistants as their traffic is captured.

## Disclaimer

A personal, educational project for inspecting **your own** LLM traffic. Don't use it to
intercept anyone else's.
