# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

Two mitmproxy addons are implemented:

- **Recorder** (`recorder/addon.py`) — blunt capture of all non-GET POST traffic to `recorded.json` as NDJSON; useful for capturing raw traffic to study a new provider.
- **Detector** (`detector/addon.py`) — the main addon. Classifies flows by AI provider, extracts the user prompt + model from the request, reconstructs the streamed (SSE) response, and writes one clean JSONL record per conversation turn to `detected.jsonl`.

ChatGPT, Claude, Gemini, Perplexity, and Grok are fully implemented and tested against real captures (kept in `tests/fixtures/`, gitignored — see *Data files*). OpenAI API is scaffolded (config entry + SSE handler stub) and ready to fill once its traffic is captured.

Flask is installed in the `.venv` but no web UI exists yet — planned future work over `detected.jsonl`.

## Setup & commands

The repo ships a `.venv` (gitignored). Use it directly rather than the system interpreter (there is no `python` on PATH, only `python3` and the venv binaries).

```bash
# Install deps (requirements.txt lists mitmproxy; ruamel.yaml is bundled with it — no extra dep)
.venv/bin/pip install -r requirements.txt

# Run the detector (primary addon) — writes detected.jsonl
.venv/bin/mitmdump -s detector/addon.py

# Run the raw recorder instead — writes recorded.json
.venv/bin/mitmdump -s recorder/addon.py
# (use .venv/bin/mitmweb for the browser UI, .venv/bin/mitmproxy for the TUI)

# Run the offline test harness (no test framework required)
.venv/bin/python tests/test_detector.py
```

To capture browser traffic, point the browser/system proxy at mitmproxy (default `localhost:8080`) and install the mitmproxy CA cert so HTTPS can be decrypted.

## Architecture

### Recorder (`recorder/addon.py`)
A mitmproxy addon (`LLMRecorder`) that appends every non-GET flow as **NDJSON** to `recorded.json`. Request and response are written as **separate lines** (no correlation id) — useful for studying a new provider's traffic but not for clean structured output.

### Detector (`detector/`)
The primary addon. Classification and extraction is config-driven; SSE reconstruction is per-provider code.

- **`providers.yaml`** — one entry per provider: `hosts`, `ignore_paths` (telemetry noise substrings), `endpoints` (path match rules), `prompt_path`/`model_path` (dotted-path into the request JSON), and `sse_handler` (registry key).
- **`config.py`** — loads `providers.yaml` via `ruamel.yaml` (bundled with mitmproxy). `Provider.classify(host, path)` returns the matching `EndpointRule` or `None`.
- **`extract.py`** — `resolve_path(obj, "messages[-1].content.parts[0]")` walks dicts/lists with negative-index support; `extract_prompt(rule, body_text)` returns `(prompt, model)`. Request bodies that aren't plain JSON use a named decoder from `REQUEST_HANDLERS` (e.g. Gemini's form-encoded `f.req`).
- **`sse.py`** — per-provider stream-reconstruction registry (`HANDLERS`). `parse_chatgpt_sse` reconstructs ChatGPT's `delta_encoding "v1"` stream (init delta, explicit appends, bare `{"v":...}` shorthand, `patch` batches); Claude (Anthropic SSE), Gemini (chunked `wrb.fr`), Perplexity (block SSE), and Grok (newline-delimited JSON) are implemented too, all excluding hidden reasoning. Providers whose model only appears in the response (Gemini, Grok) also register a `RESPONSE_MODEL_HANDLERS` extractor. Only OpenAI is a stub.
- **`addon.py`** — live addon: tags flows in `request()`, reconstructs + writes a clean record in `response()`:
  ```json
  {"timestamp": ..., "provider": "chatgpt", "model": "gpt-5-5", "prompt": "hello!", "response": "Hey! ..."}
  ```

### Data files
- **`tests/fixtures/*.json`** — real recorder captures (ChatGPT, Claude, Gemini, Perplexity, Grok) replayed by the offline test harness. **Gitignored / local-only**: they contain session tokens and personal data, so they're never committed — regenerate your own with the recorder (see `tests/fixtures/README.md`). Request and response are separate lines (recorder limitation); the live detector has the full `HTTPFlow` so they're always paired.
- **`detected.jsonl`** — clean detector output, one record per conversation turn (gitignored).
- **`recorded.json`** — raw recorder output, untracked (empty until the recorder addon runs).

When parsing NDJSON files, always read line-by-line with `json.loads(line)` — never `json.load` the whole file.

### Tests
`tests/test_detector.py` is a plain-`assert` script (no test framework) that replays the captures in `tests/fixtures/` through the classifier, extractor, and stream reconstructor — one `test_*_replay()` per provider. For ChatGPT, for example:
- Classifier accepts `/backend-api/f/conversation`, rejects all noise paths.
- Extracts `prompt="test"`, `model="gpt-5-5"`.
- SSE reconstruction yields `"Hey. Looks like your test came through—I can see your message. What would you like to do?"`.

If the fixtures are absent (e.g. a fresh clone) the harness prints a hint and exits 0.

### Adding a new provider
1. Capture raw traffic with the recorder; save it into `tests/fixtures/` (gitignored).
2. Add a `providers.yaml` entry (`hosts`, `ignore_paths`, `endpoints`, `prompt_path`, `model_path`, `sse_handler`).
3. Implement a handler function in `sse.py` and register it in `HANDLERS`. (If the model only appears in the response, also add a `RESPONSE_MODEL_HANDLERS` extractor; if the request body isn't plain JSON, add a `REQUEST_HANDLERS` decoder in `extract.py`.)
4. Add a `test_*_replay()` and a `*_SAMPLE` path (under `tests/fixtures/`) to `tests/test_detector.py`.
