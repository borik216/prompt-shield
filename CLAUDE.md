# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**PromptShield** (`github.com/borik216/prompt-shield`) — a mitmproxy-based tool that
detects hosted LLM traffic, scans outgoing prompts with DLP, and records clean
JSONL per conversation turn. The local checkout directory may still be named
`llm-traffic-detector`; the product name is PromptShield everywhere in docs and UI.

## Project state

Three main components are implemented:

- **Recorder** (`recorder/addon.py`) — blunt capture of all non-GET POST traffic to `recorded.json` as NDJSON; useful for capturing raw traffic to study a new provider.
- **Detector** (`detector/addon.py`) — the main addon. Classifies flows by AI provider, extracts the user prompt + model from the request, reconstructs the streamed (SSE) response, and writes one clean JSONL record per conversation turn to `detected.jsonl`.
- **DLP** (`dlp/`) — a config-driven Data Loss Prevention layer the detector calls on every outgoing prompt. Scans for sensitive content (`regex`, `keywords`, and NLP-backed `presidio` PII detection) and either logs the hit or blocks the request (returning a branded HTML page). Hits are recorded in the `dlp` field of each `detected.jsonl` record.
- **Dashboard** (`dashboard/`) — FastAPI + HTMX read-only UI over `detected.jsonl`. Live table, stats, filters, detail modal. Run with `uvicorn dashboard.main:app` (see `requirements-dashboard.txt`).

ChatGPT, Claude, Gemini, Perplexity, and Grok are fully implemented and tested against real captures (kept in `tests/fixtures/`, gitignored — see *Data files*). OpenAI API is scaffolded (config entry + SSE handler stub) and ready to fill once its traffic is captured.

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

# Run the offline test harnesses (no test framework required)
.venv/bin/python tests/test_detector.py
.venv/bin/python tests/test_dlp.py

# Run the dashboard (reads detected.jsonl from repo root)
.venv/bin/pip install -r requirements-dashboard.txt
.venv/bin/uvicorn dashboard.main:app --reload --port 8000
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

### DLP (`dlp/`)
A defensive, config-driven scan run on every prompt before it leaves. The detector calls `check_prompt(prompt)` in `request()`; a `blocked` result short-circuits the flow with a 403.

- **`config.yaml`** — `default_action` plus a list of `rules`. Each rule has a `type` (`regex` | `keywords` | `presidio`) and an `action` (`block` | `log_only`). regex rules carry a `pattern`, keyword rules a `keywords` list, presidio rules an optional `entities` list + `threshold`.
- **`engine.py`** — loads rules once (`DLPEngine`, singleton via `get_engine()`). `check(text)` dispatches each rule through `_scan_rule()` and returns `{"action", "blocked", "matches": [...]}`. **Defensive throughout**: bad rules are skipped at load with a warning; any scan error fails *open* (returns "allow") so the proxy never crashes. `_redact()` masks matched secrets so raw values never hit logs.
- **`presidio_backend.py`** — lazy, fail-open wrapper over Microsoft Presidio (`presidio-analyzer` + `presidio-anonymizer`). Built only when a `presidio` rule exists; if Presidio or its spaCy model isn't installed it logs once and returns no matches. Detected PII is redacted to `<ENTITY>` placeholders by the anonymizer. Model name overridable via `DLP_PRESIDIO_MODEL` (default `en_core_web_lg`).
- **`blocked_page.py` / `blocked_page.html`** — render the dark-theme "Request Blocked" HTML page returned on a block (names the provider + detected data type). NB: chat apps fetch over XHR, so the page renders on direct navigation / in tools, not inside the chat UI.
- **`local_llm_backend.py`** — scaffold only (no-op `analyze()`); the reserved extension point for a future `local_llm` rule type. The single place to wire it in is the commented branch in `engine._scan_rule()`.

To add a rule, edit `dlp/config.yaml` (no code needed for regex/keywords/presidio). To add a new *detection backend*, add the type to `_TYPES`, parse its fields in `_build_rule`, and add a branch in `_scan_rule` (see the `local_llm` scaffold). Each `detected.jsonl` record gains a `dlp` field: `null` when clean, else `{"action", "matches": [{"rule", "type", "action", "snippet", "entity"?}]}`.

### Data files
- **`tests/fixtures/*.json`** — committed, sanitized minimal samples replayed by the offline test harness. Full recorder captures go in **`tests/fixtures/local/*.json`** (gitignored; session tokens and personal data). Rebuild committed samples with `tests/build_fixtures.py` — see `tests/fixtures/README.md`. Request and response are separate lines in recorder output (recorder limitation); the live detector has the full `HTTPFlow` so they're always paired.
- **`detected.jsonl`** — clean detector output, one record per conversation turn (gitignored).
- **`recorded.json`** — raw recorder output, untracked (empty until the recorder addon runs).

When parsing NDJSON files, always read line-by-line with `json.loads(line)` — never `json.load` the whole file.

### Tests
`tests/test_detector.py` replays the committed fixtures through the classifier, extractor, and stream reconstructor — one `test_*_replay()` per provider. `tests/test_dlp.py` smoke-tests regex/keyword DLP rules with fake secrets (no Presidio required in CI). Both run via `.github/workflows/ci.yml` on push/PR.

For ChatGPT, for example:
- Classifier accepts `/backend-api/f/conversation`, rejects all noise paths.
- Extracts `prompt="test"`, `model="gpt-5-5"`.
- SSE reconstruction yields `"Hey. Looks like your test came through—I can see your message. What would you like to do?"`.

Missing fixtures exit 1 (CI must fail loudly). Committed samples should always be present after clone.

### Adding a new provider
1. Capture raw traffic with the recorder; save it into `tests/fixtures/local/` (gitignored).
2. Add a `providers.yaml` entry (`hosts`, `ignore_paths`, `endpoints`, `prompt_path`, `model_path`, `sse_handler`).
3. Implement a handler function in `sse.py` and register it in `HANDLERS`. (If the model only appears in the response, also add a `RESPONSE_MODEL_HANDLERS` extractor; if the request body isn't plain JSON, add a `REQUEST_HANDLERS` decoder in `extract.py`.)
4. Add a `test_*_replay()` and a `*_SAMPLE` path (under `tests/fixtures/`) to `tests/test_detector.py`.
