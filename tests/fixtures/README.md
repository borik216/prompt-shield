# Test fixtures

The offline test harness (`tests/test_detector.py`) replays real recorder captures from this
directory — one NDJSON file per provider: `chatgpt.json`, `claude.json`, `gemini.json`,
`perplexity.json`, `grok.json`.

These capture files are **gitignored and not committed**: they contain real session tokens
(authorization headers, cookies, and CSRF tokens echoed in request bodies) and personal
conversation content. Only this README is tracked.

## Generating your own

1. Run the recorder against your browser traffic (point your browser/system proxy at mitmproxy
   and install its CA cert first):
   ```bash
   .venv/bin/mitmdump -s recorder/addon.py     # writes ./recorded.json
   ```
2. Have a short conversation with the provider you want to capture.
3. Save the resulting `recorded.json` here as `<provider>.json` (e.g. `claude.json`).
4. Run the tests:
   ```bash
   .venv/bin/python tests/test_detector.py
   ```

The harness skips cleanly with a hint if no `*.json` fixtures are present.
