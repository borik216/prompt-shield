# Test fixtures

The offline harness replays **committed, sanitized samples** from this directory —
one minimal NDJSON file per provider: `chatgpt.json`, `claude.json`, `gemini.json`,
`perplexity.json`, `grok.json`.

These are trimmed to the handful of request/response lines each test exercises, with
UUIDs, user IDs, and emails replaced by obviously-fake placeholders. They are safe
to commit and run on a fresh clone.

Full recorder captures (session tokens, personal data) go in **`local/`** and are
gitignored:

```
tests/fixtures/local/chatgpt.json   # not committed
tests/fixtures/chatgpt.json         # committed minimal sample
```

## Running tests

```bash
.venv/bin/python tests/test_detector.py
.venv/bin/python tests/test_dlp.py
```

## Regenerating committed samples

After updating a full capture in `local/`:

```bash
.venv/bin/python tests/build_fixtures.py
```

The script keeps only the essential lines, redacts identifiers, and overwrites the
committed `*.json` files in this directory.

## Generating full local captures

1. Run the recorder against your browser traffic (point your browser/system proxy at
   mitmproxy and install its CA cert first):
   ```bash
   .venv/bin/mitmdump -s recorder/addon.py     # writes ./recorded.json
   ```
2. Have a short conversation with the provider you want to capture.
3. Save the resulting `recorded.json` as `local/<provider>.json` (e.g. `local/claude.json`).
4. Rebuild committed samples (above) and run the tests.