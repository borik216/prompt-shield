# PromptShield Dashboard

A read-only web dashboard over the detector's `detected.jsonl`. Dark, security-tool
styling; live table + stats; click a row for the full prompt, response, and DLP
matches.

**Stack:** FastAPI · HTMX · Tailwind (Play CDN) — no Node build, no database.
Live updates are done with HTMX polling every 2.5s.

## Run

```bash
# 1. Install the dashboard's deps into the existing venv
.venv/bin/pip install -r requirements-dashboard.txt

# 2. Start the server (run from the repo root so `dashboard` is importable)
.venv/bin/uvicorn dashboard.main:app --reload --port 8000

# 3. Open it
#    http://localhost:8000
```

By default it reads `detected.jsonl` from the repo root. Point it elsewhere with:

```bash
PROMPTSHIELD_DETECTED=/path/to/detected.jsonl \
  .venv/bin/uvicorn dashboard.main:app --port 8000
```

## What you get

- **Table** (newest first): Timestamp · Provider (badge) · Model · Action
  (`Blocked` / `Flagged` / `Allowed`, colour-coded) · Rule(s) · Prompt snippet.
- **Sidebar stats:** total detections, blocks today, most common provider.
- **Filters:** by provider and by action (applied live, including on each poll).
- **Detail modal:** full prompt + response + every DLP match (rule, type, entity,
  action, redacted snippet). Click a row to open; click the backdrop or ✕ to close.
- **Empty / loading states** for a fresh clone with no detections yet.

## Endpoints

| Method & path          | Purpose                                            |
|------------------------|----------------------------------------------------|
| `GET /`                | Dashboard shell (navbar + sidebar + table)         |
| `GET /fragments/table` | Table rows (HTMX-polled; honours `provider`/`action`) |
| `GET /fragments/stats` | Sidebar stat cards (HTMX-polled)                   |
| `GET /detail/{idx}`    | Detail modal for one record                        |
| `GET /api/detections`  | Raw JSON, newest first (debugging / integrations)  |

## Layout

```
dashboard/
├── main.py            FastAPI app: routes + fragment/JSON endpoints
├── data.py            JSONL reader, action classification, filtering, stats
└── templates/
    ├── index.html     full page shell (Tailwind + HTMX wiring)
    ├── _table.html    polled table-rows fragment
    ├── _stats.html    polled stats fragment
    └── _detail.html   detail modal body
```

## Extending later

The code is structured so the two obvious next steps are drop-in:

- **Server-Sent Events instead of polling** — add a `GET /stream`
  (`text/event-stream`) endpoint and have the data layer notify on file append.
  The fragment endpoints and templates don't change.
- **SQLite instead of the flat file** — reimplement `read_records()` (and friends)
  in `dashboard/data.py`. `main.py` and the templates are storage-agnostic, so
  nothing else needs touching.

> **Note:** Tailwind's Play CDN is great for an MVP but isn't meant for production
> traffic — compile a stylesheet with the Tailwind CLI before any public deployment.
