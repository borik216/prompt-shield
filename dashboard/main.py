"""FastAPI app serving the PromptShield dashboard.

A thin HTTP layer over :mod:`dashboard.data`: it reads ``detected.jsonl`` on every
request (cheap for an MVP; the file is small and append-only) and renders Jinja2
templates. The frontend uses HTMX to poll two fragment endpoints every few seconds,
so the table and stats stay live without a full page reload or any JavaScript build.

Run::

    .venv/bin/uvicorn dashboard.main:app --reload --port 8000

Endpoints
    GET /                  full dashboard shell (navbar + sidebar + table)
    GET /fragments/table   table rows fragment   (polled by HTMX, honours filters)
    GET /fragments/stats   sidebar stats fragment (polled by HTMX)
    GET /detail/{idx}      detail modal for one record
    GET /api/detections    raw JSON (debugging + documents the schema)

Future extension seams (deliberately isolated so they're drop-in later):
  * Live updates: replace the HTMX polling on /fragments/* with Server-Sent Events
    — add a `GET /stream` returning `text/event-stream` and have the data layer
    notify on file append. Nothing in data.py changes.
  * Storage: swap the JSONL reader in dashboard/data.py for SQLite. The routes and
    templates here are storage-agnostic and need no changes.
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from dashboard import data

app = FastAPI(title="PromptShield Dashboard")

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)

# Providers offered in the filter dropdown (from detector/providers.yaml). The
# actual filter matches on the record's `provider` string, so unknown providers
# still show up in the table — this list just seeds the <select>.
PROVIDERS = ["chatgpt", "claude", "gemini", "perplexity", "grok", "openai_api"]


def _filtered_views(provider: Optional[str], action: Optional[str]):
    """Read, filter and shape records for the table fragment.

    The view's ``idx`` is the position in the *unfiltered* newest-first list so it
    stays a stable key for ``/detail/{idx}`` regardless of the active filters.
    """
    records = data.read_records()
    indexed = list(enumerate(records))  # remember each record's stable index
    keep = data.filter_records(records, provider=provider, action=action)
    keep_ids = {id(r) for r in keep}
    return [data.record_view(rec, idx) for idx, rec in indexed if id(rec) in keep_ids]


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """The dashboard shell. Table + stats are filled in by the first HTMX poll."""
    return templates.TemplateResponse(
        request,
        "index.html",
        {"providers": PROVIDERS, "action_labels": data.ACTION_LABELS},
    )


# --------------------------------------------------------------------------- #
# HTMX fragments (polled)
# --------------------------------------------------------------------------- #
@app.get("/fragments/table", response_class=HTMLResponse)
def fragment_table(
    request: Request,
    provider: Optional[str] = None,
    action: Optional[str] = None,
):
    """Table rows for the current filters. Polled by HTMX every few seconds."""
    rows = _filtered_views(provider, action)
    return templates.TemplateResponse(request, "_table.html", {"rows": rows})


@app.get("/fragments/stats", response_class=HTMLResponse)
def fragment_stats(request: Request):
    """Sidebar stat cards. Computed over all records (not the active filter)."""
    stats = data.compute_stats(data.read_records())
    return templates.TemplateResponse(request, "_stats.html", {"stats": stats})


# --------------------------------------------------------------------------- #
# Detail modal
# --------------------------------------------------------------------------- #
@app.get("/detail/{idx}", response_class=HTMLResponse)
def detail(request: Request, idx: int):
    """Full prompt/response + DLP matches for one record, rendered as a modal."""
    records = data.read_records()
    if not 0 <= idx < len(records):
        # Record scrolled off or index is stale — return an empty modal target.
        return HTMLResponse("")
    return templates.TemplateResponse(
        request, "_detail.html", {"rec": data.detail_view(records[idx])}
    )


# --------------------------------------------------------------------------- #
# JSON API (debugging / extension point)
# --------------------------------------------------------------------------- #
@app.get("/api/detections")
def api_detections(provider: Optional[str] = None, action: Optional[str] = None):
    """Raw detections as JSON (newest first), honouring the same filters.

    Handy for debugging and as a stable contract for future clients (e.g. an SSE
    consumer or an external SIEM export).
    """
    records = data.read_records()
    records = data.filter_records(records, provider=provider, action=action)
    return JSONResponse(records)
