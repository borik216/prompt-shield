"""Reading, shaping, and summarising ``detected.jsonl`` for the dashboard.

This module is the *only* place that knows how detections are stored. It is pure
Python (no FastAPI), so it's easy to unit-test and easy to swap out later: to move
from the flat JSONL file to SQLite, reimplement :func:`read_records` and nothing
in ``main.py`` or the templates needs to change.

The detector writes one JSON object per line (NDJSON). A record looks like::

    {"timestamp": 1782560321.14, "provider": "gemini", "model": "3.5 Flash",
     "prompt": "...", "response": "... or null when blocked",
     "dlp": null | {"action": "block"|"log_only", "matches": [
         {"rule": "email_address", "type": "regex", "action": "block",
          "snippet": "test….com", "entity": "EMAIL_ADDRESS"}  # entity: presidio only
     ]}}

Defensive throughout (matching the DLP engine's ethos): a missing file yields an
empty list and a single malformed line is skipped rather than breaking the page.

Environment overrides:
    PROMPTSHIELD_DETECTED   path to detected.jsonl (default: repo-root file)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Optional

log = logging.getLogger("promptshield.dashboard")

# detected.jsonl lives at the repo root (one level up from dashboard/).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTED_PATH = os.environ.get(
    "PROMPTSHIELD_DETECTED", os.path.join(_REPO_ROOT, "detected.jsonl")
)

# Derived action labels — the single vocabulary used by the table, the filters,
# and the stats. Keep these three keys in sync with the UI and ACTION_LABELS.
ACTION_BLOCKED = "blocked"
ACTION_FLAGGED = "flagged"
ACTION_ALLOWED = "allowed"

ACTION_LABELS = {
    ACTION_BLOCKED: "Blocked",
    ACTION_FLAGGED: "Flagged",
    ACTION_ALLOWED: "Allowed",
}

PROMPT_SNIPPET_LEN = 90


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #
def read_records(path: str = DETECTED_PATH) -> list[dict[str, Any]]:
    """Return every detection in ``path``, newest first.

    Reads line-by-line with ``json.loads`` (never ``json.load`` the whole file —
    it's NDJSON). Blank lines are skipped; a line that fails to parse is logged
    and skipped so one bad write can't take down the dashboard. A missing file is
    treated as "no detections yet" and returns ``[]``.
    """
    records: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    log.warning("skipping malformed line %d in %s", lineno, path)
    except FileNotFoundError:
        return []
    except OSError as exc:  # permissions, etc. — degrade gracefully
        log.warning("could not read %s: %s", path, exc)
        return []

    records.reverse()  # file is append-only (oldest first) → show newest first
    return records


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
def derive_action(rec: dict[str, Any]) -> str:
    """Map a record's ``dlp`` field to one of the three derived action labels.

    Single source of truth, reused by the table, filters and stats:
      * ``dlp.action == "block"``      → ``blocked``
      * ``dlp`` present but log-only   → ``flagged``
      * ``dlp`` absent / null / empty  → ``allowed``
    """
    dlp = rec.get("dlp")
    if not dlp:
        return ACTION_ALLOWED
    if dlp.get("action") == "block":
        return ACTION_BLOCKED
    return ACTION_FLAGGED


def _rule_names(rec: dict[str, Any]) -> list[str]:
    """Distinct rule names that fired for this record (order-preserving)."""
    dlp = rec.get("dlp") or {}
    names: list[str] = []
    for match in dlp.get("matches", []) or []:
        name = match.get("rule")
        if name and name not in names:
            names.append(name)
    return names


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #
def filter_records(
    records: list[dict[str, Any]],
    provider: Optional[str] = None,
    action: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Narrow records by provider and/or derived action.

    Empty string / ``None`` / ``"all"`` mean "no filter" for either dimension.
    """
    def _wanted(value: Optional[str]) -> Optional[str]:
        if not value or value == "all":
            return None
        return value

    provider = _wanted(provider)
    action = _wanted(action)

    out = records
    if provider is not None:
        out = [r for r in out if r.get("provider") == provider]
    if action is not None:
        out = [r for r in out if derive_action(r) == action]
    return out


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #
def compute_stats(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summary numbers for the sidebar, computed over the *unfiltered* records.

    Returns ``total``, ``blocks_today`` (blocked records whose timestamp falls on
    the local current date), ``top_provider`` (most common provider name), plus
    the raw ``by_provider`` / ``by_action`` counts for any future widgets.
    """
    today = datetime.now().date()
    by_provider: dict[str, int] = {}
    by_action: dict[str, int] = {}
    blocks_today = 0

    for rec in records:
        provider = rec.get("provider") or "unknown"
        by_provider[provider] = by_provider.get(provider, 0) + 1

        action = derive_action(rec)
        by_action[action] = by_action.get(action, 0) + 1

        if action == ACTION_BLOCKED and _on_date(rec.get("timestamp"), today):
            blocks_today += 1

    top_provider = max(by_provider, key=by_provider.get) if by_provider else None

    return {
        "total": len(records),
        "blocks_today": blocks_today,
        "top_provider": top_provider,
        "by_provider": by_provider,
        "by_action": by_action,
    }


def _on_date(timestamp: Any, day) -> bool:
    """True if a unix ``timestamp`` falls on the given local ``day``."""
    try:
        return datetime.fromtimestamp(float(timestamp)).date() == day
    except (TypeError, ValueError, OSError):
        return False


# --------------------------------------------------------------------------- #
# View shaping
# --------------------------------------------------------------------------- #
def record_view(rec: dict[str, Any], idx: int) -> dict[str, Any]:
    """Flatten a raw record into the fields the templates render.

    ``idx`` is the record's position in the newest-first list and doubles as the
    key the detail modal is fetched by (``/detail/{idx}``).
    """
    action = derive_action(rec)
    prompt = rec.get("prompt") or ""
    return {
        "idx": idx,
        "timestamp": _format_ts(rec.get("timestamp")),
        "provider": rec.get("provider") or "unknown",
        "model": rec.get("model") or "—",
        "action": action,
        "action_label": ACTION_LABELS[action],
        "rules": _rule_names(rec),
        "snippet": _truncate(prompt, PROMPT_SNIPPET_LEN),
    }


def detail_view(rec: dict[str, Any]) -> dict[str, Any]:
    """Full record shaped for the detail modal (full prompt/response + matches)."""
    dlp = rec.get("dlp") or {}
    action = derive_action(rec)
    return {
        "timestamp": _format_ts(rec.get("timestamp")),
        "provider": rec.get("provider") or "unknown",
        "model": rec.get("model") or "—",
        "action": action,
        "action_label": ACTION_LABELS[action],
        "prompt": rec.get("prompt") or "",
        "response": rec.get("response"),  # None when blocked
        "dlp_action": dlp.get("action"),
        "matches": dlp.get("matches", []) or [],
    }


def _format_ts(timestamp: Any) -> str:
    """Render a unix timestamp as a readable local time, or '—' if unusable."""
    try:
        return datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "—"


def _truncate(text: str, length: int) -> str:
    text = " ".join(text.split())  # collapse whitespace/newlines for the snippet
    return text if len(text) <= length else text[: length - 1].rstrip() + "…"
