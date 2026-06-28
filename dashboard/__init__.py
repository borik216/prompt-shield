"""PromptShield web dashboard — a read-only view over ``detected.jsonl``.

See ``dashboard/main.py`` for the FastAPI app and ``dashboard/data.py`` for the
file parsing / stats helpers. Run with::

    .venv/bin/uvicorn dashboard.main:app --reload --port 8000
"""
