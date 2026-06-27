"""Scaffold for a future ``local_llm`` detection backend — NOT YET IMPLEMENTED.

The idea: instead of (or alongside) regex / keyword / presidio rules, ask a locally-hosted
LLM "does this prompt contain sensitive data of kind X?" and treat its verdict like any
other rule hit. Running the model *locally* keeps the prompt being inspected from leaving
the machine — important when the whole point is data-loss prevention.

This file exists so wiring a real implementation later is a one-function change:

  1. Add ``"local_llm"`` to ``_TYPES`` in ``engine.py``.
  2. Give the local model rule its config fields (endpoint, model name, the classification
     instruction / categories, threshold) — parsed in ``engine._build_rule``.
  3. Fill in ``analyze()`` below.
  4. Uncomment the ``local_llm`` branch in ``engine._scan_rule`` (the single dispatch point).

Until then ``analyze()`` returns ``[]`` so the type is inert even if someone enables it.

Match dict contract (same shape the other backends return, so the engine treats hits
uniformly)::

    [{"entity": "<category>", "snippet": "<redacted>"}, ...]
"""
from __future__ import annotations

import logging

log = logging.getLogger("dlp")

_logged_stub = False


def analyze(text: str, rule) -> list[dict]:
    """Placeholder. Always returns no matches until a real backend is implemented.

    Args:
        text: the prompt text to classify.
        rule: the ``Rule`` instance (will carry endpoint/model/categories once defined).

    Returns:
        Always ``[]`` for now.
    """
    global _logged_stub
    if not _logged_stub:
        log.info("dlp: local_llm backend is a scaffold (no-op); see local_llm_backend.py")
        _logged_stub = True

    # TODO: implement local-LLM classification, e.g.
    #   1. Build a prompt asking the model to classify `text` against rule.categories.
    #   2. POST to the local inference server (rule.endpoint, e.g. Ollama / llama.cpp).
    #   3. Parse the verdict; for each flagged category with confidence >= rule.threshold,
    #      append {"entity": category, "snippet": "<redacted>"}.
    #   4. Wrap everything in try/except and return [] on any failure (fail-open).
    return []
