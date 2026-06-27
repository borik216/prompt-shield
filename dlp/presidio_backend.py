"""Presidio detection backend for the DLP engine.

This module wraps Microsoft Presidio (``presidio-analyzer`` + ``presidio-anonymizer``)
behind a single ``analyze(text, ...)`` function. Presidio brings NLP-backed PII
detection (names, phone numbers, credit cards, IBANs, …) that plain regex/keyword
rules can't reach.

Two design goals, both matching the rest of the DLP layer:

1. **Lazy.** Presidio pulls in spaCy and a language model — heavy to import and slow to
   build. We only construct the engines on first use, so a config with no ``presidio``
   rule never pays the cost.
2. **Fail-open.** If Presidio (or its spaCy model) isn't installed, or the analyzer
   raises, we log *once* and return ``[]`` forever after. A missing dependency must
   never crash the proxy — it just means "no presidio matches".

Environment overrides:
    DLP_PRESIDIO_MODEL   spaCy model name (default: en_core_web_lg)
"""
from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger("dlp")

# spaCy model Presidio's NLP engine loads. Large model = better accuracy; override to
# en_core_web_sm for a lighter install.
_MODEL = os.environ.get("DLP_PRESIDIO_MODEL", "en_core_web_lg")

# Lazily-built singletons. `_unavailable` latches True the first time setup fails so we
# don't retry (and re-log) on every prompt.
_analyzer = None        # presidio_analyzer.AnalyzerEngine
_anonymizer = None      # presidio_anonymizer.AnonymizerEngine
_unavailable = False
_logged_unavailable = False


def _mark_unavailable(reason: str) -> None:
    """Latch the backend off and log the reason exactly once."""
    global _unavailable, _logged_unavailable
    _unavailable = True
    if not _logged_unavailable:
        log.warning(
            "dlp: presidio unavailable (%s); presidio rules will be skipped. "
            "Install with `pip install presidio-analyzer presidio-anonymizer` and "
            "`python -m spacy download %s`.",
            reason, _MODEL,
        )
        _logged_unavailable = True


def _ensure_engines() -> bool:
    """Build the analyzer/anonymizer on first use. Return True if usable.

    Any import or model-load failure flips the backend to a permanent no-op rather than
    propagating — Presidio being absent is an expected, non-fatal condition here.
    """
    global _analyzer, _anonymizer

    if _unavailable:
        return False
    if _analyzer is not None and _anonymizer is not None:
        return True

    try:
        # Imported lazily so the proxy runs fine without Presidio installed.
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine
    except Exception as exc:  # ImportError, or transitive dependency issues
        _mark_unavailable(f"import failed: {exc}")
        return False

    try:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": _MODEL}],
        })
        nlp_engine = provider.create_engine()   # raises if the spaCy model isn't present
        _analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        _anonymizer = AnonymizerEngine()
    except Exception as exc:  # model not downloaded, or engine construction failed
        _mark_unavailable(f"engine init failed: {exc}")
        return False

    log.info("dlp: presidio backend ready (model=%s)", _MODEL)
    return True


def _redact(text: str, results) -> dict:
    """Map each detected span to a placeholder like ``<EMAIL_ADDRESS>``.

    Uses presidio-anonymizer so the *raw* PII never reaches a log line or detected.jsonl.
    Returns ``{entity_type: redacted_snippet}``. Falls back to a generic ``<entity_type>``
    string if the anonymizer itself errors.
    """
    redacted: dict[str, str] = {}
    for r in results:
        try:
            from presidio_anonymizer.entities import OperatorConfig
            anonymized = _anonymizer.anonymize(
                text=text,
                analyzer_results=[r],
                operators={"DEFAULT": OperatorConfig("replace",
                                                     {"new_value": f"<{r.entity_type}>"})},
            )
            redacted[r.entity_type] = anonymized.text.strip()
        except Exception:
            redacted[r.entity_type] = f"<{r.entity_type}>"
    return redacted


def analyze(
    text: str,
    entities: Optional[list[str]] = None,
    threshold: float = 0.5,
    language: str = "en",
) -> list[dict]:
    """Scan ``text`` for PII and return one match dict per detected entity.

    Shape::

        [{"entity": "US_SSN", "snippet": "<US_SSN>"}, ...]

    ``entities`` limits detection to those Presidio entity types (None = all built-in
    recognizers). Results below ``threshold`` confidence are dropped. Never raises:
    if Presidio is unavailable or analysis fails, returns ``[]``.
    """
    if not text or not _ensure_engines():
        return []

    try:
        results = _analyzer.analyze(
            text=text,
            entities=entities or None,
            language=language,
            score_threshold=threshold,
        )
    except Exception as exc:
        log.error("dlp: presidio analyze() failed (%s); skipping", exc)
        return []

    if not results:
        return []

    # One snippet per entity *type* (anonymizer collapses repeats); emit a match per
    # detected result so multiple SSNs etc. are all counted.
    redacted = _redact(text, results)
    return [
        {"entity": r.entity_type, "snippet": redacted.get(r.entity_type, f"<{r.entity_type}>")}
        for r in results
    ]
