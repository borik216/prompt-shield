"""A small, defensive DLP (Data Loss Prevention) engine for the LLM proxy.

It loads detection rules from ``config.yaml`` and scans prompt text for sensitive
content. Two rule types are supported — ``regex`` and ``keywords`` — and two
actions — ``block`` and ``log_only``.

Designed to be called from the mitmproxy hook via one function::

    from dlp.engine import check_prompt
    result = check_prompt(prompt_text)
    if result["blocked"]:
        ...  # the hook decides how to block the flow

The engine is *transport-agnostic*: it never touches mitmproxy and only returns a
plain dict. It is also *defensive*: any internal error is caught and turned into a
safe "allow" result, so a bad rule or malformed input can never crash the proxy.

Environment overrides:
    DLP_CONFIG   path to config.yaml (default: alongside this file)
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from ruamel.yaml import YAML

DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), "config.yaml")

# Valid rule types and actions.
#   regex / keywords  scanned inline (see Rule.find).
#   presidio          NLP-backed PII detection via dlp/presidio_backend.py.
# FUTURE: add "local_llm" here and wire dlp/local_llm_backend.py into _scan_rule().
_TYPES = ("regex", "keywords", "presidio")
_ACTIONS = ("block", "log_only")

# Presidio entity types scanned when a presidio rule omits an explicit `entities` list.
_DEFAULT_PRESIDIO_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_BANK_NUMBER",
]

log = logging.getLogger("dlp")


@dataclass
class Rule:
    """One detection rule loaded from config.yaml."""

    name: str
    type: str                       # "regex" | "keywords" | "presidio"
    action: str                     # "block" | "log_only"
    pattern: Optional[str] = None   # for type == "regex"
    keywords: list[str] = field(default_factory=list)  # for type == "keywords"
    # type == "presidio" only:
    entities: list[str] = field(default_factory=list)  # Presidio entity types to scan
    threshold: float = 0.5                             # min confidence score
    language: str = "en"
    # Pre-compiled regex (type == "regex" only); set at load time.
    _regex: Optional[re.Pattern] = None

    def find(self, text: str) -> Optional[str]:
        """Return the matched substring if this regex/keyword rule fires, else None.

        (Presidio rules are scanned separately in ``_scan_rule`` because one scan can
        yield several matches.)
        """
        if self.type == "regex" and self._regex is not None:
            m = self._regex.search(text)
            return m.group(0) if m else None
        if self.type == "keywords":
            lowered = text.lower()
            for kw in self.keywords:
                if kw and kw.lower() in lowered:
                    return kw
        return None


def _redact(snippet: str, head: int = 4, tail: int = 4) -> str:
    """Redact the middle of a matched secret so logs never leak the full value.

    ``sk-ABCDEFGHIJKLMNOP`` -> ``sk-A…MNOP``. Short matches are masked entirely.
    """
    snippet = snippet.replace("\n", " ").strip()
    if len(snippet) <= head + tail:
        return "*" * len(snippet)
    return f"{snippet[:head]}…{snippet[-tail:]}"


def _build_rule(raw: dict) -> Optional[Rule]:
    """Validate one raw config entry into a Rule, or None if it is unusable.

    Bad rules are logged and skipped rather than raising — a single typo in the
    config must not take the whole engine (and the proxy) down.
    """
    name = raw.get("name") or "<unnamed>"
    rtype = raw.get("type")
    if rtype not in _TYPES:
        log.warning("dlp: rule %r has invalid type %r, skipping", name, rtype)
        return None

    action = raw.get("action", "log_only")
    if action not in _ACTIONS:
        log.warning(
            "dlp: rule %r has invalid action %r, defaulting to log_only", name, action
        )
        action = "log_only"

    rule = Rule(name=name, type=rtype, action=action)

    if rtype == "regex":
        pattern = raw.get("pattern")
        if not pattern:
            log.warning("dlp: regex rule %r has no 'pattern', skipping", name)
            return None
        try:
            rule._regex = re.compile(pattern)
        except re.error as exc:
            log.warning("dlp: regex rule %r failed to compile (%s), skipping", name, exc)
            return None
        rule.pattern = pattern
    elif rtype == "presidio":
        # entities optional — default to a sensible high-signal set. Bad threshold values
        # fall back to the default rather than raising (config typos must not crash).
        entities = raw.get("entities")
        rule.entities = [str(e) for e in entities] if entities else list(_DEFAULT_PRESIDIO_ENTITIES)
        try:
            rule.threshold = float(raw.get("threshold", 0.5))
        except (TypeError, ValueError):
            log.warning("dlp: presidio rule %r has bad 'threshold', using 0.5", name)
            rule.threshold = 0.5
        rule.language = str(raw.get("language", "en"))
    else:  # keywords
        keywords = raw.get("keywords") or []
        if not keywords:
            log.warning("dlp: keyword rule %r has no 'keywords', skipping", name)
            return None
        rule.keywords = [str(k) for k in keywords]

    return rule


def _scan_rule(rule: Rule, text: str) -> list[dict]:
    """Scan ``text`` with one rule and return zero or more match dicts.

    This is the single dispatch point per detection backend. regex/keywords yield at
    most one match; presidio can yield several (one per detected PII entity). Each match
    is enriched with the rule's name/type/action by the caller.

    Match dict (before enrichment): ``{"snippet": str, "entity": Optional[str]}``.
    """
    if rule.type in ("regex", "keywords"):
        found = rule.find(text)
        if found is None:
            return []
        return [{"snippet": _redact(found), "entity": None}]

    if rule.type == "presidio":
        # Imported lazily so the proxy runs without Presidio installed (fail-open).
        from dlp import presidio_backend
        hits = presidio_backend.analyze(
            text, entities=rule.entities, threshold=rule.threshold, language=rule.language,
        )
        return [{"snippet": h["snippet"], "entity": h["entity"]} for h in hits]

    # FUTURE: local_llm backend — uncomment once dlp/local_llm_backend.analyze is real.
    # if rule.type == "local_llm":
    #     from dlp import local_llm_backend
    #     hits = local_llm_backend.analyze(text, rule)
    #     return [{"snippet": h["snippet"], "entity": h["entity"]} for h in hits]

    return []


class DLPEngine:
    """Loads rules once and scans text against them."""

    def __init__(self, config_path: str = DEFAULT_CONFIG):
        self.default_action = "log_only"
        self.rules: list[Rule] = []
        self._load(config_path)

    def _load(self, config_path: str) -> None:
        try:
            yaml = YAML(typ="safe")
            with open(config_path) as f:
                data = yaml.load(f) or {}
        except Exception as exc:  # missing/malformed file — start with no rules
            log.error("dlp: could not load config %s (%s); DLP disabled", config_path, exc)
            return

        default_action = data.get("default_action", "log_only")
        if default_action in _ACTIONS:
            self.default_action = default_action

        for raw in data.get("rules") or []:
            # A rule with no explicit action inherits the engine default.
            raw.setdefault("action", self.default_action)
            rule = _build_rule(raw)
            if rule is not None:
                self.rules.append(rule)

        log.info("dlp: loaded %d rule(s) from %s", len(self.rules), config_path)

    def check(self, text: Optional[str]) -> dict:
        """Scan ``text`` and return a result dict.

        Shape::

            {
              "action": "block" | "log_only" | "allow",
              "blocked": bool,
              "matches": [
                {"rule": ..., "type": ..., "action": ..., "snippet": ...,
                 "entity": ...},   # entity is the PII type for presidio, else None
              ],
            }

        Never raises: any unexpected error yields a safe "allow" result.
        """
        result = {"action": "allow", "blocked": False, "matches": []}
        if not text:
            return result

        try:
            for rule in self.rules:
                for hit in _scan_rule(rule, text):
                    match = {
                        "rule": rule.name,
                        "type": rule.type,
                        "action": rule.action,
                        "snippet": hit["snippet"],
                    }
                    if hit.get("entity"):
                        match["entity"] = hit["entity"]
                    result["matches"].append(match)
                    log.warning(
                        "dlp: MATCH rule=%s type=%s action=%s entity=%s snippet=%s",
                        rule.name, rule.type, rule.action,
                        hit.get("entity") or "-", hit["snippet"],
                    )

            if any(m["action"] == "block" for m in result["matches"]):
                result["action"] = "block"
                result["blocked"] = True
            elif result["matches"]:
                result["action"] = "log_only"
        except Exception as exc:  # belt-and-braces: never crash the caller
            log.error("dlp: check() failed (%s); allowing by default", exc)
            return {"action": "allow", "blocked": False, "matches": []}

        return result


# Module-level singleton so the hook can just call check_prompt(text).
_engine: Optional[DLPEngine] = None


def get_engine() -> DLPEngine:
    global _engine
    if _engine is None:
        _engine = DLPEngine(os.environ.get("DLP_CONFIG", DEFAULT_CONFIG))
    return _engine


def check_prompt(prompt_text: Optional[str]) -> dict:
    """Convenience wrapper: scan a prompt with the shared engine instance."""
    try:
        return get_engine().check(prompt_text)
    except Exception as exc:  # initialisation itself failed — stay open
        log.error("dlp: engine unavailable (%s); allowing by default", exc)
        return {"action": "allow", "blocked": False, "matches": []}
