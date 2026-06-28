"""Offline smoke tests for the DLP engine (regex + keyword rules).

Runs without any test framework:

    .venv/bin/python tests/test_dlp.py

Presidio-backed rules are not asserted here — they need a spaCy model and are
tested manually when Presidio is installed. CI relies on these fast, deterministic
checks only.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _REPO_ROOT)

from dlp.engine import DLPEngine  # noqa: E402

_CONFIG = os.path.join(_REPO_ROOT, "dlp", "config.yaml")


def _engine() -> DLPEngine:
    return DLPEngine(_CONFIG)


def _rule_names(result: dict) -> set[str]:
    return {m["rule"] for m in result.get("matches", [])}


def test_clean_prompt():
    result = _engine().check("hello world")
    assert not result["blocked"], result
    assert result["action"] == "allow", result
    assert result["matches"] == [], result
    print("OK: clean prompt allowed")


def test_openai_api_key_blocked():
    result = _engine().check("use sk-FAKE123456789012345678901234 here")
    assert result["blocked"], result
    assert result["action"] == "block", result
    assert "openai_api_key" in _rule_names(result), result
    print("OK: OpenAI API key pattern blocked")


def test_aws_access_key_blocked():
    result = _engine().check("AKIAFAKE000000000001")
    assert result["blocked"], result
    assert "aws_access_key_id" in _rule_names(result), result
    print("OK: AWS access key pattern blocked")


def test_sensitive_keywords_log_only():
    result = _engine().check("my password is secret")
    assert not result["blocked"], result
    assert result["action"] == "log_only", result
    assert "sensitive_keywords" in _rule_names(result), result
    print("OK: sensitive keywords logged, not blocked")


def test_email_blocked():
    result = _engine().check("reach me at fake.user@example.com")
    assert result["blocked"], result
    assert "email_address" in _rule_names(result), result
    print("OK: email pattern blocked")


def test_empty_prompt_allowed():
    for text in ("", None):
        result = _engine().check(text)
        assert not result["blocked"], result
        assert result["matches"] == [], result
    print("OK: empty prompt allowed")


if __name__ == "__main__":
    test_clean_prompt()
    test_openai_api_key_blocked()
    test_aws_access_key_blocked()
    test_sensitive_keywords_log_only()
    test_email_blocked()
    test_empty_prompt_allowed()
    print("\nAll DLP tests passed.")