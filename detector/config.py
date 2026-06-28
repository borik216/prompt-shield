"""Load and validate providers.yaml into Provider objects.

YAML is parsed with ruamel.yaml, which ships as a mitmproxy dependency (so no
extra package is required in this environment).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from ruamel.yaml import YAML

DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), "providers.yaml")

# Valid `match` strategies for an endpoint path rule.
_MATCHERS = ("exact", "prefix", "contains")


@dataclass
class EndpointRule:
    """How to match one request path and where to find the prompt/model in it."""

    path: str
    match: str = "exact"
    prompt_path: Optional[str] = None
    model_path: Optional[str] = None
    # Optional named decoder (see detector/extract.py REQUEST_HANDLERS) for
    # request bodies that aren't plain JSON; when set it supersedes the
    # prompt_path/model_path dotted-path extraction.
    request_handler: Optional[str] = None

    def matches(self, path: str) -> bool:
        if self.match == "exact":
            # Compare against the path without any query string.
            return path.split("?", 1)[0] == self.path
        if self.match == "prefix":
            return path.startswith(self.path)
        if self.match == "contains":
            return self.path in path
        return False


@dataclass
class Provider:
    name: str
    hosts: list[str]
    endpoints: list[EndpointRule]
    ignore_paths: list[str] = field(default_factory=list)
    response: str = "sse"
    sse_handler: Optional[str] = None

    def classify(self, host: str, path: str) -> Optional[EndpointRule]:
        """Return the matching endpoint rule, or None if this flow is not a
        prompt turn for this provider (host mismatch, noise, or no match)."""
        if host not in self.hosts:
            return None
        if any(token in path for token in self.ignore_paths):
            return None
        for rule in self.endpoints:
            if rule.matches(path):
                return rule
        return None


def _build_provider(raw: dict) -> Provider:
    name = raw.get("name")
    if not name:
        raise ValueError("provider entry is missing 'name'")
    hosts = raw.get("hosts")
    if not hosts:
        raise ValueError(f"provider '{name}' is missing 'hosts'")
    raw_endpoints = raw.get("endpoints") or []
    if not raw_endpoints:
        raise ValueError(f"provider '{name}' has no 'endpoints'")

    endpoints = []
    for ep in raw_endpoints:
        if "path" not in ep:
            raise ValueError(f"provider '{name}' has an endpoint missing 'path'")
        match = ep.get("match", "exact")
        if match not in _MATCHERS:
            raise ValueError(
                f"provider '{name}' endpoint '{ep['path']}' has invalid match "
                f"'{match}' (expected one of {_MATCHERS})"
            )
        # For `contains`, an explicit `contains:` key overrides `path` as the
        # token to search for (lets `path` stay human-readable in the config).
        token = ep.get("contains", ep["path"]) if match == "contains" else ep["path"]
        endpoints.append(
            EndpointRule(
                path=token,
                match=match,
                prompt_path=ep.get("prompt_path"),
                model_path=ep.get("model_path"),
                request_handler=ep.get("request_handler"),
            )
        )

    return Provider(
        name=name,
        hosts=list(hosts),
        endpoints=endpoints,
        ignore_paths=list(raw.get("ignore_paths") or []),
        response=raw.get("response", "sse"),
        sse_handler=raw.get("sse_handler"),
    )


def load_providers(path: str = DEFAULT_CONFIG) -> list[Provider]:
    yaml = YAML(typ="safe")
    with open(path) as f:
        data = yaml.load(f)
    if not data or "providers" not in data:
        raise ValueError(f"{path} has no top-level 'providers' key")
    return [_build_provider(raw) for raw in data["providers"]]


@dataclass
class OverlayConfig:
    """Settings for the in-page DLP block notification (see detector/overlay.py).

    enabled    -- inject the overlay + return a JSON block response (vs. the old
                  HTML-page-in-a-new-tab fallback).
    strip_csp  -- drop Content-Security-Policy headers on injected pages so the
                  inline overlay can execute (provider CSPs block inline scripts).
    inject_hosts -- hosts to inject into; empty means "all configured provider
                  hosts" (the addon fills the default from the loaded providers).
    """

    enabled: bool = True
    strip_csp: bool = True
    inject_hosts: set[str] = field(default_factory=set)


def load_overlay_config(path: str = DEFAULT_CONFIG) -> OverlayConfig:
    """Read the optional top-level ``overlay:`` mapping from providers.yaml.

    Missing/blank config yields sensible defaults (enabled, strip_csp, inject
    into all provider hosts). Kept defensive: a malformed section logs and falls
    back to defaults rather than breaking proxy startup.
    """
    yaml = YAML(typ="safe")
    try:
        with open(path) as f:
            data = yaml.load(f) or {}
        raw = data.get("overlay") or {}
        return OverlayConfig(
            enabled=bool(raw.get("enabled", True)),
            strip_csp=bool(raw.get("strip_csp", True)),
            inject_hosts=set(raw.get("inject_hosts") or []),
        )
    except Exception:
        return OverlayConfig()
