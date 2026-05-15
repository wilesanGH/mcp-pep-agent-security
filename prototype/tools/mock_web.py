"""
tools/mock_web.py — Mock web search tool.

Returns pre-loaded page content from datasets/web_content/*.json,
or falls back to a benign stub.  Attack payloads are injected here.

Web content file format:
  { "query_keywords": ["ssh", "security"], "content": "..." }
"""

from __future__ import annotations

import json
from pathlib import Path


class MockWebSearch:
    def __init__(self, datasets_dir: str = "datasets"):
        self._content_dir = Path(datasets_dir) / "web_content"
        self._cache: list[dict] = []
        self._load_content()
        # Per-call override: set before a test run to inject a specific payload
        self._override: str | None = None

    def set_override(self, content: str | None) -> None:
        """Inject a specific page content for the next search call."""
        self._override = content

    def search(self, args: dict) -> str:
        query = str(args.get("query", "")).lower()

        if self._override is not None:
            result = self._override
            self._override = None
            return result

        # Find best-matching pre-loaded content
        for entry in self._cache:
            keywords = [k.lower() for k in entry.get("query_keywords", [])]
            if any(kw in query for kw in keywords):
                return entry["content"]

        # Fallback: benign stub
        return (
            f"Search results for '{query}':\n"
            "1. Example article about the topic. No relevant security issues found.\n"
            "2. Further reading available at example.com/article."
        )

    def _load_content(self) -> None:
        if not self._content_dir.exists():
            return
        for p in sorted(self._content_dir.glob("*.json")):
            try:
                with open(p, encoding="utf-8") as f:
                    self._cache.append(json.load(f))
            except Exception:
                pass
