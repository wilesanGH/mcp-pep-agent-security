"""
pep/ds_detector.py — Content-based DS:SENSITIVE detection.

Scans strings (or all string values in a dict) for PII, credentials,
local paths, JWTs, etc.  Returns DS.SENSITIVE on first match.
"""

from __future__ import annotations

import re
from datatypes import DS

REDACT_PLACEHOLDER = "<REDACTED:DS:SENSITIVE>"

# Each entry: (label, compiled_regex)
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("api_key",
     # sk- keys: allow hyphens and underscores (real keys use sk-proj-xxxx format).
     # Min 8 chars after sk- to catch short test keys while avoiding false positives on
     # ordinary hyphenated words.
     re.compile(r"(sk-[a-zA-Z0-9_\-]{8,}|Bearer\s+[A-Za-z0-9\-._~+/]+=*)", re.I)),

    ("rsa_key",
     re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE KEY-----")),

    ("local_path",
     re.compile(r"(/home/|/Users/|C:\\Users\\|~/\.ssh/|/etc/passwd|/etc/shadow|/root/)")),

    ("jwt",
     re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+")),

    ("password_field",
     re.compile(r"(password|passwd|pwd|secret)\s*[=:]\s*\S+", re.I)),

    ("credit_card",
     re.compile(r"\b(?:\d[ \-]?){13,16}\b")),

    ("pii_ssn",
     re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


class DSDetector:
    """
    Detects whether content contains sensitive data.

    detect(content)  → DS.SENSITIVE | DS.NORMAL
    redact(args)     → copy of args dict with sensitive values replaced
    """

    def detect(self, content: str | dict | None) -> str:
        """
        Return DS.SENSITIVE if any pattern matches; else DS.NORMAL.
        Accepts a plain string or a dict (all string values are scanned).
        """
        if content is None:
            return DS.NORMAL
        texts = self._extract_strings(content)
        for text in texts:
            for _label, pattern in _PATTERNS:
                if pattern.search(text):
                    return DS.SENSITIVE
        return DS.NORMAL

    def detect_with_reason(self, content: str | dict | None) -> tuple[str, str]:
        """
        Like detect(), but also returns the name of the first matched pattern.
        Returns (DS.NORMAL, "") if nothing matched.
        """
        if content is None:
            return DS.NORMAL, ""
        texts = self._extract_strings(content)
        for text in texts:
            for label, pattern in _PATTERNS:
                if pattern.search(text):
                    return DS.SENSITIVE, label
        return DS.NORMAL, ""

    def redact(self, args: dict) -> dict:
        """
        Return a copy of args with any string value that matches a pattern
        replaced by REDACT_PLACEHOLDER.  Used for args_redacted in AuditEvent.
        """
        result = {}
        for k, v in args.items():
            if isinstance(v, str) and self.detect(v) == DS.SENSITIVE:
                result[k] = REDACT_PLACEHOLDER
            elif isinstance(v, dict):
                result[k] = self.redact(v)
            else:
                result[k] = v
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_strings(content: str | dict) -> list[str]:
        if isinstance(content, str):
            return [content]
        if isinstance(content, dict):
            out = []
            for v in content.values():
                if isinstance(v, str):
                    out.append(v)
                elif isinstance(v, dict):
                    out.extend(DSDetector._extract_strings(v))
            return out
        return []
