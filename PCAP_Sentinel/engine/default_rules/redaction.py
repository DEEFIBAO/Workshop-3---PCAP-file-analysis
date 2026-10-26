"""Provided helpers that keep secrets out of findings, logs and the dashboard."""
from __future__ import annotations

import re
from typing import Optional

SENSITIVE_NAMES = ("pass", "pwd", "secret", "token", "apikey", "api_key", "auth", "session", "cookie", "credential")
_FORM_SECRET = re.compile(r"(?i)\b([a-z0-9_.\-]*(?:pass|pwd|secret|token|api_?key|credential)[a-z0-9_.\-]*)=([^&\s;\"']*)")
_AUTH_HEADER = re.compile(r"(?i)\b(authorization|cookie|set-cookie|proxy-authorization)\s*:\s*[^\r\n]*")
_FTP_PASS = re.compile(r"(?im)^(\s*PASS)\s+\S.*$")
_JSON_SECRET = re.compile(r"(?i)(\"[a-z0-9_]*(?:pass|pwd|secret|token|api_?key)[a-z0-9_]*\"\s*:\s*)\"[^\"]*\"")


def is_sensitive_name(name: Optional[str]) -> bool:
    lowered = (name or "").lower()
    return any(marker in lowered for marker in SENSITIVE_NAMES)


def redact_text(text: Optional[str]) -> str:
    """Mask passwords, tokens, cookies and Authorization values inside free text."""
    if not text:
        return text or ""
    text = _FORM_SECRET.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}: [REDACTED]", text)
    text = _FTP_PASS.sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    return _JSON_SECRET.sub(lambda m: f'{m.group(1)}"[REDACTED]"', text)


def safe_excerpt(text: str, limit: int = 80) -> str:
    """Short, printable, redacted excerpt suitable for evidence strings."""
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text[:limit * 2])
    cleaned = redact_text(cleaned)
    return cleaned if len(cleaned) <= limit else cleaned[:limit - 1] + "…"
