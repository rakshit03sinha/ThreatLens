"""ThreatLens Log Redaction and Sanitization."""

import re
from typing import Any, Dict, List, Union

REDACTION_PATTERNS = [
    # Passwords in query params / logs: password=xyz, pass=xyz, pwd=xyz
    (re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|auth_token|bearer)\s*[:=]\s*['\"]?([^\s'\",;&]+)['\"]?"), r"\1=[REDACTED]"),
    # Bearer tokens
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"), "Bearer [REDACTED]"),
    # Basic Authorization
    (re.compile(r"(?i)basic\s+[a-zA-Z0-9+/=]{15,}"), "Basic [REDACTED]"),
    # Credit Card Numbers (13-16 digits)
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[CARD-REDACTED]"),
    # Private Keys
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"), "[PRIVATE-KEY-REDACTED]"),
]


def redact_sensitive_text(text: str) -> str:
    """Mask known sensitive patterns from text logs."""
    if not text:
        return ""
    redacted = text
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_sensitive_dict(data: Union[Dict[str, Any], List[Any], Any]) -> Any:
    """Recursively mask sensitive keys in nested dictionaries or lists."""
    sensitive_keys = {"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "authorization"}
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if str(k).lower() in sensitive_keys:
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_sensitive_dict(v)
        return cleaned
    elif isinstance(data, list):
        return [redact_sensitive_dict(item) for item in data]
    elif isinstance(data, str):
        return redact_sensitive_text(data)
    return data
