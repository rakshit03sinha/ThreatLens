"""ThreatLens Hashing and Deterministic ID Utilities."""

import hashlib
import json
import uuid
from typing import Any, Dict


def compute_sha256(content: str) -> str:
    """Compute sha256 hex digest of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def generate_event_fingerprint(
    timestamp: str,
    source_format: str,
    raw_message: str,
    extra: str = "",
) -> str:
    """Generate deterministic sha256 fingerprint for event deduplication."""
    canonical = f"{source_format}:{timestamp}:{raw_message.strip()}:{extra}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def generate_uuid() -> str:
    """Generate a random UUID4 string."""
    return str(uuid.uuid4())
