"""ThreatLens IOC Intelligence Store and Matching Service."""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.ioc import IOC, IOCMatch
from app.schemas.event import NormalizedEvent

HASH_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
HASH_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")


INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_ip(ip_str: str) -> bool:
    """Return True if an IP is in RFC 1918 / loopback / link-local private space."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def normalize_indicator(value: str, ind_type: str) -> str:
    """Normalize indicators for canonical matching."""
    val = value.strip()
    if ind_type in ["domain", "url"]:
        val = val.lower()
        # strip protocol if present in domain
        if ind_type == "domain":
            val = re.sub(r"^https?://", "", val).split("/")[0].split(":")[0]
    elif ind_type in ["sha256", "md5", "sha1"]:
        val = val.lower()
    return val


class IOCService:
    """Service for managing IOCs and matching events against intelligence."""

    async def get_ioc_by_value(self, session: AsyncSession, value: str) -> Optional[IOC]:
        result = await session.execute(select(IOC).where(IOC.indicator_value == value.strip().lower()))
        return result.scalars().first()

    async def add_or_update_ioc(
        self,
        session: AsyncSession,
        indicator_value: str,
        indicator_type: str,
        severity: str = "medium",
        confidence: int = 80,
        source: str = "ThreatLens",
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> IOC:
        norm_val = normalize_indicator(indicator_value, indicator_type)
        ioc = await self.get_ioc_by_value(session, norm_val)
        now = datetime.now(timezone.utc)

        if ioc:
            ioc.severity = severity
            ioc.confidence = confidence
            ioc.source = source
            ioc.description = description or ioc.description
            ioc.tags = list(set((ioc.tags or []) + (tags or [])))
            ioc.last_seen = now
        else:
            ioc = IOC(
                indicator_value=norm_val,
                indicator_type=indicator_type,
                severity=severity,
                confidence=confidence,
                source=source,
                description=description,
                tags=tags or [],
                first_seen=now,
                last_seen=now,
            )
            session.add(ioc)
        await session.flush()
        return ioc

    async def match_event(
        self,
        session: AsyncSession,
        event: NormalizedEvent,
        event_db_id: str,
    ) -> List[IOCMatch]:
        """Scan normalized event and raw message for active IOC indicators."""
        matches: List[IOCMatch] = []
        candidates: List[Tuple[str, str, str]] = []  # (field_name, value, type)

        # Check IP fields (do not treat purely private IPs as malicious unless explicitly defined)
        if event.source_ip and not is_private_ip(event.source_ip):
            candidates.append(("source_ip", event.source_ip.strip(), "ipv4"))
        if event.destination_ip and not is_private_ip(event.destination_ip):
            candidates.append(("destination_ip", event.destination_ip.strip(), "ipv4"))

        # Check domain in hostname or parsed fields
        if event.hostname and "." in event.hostname:
            candidates.append(("hostname", event.hostname.strip().lower(), "domain"))

        # Extract file hashes and domains from raw message or parsed fields
        raw = event.raw_message
        for sha in HASH_SHA256_PATTERN.findall(raw):
            candidates.append(("raw_message", sha.lower(), "sha256"))
        for md5 in HASH_MD5_PATTERN.findall(raw):
            candidates.append(("raw_message", md5.lower(), "md5"))

        # Check parsed fields
        fields = event.parsed_fields or {}
        for k in ["domain", "query_name", "dhost", "shost"]:
            if k in fields and isinstance(fields[k], str) and "." in fields[k]:
                candidates.append((k, fields[k].strip().lower(), "domain"))
        for k in ["file_hash", "hash", "sha256", "md5"]:
            if k in fields and isinstance(fields[k], str):
                candidates.append((k, fields[k].strip().lower(), "sha256" if len(fields[k]) == 64 else "md5"))

        if not candidates:
            return matches

        # Query DB for candidate indicator values
        distinct_vals = list({c[1] for c in candidates})
        stmt = select(IOC).where(IOC.indicator_value.in_(distinct_vals))
        res = await session.execute(stmt)
        active_iocs = {ioc.indicator_value: ioc for ioc in res.scalars().all()}

        for field_name, val, ind_type in candidates:
            if val in active_iocs:
                ioc = active_iocs[val]
                match = IOCMatch(
                    ioc_id=ioc.id,
                    event_id=event_db_id,
                    matched_field=field_name,
                    matched_value=val,
                    match_context={
                        "indicator_type": ioc.indicator_type,
                        "ioc_severity": ioc.severity,
                        "ioc_confidence": ioc.confidence,
                        "source": ioc.source,
                    },
                )
                session.add(match)
                matches.append(match)
                # Annotate event parsed fields
                event.parsed_fields["matched_ioc_type"] = ioc.indicator_type
                event.parsed_fields["matched_ioc_value"] = val

        if matches:
            await session.flush()
        return matches


# Global IOC service instance
ioc_service = IOCService()
