"""ThreatLens Log Parser Registry."""

from typing import Dict, List, Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.parsers.windows import WindowsEventParser
from app.parsers.linux import LinuxAuthParser
from app.parsers.syslog import GenericSyslogParser
from app.parsers.cisco import CiscoDeviceParser
from app.parsers.paloalto import PaloAltoParser
from app.parsers.aws_cloudtrail import AWSCloudTrailParser
from app.parsers.azure_activity import AzureActivityParser
from app.parsers.ndjson import NDJSONParser
from app.parsers.cef import CEFParser
from app.parsers.leef import LEEFParser
from app.parsers.apache import ApacheAccessParser
from app.parsers.nginx import NginxAccessParser


class ParserRegistry:
    """Registry maintaining all 12 supported log parsers with auto-detection."""

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        # Priority order for auto-detection: structured formats first, then specialized text, then generic
        self._detection_order: List[BaseParser] = []
        self._register_default_parsers()

    def _register_default_parsers(self):
        parsers = [
            # High specificity JSON formats
            AWSCloudTrailParser(),
            AzureActivityParser(),
            WindowsEventParser(),
            # High specificity text formats
            CEFParser(),
            LEEFParser(),
            CiscoDeviceParser(),
            PaloAltoParser(),
            # Web servers
            ApacheAccessParser(),
            NginxAccessParser(),
            # Linux auth/system
            LinuxAuthParser(),
            # Generic syslog
            GenericSyslogParser(),
            # Fallback JSON
            NDJSONParser(),
        ]
        for p in parsers:
            self.register(p)

    def register(self, parser: BaseParser):
        self._parsers[parser.format_id.lower()] = parser
        if parser not in self._detection_order:
            self._detection_order.append(parser)

    def get_parser(self, format_id: str) -> Optional[BaseParser]:
        return self._parsers.get(format_id.lower())

    def list_formats(self) -> List[Dict[str, str]]:
        return [
            {
                "format_id": p.format_id,
                "name": p.format_name,
                "description": p.description,
            }
            for p in self._parsers.values()
        ]

    def parse_log(self, raw_log: str, format_hint: Optional[str] = None) -> ParseResult:
        """Parse a log line using explicit format hint or auto-detection."""
        trimmed = raw_log.strip()
        if not trimmed:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message="Empty log payload")],
                raw_preview="",
            )

        # 1. Use explicit hint if provided
        if format_hint and format_hint.lower() in self._parsers:
            parser = self._parsers[format_hint.lower()]
            return parser.parse(trimmed)

        # 2. Auto-detection pass
        for parser in self._detection_order:
            try:
                if parser.can_parse(trimmed):
                    res = parser.parse(trimmed)
                    if res.success:
                        return res
            except Exception:
                continue

        # 3. If no parser matched, return failure diagnostic
        return ParseResult(
            success=False,
            diagnostics=[
                ParseDiagnostic(
                    level="error",
                    message="Could not auto-detect format. Specify an explicit format from supported formats.",
                )
            ],
            raw_preview=trimmed[:200],
        )


# Global singleton instance
parser_registry = ParserRegistry()
