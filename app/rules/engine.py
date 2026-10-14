"""ThreatLens Detection Rule Evaluation Engine."""

import logging
from typing import Any, Dict, List, Optional
from app.rules.base import BaseRule, RuleMatch
from app.rules.catalogue import ALL_RULES
from app.schemas.event import NormalizedEvent

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Evaluates normalized events against active detection rules."""

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self._rules: Dict[str, BaseRule] = {r.rule_id: r for r in (rules or ALL_RULES)}
        self._enabled_status: Dict[str, bool] = {r.rule_id: True for r in self._rules.values()}

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        return self._rules.get(rule_id)

    def list_rules(self) -> List[BaseRule]:
        return list(self._rules.values())

    def set_rule_status(self, rule_id: str, enabled: bool) -> bool:
        if rule_id in self._rules:
            self._enabled_status[rule_id] = enabled
            return True
        return False

    def is_rule_enabled(self, rule_id: str) -> bool:
        return self._enabled_status.get(rule_id, True)

    def evaluate_event(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        rule_parameters: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        params_by_rule = rule_parameters or {}

        for rule_id, rule in self._rules.items():
            if not self.is_rule_enabled(rule_id):
                continue

            try:
                p = params_by_rule.get(rule_id)
                match = rule.evaluate(current_event, recent_events, parameters=p)
                if match:
                    matches.append(match)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule_id}: {str(e)}", exc_info=True)
                continue

        return matches


# Global detection engine instance
detection_engine = DetectionEngine()
