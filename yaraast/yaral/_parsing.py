"""Parsing routines for YARA-L rules."""

from __future__ import annotations

from ._parsing_conditions import YaraLConditionParsingMixin
from ._parsing_events import YaraLEventsParsingMixin
from ._parsing_match import YaraLMatchParsingMixin
from ._parsing_outcome import YaraLOutcomeParsingMixin
from ._parsing_rules import YaraLRuleParsingMixin


class YaraLParsingMixin(
    YaraLRuleParsingMixin,
    YaraLEventsParsingMixin,
    YaraLMatchParsingMixin,
    YaraLConditionParsingMixin,
    YaraLOutcomeParsingMixin,
):
    """Mixin providing YARA-L parse routines."""
