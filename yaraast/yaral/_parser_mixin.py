"""Shared type contract for cooperating YARA-L parser mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._token_stream import TokenStreamMixin


class YaraLParserMixinBase(TokenStreamMixin):
    """Declare methods supplied by the complete YARA-L parser."""

    if TYPE_CHECKING:

        def _parse_events_section(self) -> Any: ...

        def _parse_match_section(self) -> Any: ...

        def _parse_condition_section(self) -> Any: ...

        def _parse_outcome_section(self) -> Any: ...

        def _parse_outcome_expression(self) -> Any: ...

        def _parse_outcome_arithmetic_expression(self) -> Any: ...

        def _parse_function_call_args(self, function_name: str) -> Any: ...
