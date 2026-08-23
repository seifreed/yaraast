"""Resource limits for parsing untrusted YARA-family source."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Event
from time import monotonic
from typing import Any

from yaraast.ast.base import ASTNode
from yaraast.errors import ParseCancelledError, ResourceLimitError

LIBYARA_HEX_JUMP_MAX = (1 << 31) - 1


@dataclass(frozen=True)
class ResourceLimits:
    """Optional hard limits applied to one parse operation."""

    max_input_bytes: int | None = None
    max_tokens: int | None = None
    max_nesting_depth: int | None = None
    max_rules: int | None = None
    max_strings_per_rule: int | None = None
    max_regex_length: int | None = None
    max_hex_pattern_length: int | None = None
    max_include_depth: int | None = None
    parse_deadline: float | None = None

    def __post_init__(self) -> None:
        integer_fields = (
            "max_input_bytes",
            "max_tokens",
            "max_nesting_depth",
            "max_rules",
            "max_strings_per_rule",
            "max_regex_length",
            "max_hex_pattern_length",
            "max_include_depth",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise TypeError(f"{name} must be an integer or None")
            if value is not None and value < 0:
                raise ValueError(f"{name} must be non-negative")
        deadline = self.parse_deadline
        if deadline is not None and (
            isinstance(deadline, bool) or not isinstance(deadline, int | float)
        ):
            raise TypeError("parse_deadline must be a number or None")
        if deadline is not None and deadline <= 0:
            raise ValueError("parse_deadline must be positive")


DEFAULT_RESOURCE_LIMITS = ResourceLimits(
    max_input_bytes=32 * 1024 * 1024,
    max_tokens=1_000_000,
    max_nesting_depth=256,
    max_rules=25_000,
    max_strings_per_rule=10_000,
    max_regex_length=1024 * 1024,
    max_hex_pattern_length=4 * 1024 * 1024,
    max_include_depth=32,
    parse_deadline=300.0,
)

LSP_RESOURCE_LIMITS = ResourceLimits(
    max_input_bytes=8 * 1024 * 1024,
    max_tokens=250_000,
    max_nesting_depth=128,
    max_rules=10_000,
    max_strings_per_rule=2_000,
    max_regex_length=256 * 1024,
    max_hex_pattern_length=1024 * 1024,
    max_include_depth=16,
    parse_deadline=2.0,
)


@dataclass
class CancellationToken:
    """Thread-safe cooperative parse cancellation token."""

    _event: Event = field(default_factory=Event, init=False, repr=False)

    def cancel(self) -> None:
        """Request cancellation."""
        self._event.set()

    @property
    def cancelled(self) -> bool:
        """Whether cancellation has been requested."""
        return self._event.is_set()


class ParseBudget:
    """Mutable counters shared by a lexer and parser for one operation."""

    _OPEN_TOKENS = frozenset({"LPAREN", "LBRACE", "LBRACKET"})
    _CLOSE_TOKENS = frozenset({"RPAREN", "RBRACE", "RBRACKET"})

    def __init__(
        self,
        limits: ResourceLimits | None,
        cancellation_token: CancellationToken | None = None,
    ) -> None:
        if limits is not None and not isinstance(limits, ResourceLimits):
            raise TypeError("resource_limits must be a ResourceLimits or None")
        if cancellation_token is not None and not isinstance(cancellation_token, CancellationToken):
            raise TypeError("cancellation_token must be a CancellationToken or None")
        self.limits = limits
        self.cancellation_token = cancellation_token
        self.started_at = monotonic()
        self.token_count = 0
        self.nesting_depth = 0

    def checkpoint(self) -> None:
        """Raise when cancellation or the deadline has been reached."""
        if self.cancellation_token is not None and self.cancellation_token.cancelled:
            raise ParseCancelledError("Parsing cancelled")
        deadline = self.limits.parse_deadline if self.limits is not None else None
        if deadline is not None and monotonic() - self.started_at > deadline:
            raise ResourceLimitError(f"parse_deadline exceeded ({deadline:g} seconds)")

    def validate_source(self, source: str) -> None:
        """Validate input size before dialect detection or token allocation."""
        self.checkpoint()
        maximum = self.limits.max_input_bytes if self.limits is not None else None
        if maximum is not None and len(source.encode("utf-8", errors="surrogatepass")) > maximum:
            raise ResourceLimitError(f"max_input_bytes exceeded ({maximum})")

    def consume_token(self, token_type: Any, value: object) -> None:
        """Account for a token and token-local limits."""
        self.token_count += 1
        if self.token_count % 256 == 0:
            self.checkpoint()
        limits = self.limits
        if limits is None:
            return
        if limits.max_tokens is not None and self.token_count > limits.max_tokens:
            raise ResourceLimitError(f"max_tokens exceeded ({limits.max_tokens})")

        kind = getattr(token_type, "name", "")
        if kind in self._OPEN_TOKENS:
            self.nesting_depth += 1
            if (
                limits.max_nesting_depth is not None
                and self.nesting_depth > limits.max_nesting_depth
            ):
                raise ResourceLimitError(f"max_nesting_depth exceeded ({limits.max_nesting_depth})")
        elif kind in self._CLOSE_TOKENS:
            self.nesting_depth = max(0, self.nesting_depth - 1)

        if kind == "REGEX" and limits.max_regex_length is not None:
            value_bytes = len(str(value).encode("utf-8", errors="surrogatepass"))
            if value_bytes > limits.max_regex_length:
                raise ResourceLimitError(f"max_regex_length exceeded ({limits.max_regex_length})")
        elif kind == "HEX_STRING" and limits.max_hex_pattern_length is not None:
            value_bytes = len(str(value).encode("utf-8", errors="surrogatepass"))
            if value_bytes > limits.max_hex_pattern_length:
                raise ResourceLimitError(
                    f"max_hex_pattern_length exceeded ({limits.max_hex_pattern_length})"
                )

    def validate_document(self, document: ASTNode) -> None:
        """Validate AST-wide limits after parsing."""
        self.checkpoint()
        limits = self.limits
        if limits is None:
            return
        rules = getattr(document, "rules", [])
        if limits.max_rules is not None and len(rules) > limits.max_rules:
            raise ResourceLimitError(f"max_rules exceeded ({limits.max_rules})")
        if limits.max_strings_per_rule is not None:
            for rule in rules:
                strings = getattr(rule, "strings", [])
                if len(strings) > limits.max_strings_per_rule:
                    raise ResourceLimitError(
                        f"max_strings_per_rule exceeded ({limits.max_strings_per_rule})"
                    )

        if limits.max_nesting_depth is None:
            return
        stack = [(document, 1)]
        while stack:
            node, depth = stack.pop()
            if depth > limits.max_nesting_depth:
                raise ResourceLimitError(f"max_nesting_depth exceeded ({limits.max_nesting_depth})")
            stack.extend((child, depth + 1) for child in node.children())
