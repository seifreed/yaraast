"""Validation helpers for builder-created hex token sequences."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from yaraast.ast.strings import HexAlternative, HexJump, HexToken
from yaraast.errors import ValidationError


def validate_hex_tokens_for_builder(tokens: Sequence[HexToken], identifier: str) -> None:
    """Reject hex token sequences that cannot be emitted as libyara output."""
    _validate_hex_token_sequence(
        tokens,
        identifier,
        context="hex string",
        inside_alternative=False,
    )


def _validate_hex_token_sequence(
    tokens: Sequence[Any],
    identifier: str,
    *,
    context: str,
    inside_alternative: bool,
) -> None:
    if not tokens:
        msg = f"Hex string content not set for {identifier}"
        raise ValidationError(msg)

    for token in tokens:
        if isinstance(token, HexAlternative):
            _validate_hex_alternative(token, identifier)
        elif inside_alternative and isinstance(token, HexJump) and token.max_jump is None:
            msg = "Unbounded HexJump is not allowed inside hex alternatives"
            raise ValidationError(msg)

    if isinstance(tokens[0], HexJump) or isinstance(tokens[-1], HexJump):
        msg = f"HexJump cannot appear at the beginning or end of {context} {identifier}"
        raise ValidationError(msg)


def _validate_hex_alternative(token: HexAlternative, identifier: str) -> None:
    alternatives = token.alternatives
    if not isinstance(alternatives, list | tuple) or not alternatives:
        msg = "HexAlternative must contain at least one branch"
        raise ValidationError(msg)

    for alternative in alternatives:
        branch = alternative if isinstance(alternative, list | tuple) else [alternative]
        if not branch:
            msg = "HexAlternative branches must not be empty"
            raise ValidationError(msg)
        _validate_hex_token_sequence(
            branch,
            identifier,
            context="hex alternative branch",
            inside_alternative=True,
        )
