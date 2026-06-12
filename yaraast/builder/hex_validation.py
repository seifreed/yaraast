"""Validation helpers for builder-created hex token sequences."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexToken,
    HexWildcard,
)
from yaraast.errors import ValidationError

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


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
        elif inside_alternative and isinstance(token, int | str):
            _validate_hex_byte_value(token)
        elif not isinstance(
            token,
            HexByte | HexNegatedByte | HexNibble | HexWildcard | HexJump,
        ):
            msg = f"Unsupported hex token '{type(token).__name__}'"
            raise TypeError(msg)
        else:
            _validate_hex_token_structure(token)

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


def _validate_hex_token_structure(token: HexToken) -> None:
    validate_structure = getattr(token, "validate_structure", None)
    if callable(validate_structure):
        validate_structure()


def _validate_hex_byte_value(value: int | str) -> None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return
    if isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value):
        return
    msg = "HexByte value must be a byte"
    raise TypeError(msg)
