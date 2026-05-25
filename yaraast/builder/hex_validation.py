"""Validation helpers for builder-created hex token sequences."""

from __future__ import annotations

from collections.abc import Sequence

from yaraast.ast.strings import HexJump, HexToken
from yaraast.errors import ValidationError


def validate_hex_tokens_for_builder(tokens: Sequence[HexToken], identifier: str) -> None:
    """Reject hex token sequences that cannot be emitted as libyara output."""
    if not tokens:
        msg = f"Hex string content not set for {identifier}"
        raise ValidationError(msg)
    if isinstance(tokens[0], HexJump) or isinstance(tokens[-1], HexJump):
        msg = f"HexJump cannot appear at the beginning or end of hex string {identifier}"
        raise ValidationError(msg)
