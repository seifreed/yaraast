"""Validation helpers for builder string identifiers."""

from __future__ import annotations

from collections.abc import Sequence
import re

from yaraast.ast.strings import StringDefinition
from yaraast.errors import ValidationError

_STRING_IDENTIFIER_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")


def normalize_string_identifier(identifier: object) -> str:
    if not isinstance(identifier, str):
        msg = f"Invalid string identifier: {identifier}"
        raise TypeError(msg)
    normalized = identifier if identifier.startswith("$") else f"${identifier}"
    body = normalized.removeprefix("$")
    if body and _STRING_IDENTIFIER_BODY_RE.fullmatch(body) is not None:
        return normalized
    msg = f"Invalid string identifier: {normalized}"
    raise ValidationError(msg)


def validate_new_string_definitions(
    existing_strings: Sequence[StringDefinition],
    new_strings: Sequence[StringDefinition],
) -> None:
    seen = {
        normalize_string_identifier(string_def.identifier)
        for string_def in existing_strings
        if not string_def.is_anonymous
    }
    for string_def in new_strings:
        if string_def.is_anonymous:
            continue
        identifier = normalize_string_identifier(string_def.identifier)
        if identifier in seen:
            msg = f"Duplicate string identifier: {identifier}"
            raise ValidationError(msg)
        seen.add(identifier)
