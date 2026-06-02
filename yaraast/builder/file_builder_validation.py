"""Validation helpers for YARA file builders."""

from __future__ import annotations

from collections.abc import Sequence
import re

from yaraast.ast.rules import Rule
from yaraast.errors import ValidationError
from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH

_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)


def validate_nonempty_text(value: object, kind: str) -> None:
    if not isinstance(value, str):
        msg = f"{kind} must be a string"
        raise TypeError(msg)
    if value.strip():
        return
    msg = f"{kind} must not be empty"
    raise ValidationError(msg)


def validate_nonempty_texts(values: Sequence[str], kind: str) -> None:
    for value in values:
        validate_nonempty_text(value, kind)


def validate_identifier(value: object, kind: str) -> None:
    if not isinstance(value, str):
        msg = f"Invalid {kind} identifier: {value}"
        raise TypeError(msg)
    if (
        len(value) <= YARA_IDENTIFIER_MAX_LENGTH
        and _YARA_IDENTIFIER_RE.fullmatch(value) is not None
        and value not in _YARA_KEYWORDS
    ):
        return
    msg = f"Invalid {kind} identifier: {value}"
    raise ValidationError(msg)


def validate_identifier_path(value: object, kind: str) -> None:
    if not isinstance(value, str):
        msg = f"Invalid {kind} identifier: {value}"
        raise TypeError(msg)
    parts = value.split(".")
    if any(part == "" for part in parts):
        msg = f"Invalid {kind} identifier: {value}"
        raise ValidationError(msg)
    for part in parts:
        validate_identifier(part, kind)


def validate_meta_value(value: object) -> None:
    if isinstance(value, str | bool | int):
        return
    msg = f"Invalid meta value: {value}"
    raise TypeError(msg)


def validate_version_value(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = "Version value must be an integer"
    raise TypeError(msg)


def validate_optional_identifier(value: object | None, kind: str) -> None:
    if value is None:
        return
    validate_identifier(value, kind)


def validate_rule_names(rules: Sequence[Rule]) -> None:
    for rule in rules:
        validate_identifier(rule.name, "rule")


def validate_unique_rule_names(existing_rules: Sequence[Rule], new_rules: Sequence[Rule]) -> None:
    seen = {rule.name for rule in existing_rules}
    for rule in new_rules:
        if rule.name in seen:
            msg = f"Duplicate rule identifier: {rule.name}"
            raise ValidationError(msg)
        seen.add(rule.name)
