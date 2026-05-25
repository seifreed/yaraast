"""Validation helpers for YARA file builders."""

from __future__ import annotations

from collections.abc import Sequence

from yaraast.ast.rules import Rule
from yaraast.errors import ValidationError


def validate_nonempty_text(value: object, kind: str) -> None:
    if not isinstance(value, str):
        msg = f"{kind} must be a string"
        raise TypeError(msg)
    if value:
        return
    msg = f"{kind} must not be empty"
    raise ValidationError(msg)


def validate_nonempty_texts(values: Sequence[str], kind: str) -> None:
    for value in values:
        validate_nonempty_text(value, kind)


def validate_unique_rule_names(existing_rules: Sequence[Rule], new_rules: Sequence[Rule]) -> None:
    seen = {rule.name for rule in existing_rules}
    for rule in new_rules:
        if rule.name in seen:
            msg = f"Duplicate rule identifier: {rule.name}"
            raise ValidationError(msg)
        seen.add(rule.name)
