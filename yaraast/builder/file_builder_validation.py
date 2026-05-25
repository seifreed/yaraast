"""Validation helpers for YARA file builders."""

from __future__ import annotations

from collections.abc import Sequence

from yaraast.ast.rules import Rule
from yaraast.errors import ValidationError


def validate_unique_rule_names(existing_rules: Sequence[Rule], new_rules: Sequence[Rule]) -> None:
    seen = {rule.name for rule in existing_rules}
    for rule in new_rules:
        if rule.name in seen:
            msg = f"Duplicate rule identifier: {rule.name}"
            raise ValidationError(msg)
        seen.add(rule.name)
