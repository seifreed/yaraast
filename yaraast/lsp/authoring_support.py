"""Support types and helpers for LSP authoring actions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.codegen.formatting import FormattingConfig, PredefinedStyles
from yaraast.lsp.structure import get_rule_text_range

STRING_DEF_RE = re.compile(r"^(?P<indent>\s*)(?P<identifier>\$\w+)\s*=\s*(?P<body>.+?)\s*$")
PLAIN_STRING_RE = re.compile(r'^"(?P<value>[^"\n]*)"(?P<tail>.*)$')

PREFERRED_MODIFIER_ORDER = [
    "ascii",
    "wide",
    "nocase",
    "fullword",
    "xor",
    "base64",
    "base64wide",
    "private",
]


@dataclass(slots=True)
class RuleContext:
    """Source slice covering one rule in the current document."""

    start: int
    end: int
    text: str
    lines: list[str]


def get_rule_context(text: str, current_line: int) -> RuleContext | None:
    rule_range = get_rule_text_range(text, current_line)
    if rule_range is None:
        return None
    return RuleContext(
        start=rule_range.start,
        end=rule_range.end,
        text=rule_range.text,
        lines=rule_range.lines,
    )


def diff_preview(diff: Any, base: str) -> str:
    style = len(getattr(diff, "style_only_changes", []) or [])
    structural = len(getattr(diff, "structural_changes", []) or [])
    logical = len(getattr(diff, "logical_changes", []) or [])
    parts = [base]
    if style:
        parts.append(f"{style} style")
    if structural:
        parts.append(f"{structural} structural")
    if logical:
        parts.append(f"{logical} logical")
    return " | ".join(parts)


def modifier_start(body: str) -> int | None:
    in_quote = False
    in_regex = False
    brace_depth = 0
    for idx, char in enumerate(body):
        if char == '"' and not in_regex and brace_depth == 0:
            in_quote = not in_quote
        elif char == "/" and not in_quote and brace_depth == 0:
            in_regex = not in_regex
        elif char == "{" and not in_quote and not in_regex:
            brace_depth += 1
        elif char == "}" and brace_depth > 0 and not in_quote and not in_regex:
            brace_depth -= 1
        elif char.isspace() and not in_quote and not in_regex and brace_depth == 0:
            return idx + 1
    return None


def normalize_modifiers(modifiers: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for modifier in modifiers:
        if modifier not in seen:
            unique.append(modifier)
            seen.add(modifier)
    order = {name: idx for idx, name in enumerate(PREFERRED_MODIFIER_ORDER)}
    return sorted(unique, key=lambda item: (order.get(item, len(order)), item))


def string_signature(string_def: Any) -> tuple[object, ...]:
    modifiers = tuple(sorted(str(modifier) for modifier in getattr(string_def, "modifiers", [])))
    if isinstance(string_def, PlainString):
        return ("plain", string_def.value, modifiers)
    if isinstance(string_def, RegexString):
        return ("regex", string_def.regex, modifiers)
    if isinstance(string_def, HexString):
        return ("hex", tuple(str(token) for token in string_def.tokens), modifiers)
    return (type(string_def).__name__, getattr(string_def, "identifier", ""), modifiers)


def canonical_config() -> FormattingConfig:
    config = PredefinedStyles.readable()
    config.sort_meta = True
    config.sort_strings = True
    config.blank_lines_between_sections = 1
    config.section_order = ["meta", "strings", "condition"]
    return config


def impact_title(base: str, diff: Any, new_text: str) -> str:
    if diff.style_only_changes and not diff.logical_changes and not diff.structural_changes:
        return f"{base} (style-only)"
    if not diff.logical_changes and not diff.structural_changes and new_text:
        return f"{base} (safe rewrite)"
    return base
