"""YARA dialect support for YARA, YARA-X, and YARA-L."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any


class YaraDialect(Enum):
    """YARA dialect enumeration."""

    YARA = auto()  # Standard YARA
    YARA_X = auto()  # YARA-X (VirusTotal's next-gen YARA)
    YARA_L = auto()  # YARA-L (Google Chronicle)


def _strip_string_literals(content: str) -> str:
    """Remove string literal contents to avoid false positive dialect detection.

    Replaces the contents of double-quoted strings with empty strings,
    handling escaped quotes properly.
    """
    result: list[str] = []
    i = 0
    in_line_comment = False
    in_block_comment = False

    while i < len(content):
        # Handle line comments — replace content with spaces
        if not in_block_comment and i < len(content) - 1 and content[i : i + 2] == "//":
            in_line_comment = True
            result.append(" ")
            i += 1
            continue
        if in_line_comment:
            if content[i] == "\n":
                result.append("\n")
                in_line_comment = False
            else:
                result.append(" ")
            i += 1
            continue

        # Handle block comments — replace content with spaces (preserve newlines)
        if not in_line_comment and i < len(content) - 1 and content[i : i + 2] == "/*":
            in_block_comment = True
            result.append(" ")
            i += 1
            continue
        if in_block_comment:
            if i < len(content) - 1 and content[i : i + 2] == "*/":
                result.append(" ")
                result.append(" ")
                in_block_comment = False
                i += 2
                continue
            result.append("\n" if content[i] == "\n" else " ")
            i += 1
            continue

        # Handle string literals - replace contents with empty
        if content[i] == '"':
            result.append('"')
            i += 1
            while i < len(content) and content[i] != '"':
                if content[i] == "\\" and i + 1 < len(content):
                    i += 2  # Skip escaped character
                else:
                    i += 1
            if i < len(content):
                result.append('"')
                i += 1
            continue

        result.append(content[i])
        i += 1

    return "".join(result)


# -- Pattern lists for dialect detection --

# YARA-L specific structural keywords (high confidence indicators)
# Match these as section headers at the start of a line (possibly after whitespace)
# to avoid false positives from strings containing these patterns
yaral_structural_patterns = [
    r"^\s*events\s*:",
    r"^\s*match\s*:",
    r"^\s*outcome\s*:",
]

# YARA-L UDM (Unified Data Model) field patterns
# These start with $ followed by event variable and UDM field path
# Example: $e.metadata.event_type, $e1.principal.hostname
yaral_udm_patterns = [
    r"\$\w+\.metadata\.event_type",
    r"\$\w+\.principal\.",
    r"\$\w+\.target\.",
    r"\$\w+\.udm\.",
]

# YARA-L aggregation functions (unique to YARA-L)
yaral_aggregation_patterns = [
    r"\bcount_distinct\s*\(",
    r"\barray_distinct\s*\(",
    r"\bearliest\s*\(",
    r"\blatest\s*\(",
]

# YARA-X specific features supported by this codebase.
# Keep these patterns narrow to avoid false positives in standard YARA.
yarax_patterns = [
    r"\bwith\s+\$\w+\s*=",
    r"\blambda(?:\s+\w+(?:\s*,\s*\w+)*)?\s*:",
    r"\bmatch\s+[^{}]+\{[^{}]*=>",
    r"\[[^\]]+\bfor\s+\w+\s+in\s+[^\]]+\]",
    r"\{[^{}:]+:[^{}]+\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+[^{}]+\}",
]


# -- Registry --


@dataclass
class DialectSpec:
    """Registration spec for a YARA dialect."""

    dialect: YaraDialect
    parser_factory: Callable[[str], Any]  # text -> AST (YaraFile | YaraLFile)
    detection_patterns: list[tuple[str, re.RegexFlag]]  # (regex, re_flags) pairs
    priority: int = 0  # higher = checked first


class DialectRegistry:
    """Registry allowing dialect plugins without modifying UnifiedParser."""

    _specs: list[DialectSpec] = []

    @classmethod
    def register(cls, spec: DialectSpec) -> None:
        cls._specs.append(spec)
        cls._specs.sort(key=lambda s: -s.priority)

    @classmethod
    def detect(cls, content: str) -> YaraDialect:
        stripped = _strip_string_literals(content)
        for spec in cls._specs:
            for pattern, flags in spec.detection_patterns:
                if re.search(pattern, stripped, flags):
                    return spec.dialect
        return YaraDialect.YARA

    @classmethod
    def get_parser_factory(cls, dialect: YaraDialect) -> Callable[[str], Any] | None:
        for spec in cls._specs:
            if spec.dialect == dialect:
                return spec.parser_factory
        return None

    @classmethod
    def clear(cls) -> None:
        cls._specs.clear()


def _register_builtins() -> None:
    from yaraast.yaral.parser import YaraLParser
    from yaraast.yarax.parser import YaraXParser

    DialectRegistry.register(
        DialectSpec(
            dialect=YaraDialect.YARA_L,
            parser_factory=lambda text: YaraLParser(text).parse(),
            detection_patterns=[
                (p, re.MULTILINE | re.IGNORECASE) for p in yaral_structural_patterns
            ]
            + [(p, re.IGNORECASE) for p in yaral_udm_patterns + yaral_aggregation_patterns],
            priority=10,
        )
    )
    DialectRegistry.register(
        DialectSpec(
            dialect=YaraDialect.YARA_X,
            parser_factory=lambda text: YaraXParser(text).parse(),
            detection_patterns=[(p, re.IGNORECASE | re.DOTALL) for p in yarax_patterns],
            priority=5,
        )
    )


_register_builtins()


def detect_dialect(content: str) -> YaraDialect:
    """Detect the YARA dialect from content.

    Args:
        content: The rule content to analyze

    Returns:
        The detected YARA dialect

    """
    return DialectRegistry.detect(content)


__all__ = ["DialectRegistry", "DialectSpec", "YaraDialect", "detect_dialect"]
