"""YARA dialect support for YARA, YARA-X, and YARA-L."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto
import re
import threading
from typing import Any, ClassVar, Protocol, runtime_checkable


@runtime_checkable
class ParseResult(Protocol):
    """Minimal protocol for dialect parse results."""

    rules: list[Any]
    imports: list[Any]
    includes: list[Any]


class YaraDialect(Enum):
    """YARA dialect enumeration."""

    YARA = auto()  # Standard YARA
    YARA_X = auto()  # YARA-X (VirusTotal's next-gen YARA)
    YARA_L = auto()  # YARA-L (Google Chronicle)


_REGEX_CONTEXT_KEYWORDS = {"and", "condition", "contains", "matches", "not", "or"}


def _is_regex_literal_start(content: str, index: int) -> bool:
    """Return whether a slash appears in a YARA regex-literal context."""
    if content[index] != "/" or (index + 1 < len(content) and content[index + 1] in "/*"):
        return False

    previous = index - 1
    while previous >= 0 and content[previous].isspace():
        previous -= 1

    if previous < 0:
        return True

    if content[previous] in "=(:,[!~":
        return True

    if content[previous].isalnum() or content[previous] == "_":
        word_end = previous + 1
        while previous >= 0 and (content[previous].isalnum() or content[previous] == "_"):
            previous -= 1
        return content[previous + 1 : word_end].lower() in _REGEX_CONTEXT_KEYWORDS

    return False


def _strip_string_literals(content: str) -> str:
    """Remove literal contents to avoid false positive dialect detection.

    Replaces the contents of double-quoted strings with empty strings,
    handling escaped quotes properly. Regex literals are also replaced,
    since YARA-X-looking snippets inside regex patterns are still classic YARA.
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

        if _is_regex_literal_start(content, i):
            result.append(" ")
            i += 1
            escaped = False
            while i < len(content):
                char = content[i]
                result.append("\n" if char == "\n" else " ")
                i += 1
                if escaped:
                    escaped = False
                    continue
                if char == "\\":
                    escaped = True
                    continue
                if char == "/":
                    while i < len(content) and content[i] in "ims":
                        result.append(" ")
                        i += 1
                    break
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
    r"\bwith\s+\$?\w+\s*=",
    r"\blambda(?:\s+\w+(?:\s*,\s*\w+)*)?\s*:",
    r"\bmatch\s+[^{}]+\{[^{}]*=>",
    r"\[[^\]]+\bfor\s+\w+\s+in\s+[^\]]+\]",
    r"\{[^{}:]+:[^{}]+\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+[^{}]+\}",
    r"\bcondition\s*:\s*\[[^\]\n]*\]",
    r"\bcondition\s*:\s*\{\s*\}",
    r"\bcondition\s*:\s*\{[^{}\n]*:[^{}\n]*\}",
    r"\bcondition\s*:\s*\([^()\n]*,\s*[^()\n]*\)",
    r"\bcondition\s*:\s*\(\s*\([^()\n]*,[^()\n]*\)\s*,",
    r"\bcondition\s*:\s*\([^()\n]*,\s*\([^()\n]*,[^()\n]*\)\s*\)",
    r"(?:\bcondition\s*:|[=(:,]\s*)\[[^\]\n]*(?:,|\.{3}|\b(?:true|false|lambda|match)\b|\"\")[^\]\n]*\]",
    r"(?:\bcondition\s*:|[=(:,]\s*)\{\s*(?:\"\"|\d+|true|false)\s*:",
    r"(?:\bcondition\s*:|[=(:,]\s*)\{\s*\*\*",
    r"(?:[A-Za-z_$]\w*(?:\s*\([^)]*\))?|\"\"|\])\s*\[[^\]\n]*:[^\]\n]*\]",
    r"\([^()\n]*,[^()\n]*\)\s*\[",
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

    _specs: ClassVar[list[DialectSpec]] = []
    _lock: ClassVar[Any] = threading.Lock()

    @classmethod
    def register(cls, spec: DialectSpec) -> None:
        with cls._lock:
            cls._specs.append(spec)
            cls._specs.sort(key=lambda s: -s.priority)

    @classmethod
    def detect(cls, content: str) -> YaraDialect:
        with cls._lock:
            specs = list(cls._specs)  # snapshot under lock
        stripped = _strip_string_literals(content)
        for spec in specs:
            for pattern, flags in spec.detection_patterns:
                if re.search(pattern, stripped, flags):
                    return spec.dialect
        return YaraDialect.YARA

    @classmethod
    def get_parser_factory(cls, dialect: YaraDialect) -> Callable[[str], Any] | None:
        with cls._lock:
            specs = list(cls._specs)
        for spec in specs:
            if spec.dialect == dialect:
                return spec.parser_factory
        return None

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
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


__all__ = ["DialectRegistry", "DialectSpec", "ParseResult", "YaraDialect", "detect_dialect"]
