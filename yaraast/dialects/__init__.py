"""YARA dialect support for YARA, YARA-X, and YARA-L."""

import re
from enum import Enum, auto


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


def detect_dialect(content: str) -> YaraDialect:
    """Detect the YARA dialect from content.

    Args:
        content: The rule content to analyze

    Returns:
        The detected YARA dialect

    """
    # Strip string literals to avoid false positives from patterns inside strings
    stripped = _strip_string_literals(content)

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

    # Check for YARA-L structural indicators (highest priority)
    # Use MULTILINE flag so ^ matches at start of each line
    for pattern in yaral_structural_patterns:
        if re.search(pattern, stripped, re.MULTILINE | re.IGNORECASE):
            return YaraDialect.YARA_L

    # Check for YARA-L UDM patterns
    for pattern in yaral_udm_patterns:
        if re.search(pattern, stripped, re.IGNORECASE):
            return YaraDialect.YARA_L

    # Check for YARA-L aggregation functions
    for pattern in yaral_aggregation_patterns:
        if re.search(pattern, stripped, re.IGNORECASE):
            return YaraDialect.YARA_L

    # Check for YARA-X indicators
    for pattern in yarax_patterns:
        if re.search(pattern, stripped, re.IGNORECASE | re.DOTALL):
            return YaraDialect.YARA_X

    # Default to standard YARA
    return YaraDialect.YARA


__all__ = ["YaraDialect", "detect_dialect"]
