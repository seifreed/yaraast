"""YARA dialect support for YARA, YARA-X, and YARA-L."""

from enum import Enum, auto


class YaraDialect(Enum):
    """YARA dialect enumeration."""

    YARA = auto()  # Standard YARA
    YARA_X = auto()  # YARA-X (VirusTotal's next-gen YARA)
    YARA_L = auto()  # YARA-L (Google Chronicle)


def detect_dialect(content: str) -> YaraDialect:
    """Detect the YARA dialect from content.

    Args:
        content: The rule content to analyze

    Returns:
        The detected YARA dialect

    """
    import re

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

    # YARA-X specific features (if any distinct ones exist)
    yarax_keywords = [
        # Add YARA-X specific features when identified
    ]

    # Check for YARA-L structural indicators (highest priority)
    # Use MULTILINE flag so ^ matches at start of each line
    for pattern in yaral_structural_patterns:
        if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
            return YaraDialect.YARA_L

    # Check for YARA-L UDM patterns
    for pattern in yaral_udm_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return YaraDialect.YARA_L

    # Check for YARA-L aggregation functions
    for pattern in yaral_aggregation_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return YaraDialect.YARA_L

    # Check for YARA-X indicators
    for keyword in yarax_keywords:
        if keyword.lower() in content.lower():
            return YaraDialect.YARA_X

    # Default to standard YARA
    return YaraDialect.YARA


__all__ = ["YaraDialect", "detect_dialect"]
