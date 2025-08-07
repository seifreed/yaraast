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
    # Quick heuristics for dialect detection
    content_lower = content.lower()

    # YARA-L specific keywords
    yaral_keywords = [
        "events:",
        "match:",
        "outcome:",
        "options:",
        "metadata.event_type",
        "principal.",
        "target.",
        "udm.",
        "over ",
        "nocase",
        "count_distinct",
        "array_distinct",
        "earliest",
        "latest",
    ]

    # YARA-X specific features (if any distinct ones exist)
    yarax_keywords = [
        # Add YARA-X specific features when identified
    ]

    # Check for YARA-L indicators
    for keyword in yaral_keywords:
        if keyword in content_lower:
            return YaraDialect.YARA_L

    # Check for YARA-X indicators
    for keyword in yarax_keywords:
        if keyword in content_lower:
            return YaraDialect.YARA_X

    # Default to standard YARA
    return YaraDialect.YARA


__all__ = ["YaraDialect", "detect_dialect"]
