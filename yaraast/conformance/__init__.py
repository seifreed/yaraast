"""Differential conformance checking against reference YARA engines.

yaraast is a parse/manipulate library: scanning is delegated to real engines.
This package verifies that yaraast's parse->generate round-trip never changes
what a reference engine (libyara via yara-python, and YARA-X) thinks of a rule
-- neither its acceptance nor its matches. It is the drift-prevention gate.
"""

from yaraast.conformance.differential import (
    ConformanceReport,
    DifferentialChecker,
    Divergence,
)
from yaraast.conformance.engines import (
    EngineResult,
    LibyaraEngine,
    ReferenceEngine,
    YaraXEngine,
    available_engines,
)

__all__ = [
    "ConformanceReport",
    "DifferentialChecker",
    "Divergence",
    "EngineResult",
    "LibyaraEngine",
    "ReferenceEngine",
    "YaraXEngine",
    "available_engines",
]
