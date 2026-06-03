"""Adapters over reference YARA engines with a uniform evaluate() contract.

Each engine answers two questions about a piece of YARA source: does it accept
the source (compile), and -- if data is supplied and the source compiled --
which rule identifiers match. Engines that are not installed report
``available = False`` and are skipped by callers rather than raising.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class EngineResult:
    """Outcome of evaluating YARA source with one reference engine."""

    accepted: bool
    error: str | None = None
    matches: frozenset[str] | None = None


class ReferenceEngine(ABC):
    """Uniform interface over a reference YARA engine."""

    name: str

    @property
    @abstractmethod
    def available(self) -> bool:
        """Whether the underlying engine is importable in this environment."""

    @abstractmethod
    def evaluate(self, source: str, data: bytes | None = None) -> EngineResult:
        """Compile ``source`` and, if it compiles and ``data`` is given, scan it."""


class LibyaraEngine(ReferenceEngine):
    """Reference engine backed by yara-python (libyara)."""

    name = "libyara"

    @property
    def available(self) -> bool:
        from yaraast.libyara import YARA_AVAILABLE

        return bool(YARA_AVAILABLE)

    def evaluate(self, source: str, data: bytes | None = None) -> EngineResult:
        import yara

        try:
            compiled = yara.compile(source=source)
        except yara.Error as exc:
            return EngineResult(accepted=False, error=str(exc))

        if data is None:
            return EngineResult(accepted=True)

        matches = compiled.match(data=data)
        return EngineResult(
            accepted=True,
            matches=frozenset(match.rule for match in matches),
        )


class YaraXEngine(ReferenceEngine):
    """Reference engine backed by the YARA-X Python bindings."""

    name = "yara-x"

    @property
    def available(self) -> bool:
        try:
            import yara_x  # noqa: F401
        except ImportError:
            return False
        return True

    def evaluate(self, source: str, data: bytes | None = None) -> EngineResult:
        import yara_x

        try:
            compiled = yara_x.compile(source)
        except yara_x.CompileError as exc:
            return EngineResult(accepted=False, error=str(exc))

        if data is None:
            return EngineResult(accepted=True)

        results = yara_x.Scanner(compiled).scan(data)
        return EngineResult(
            accepted=True,
            matches=frozenset(rule.identifier for rule in results.matching_rules),
        )


def available_engines() -> list[ReferenceEngine]:
    """Return the reference engines installed in this environment."""
    return [engine for engine in (LibyaraEngine(), YaraXEngine()) if engine.available]
