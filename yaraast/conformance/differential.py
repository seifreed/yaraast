"""Differential round-trip conformance against reference YARA engines.

The gate checks invariants that only fire on *yaraast* drift, never on
legitimate differences between libyara and YARA-X:

* G1 acceptance preservation -- if an engine accepts the original source, it
  must also accept the source yaraast regenerates from its AST.
* G2 match preservation -- when both the original and the regenerated source
  compile and scan data is supplied, both must match the same rule set.
* G3 parse parity -- if libyara (the classic reference) accepts the original,
  yaraast must be able to parse and regenerate it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from yaraast.codegen.generator import CodeGenerator
from yaraast.conformance.engines import EngineResult, ReferenceEngine, available_engines
from yaraast.parser.parser import Parser


@dataclass(frozen=True)
class Divergence:
    """A single conformance violation attributable to yaraast."""

    engine: str
    kind: str
    detail: str


@dataclass
class ConformanceReport:
    """Per-source differential result."""

    name: str
    parse_ok: bool
    regenerated: str | None
    parse_error: str | None = None
    engine_results: dict[str, EngineResult] = field(default_factory=dict)
    divergences: list[Divergence] = field(default_factory=list)

    @property
    def conformant(self) -> bool:
        """True when no yaraast-attributable divergence was found."""
        return not self.divergences


class DifferentialChecker:
    """Run the round-trip conformance invariants over reference engines."""

    def __init__(self, engines: list[ReferenceEngine] | None = None) -> None:
        """Use the supplied engines, or every engine installed in this env."""
        self.engines = engines if engines is not None else available_engines()

    def _round_trip(self, source: str) -> tuple[str | None, str | None]:
        try:
            ast = Parser(source).parse()
            return CodeGenerator().generate(ast), None
        except Exception as exc:
            return None, str(exc)

    def check(
        self, source: str, data: bytes | None = None, *, name: str = "<source>"
    ) -> ConformanceReport:
        """Evaluate one YARA source against every configured engine."""
        regenerated, parse_error = self._round_trip(source)
        report = ConformanceReport(
            name=name,
            parse_ok=regenerated is not None,
            regenerated=regenerated,
            parse_error=parse_error,
        )

        for engine in self.engines:
            original = engine.evaluate(source, data)
            report.engine_results[engine.name] = original

            if engine.name == "libyara" and original.accepted and parse_error is not None:
                report.divergences.append(
                    Divergence(
                        engine=engine.name,
                        kind="parse_parity",
                        detail=f"libyara accepts source but yaraast failed to parse: {parse_error}",
                    )
                )

            if regenerated is None or not original.accepted:
                continue

            regen = engine.evaluate(regenerated, data)
            if not regen.accepted:
                report.divergences.append(
                    Divergence(
                        engine=engine.name,
                        kind="codegen_acceptance",
                        detail=(
                            f"{engine.name} accepted original but rejected regenerated "
                            f"source: {regen.error}"
                        ),
                    )
                )
                continue

            if data is not None and original.matches != regen.matches:
                only_original = sorted(
                    (original.matches or frozenset()) - (regen.matches or frozenset())
                )
                only_regen = sorted(
                    (regen.matches or frozenset()) - (original.matches or frozenset())
                )
                report.divergences.append(
                    Divergence(
                        engine=engine.name,
                        kind="match_drift",
                        detail=(
                            f"{engine.name} match set changed after round-trip; "
                            f"only in original={only_original}, only in regenerated={only_regen}"
                        ),
                    )
                )

        return report
