"""Local fixture-based testing for YARA rules."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

import yaml

from yaraast.conformance.engines import LibyaraEngine, ReferenceEngine, YaraXEngine


@dataclass(frozen=True)
class FixtureCase:
    """One binary fixture and its expected matching rules."""

    path: str
    expected: tuple[str, ...]


@dataclass(frozen=True)
class TestBudgets:
    """Optional compile, scan, and memory budgets in manifest units."""

    max_compile_ms: int | None = None
    max_scan_ms: int | None = None
    max_peak_memory_mb: int | None = None


@dataclass(frozen=True)
class RuleTestManifest:
    """Validated ``yaraast-test/v1`` manifest."""

    path: Path
    rule_id: str
    engines: tuple[str, ...]
    positive: tuple[FixtureCase, ...]
    negative: tuple[FixtureCase, ...]
    budgets: TestBudgets = field(default_factory=TestBudgets)

    @classmethod
    def load(cls, path: str | Path) -> RuleTestManifest:
        """Load and validate a YAML test manifest."""
        manifest_path = Path(path)
        try:
            data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise ValueError(f"invalid test manifest: {manifest_path}") from exc
        if not isinstance(data, dict) or data.get("schema") != "yaraast-test/v1":
            raise ValueError("test manifest schema must be yaraast-test/v1")
        rule_id = _string(data.get("rule_id"), "rule_id")
        engines = _string_tuple(data.get("engines", ("libyara",)), "engines")
        budgets = data.get("budgets", {})
        if not isinstance(budgets, dict):
            raise ValueError("budgets must be a mapping")
        return cls(
            path=manifest_path,
            rule_id=rule_id,
            engines=engines,
            positive=_cases(data.get("positive", ()), "positive"),
            negative=_cases(data.get("negative", ()), "negative"),
            budgets=TestBudgets(
                _optional_nonnegative_int(budgets.get("max_compile_ms"), "max_compile_ms"),
                _optional_nonnegative_int(budgets.get("max_scan_ms"), "max_scan_ms"),
                _optional_nonnegative_int(budgets.get("max_peak_memory_mb"), "max_peak_memory_mb"),
            ),
        )


@dataclass(frozen=True)
class FixtureResult:
    """Result for one fixture on one engine."""

    engine: str
    kind: str
    path: str
    passed: bool
    skipped: bool = False
    expected: tuple[str, ...] = ()
    actual: tuple[str, ...] = ()
    elapsed_ms: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "kind": self.kind,
            "path": self.path,
            "passed": self.passed,
            "skipped": self.skipped,
            "expected": list(self.expected),
            "actual": list(self.actual),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "error": self.error,
        }


@dataclass(frozen=True)
class RuleTestResult:
    """Aggregate result for one or more manifests."""

    manifests: tuple[RuleTestManifest, ...]
    fixtures: tuple[FixtureResult, ...]

    @property
    def failed(self) -> tuple[FixtureResult, ...]:
        return tuple(item for item in self.fixtures if not item.passed and not item.skipped)

    @property
    def passed(self) -> tuple[FixtureResult, ...]:
        return tuple(item for item in self.fixtures if item.passed)

    @property
    def skipped(self) -> tuple[FixtureResult, ...]:
        return tuple(item for item in self.fixtures if item.skipped)

    def coverage(self) -> dict[str, int]:
        """Return positive/negative rule coverage counts."""
        return {
            "rules": len(self.manifests),
            "positive": sum(bool(item.positive) for item in self.manifests),
            "negative": sum(bool(item.negative) for item in self.manifests),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifests": [manifest.rule_id for manifest in self.manifests],
            "fixtures": [item.to_dict() for item in self.fixtures],
            "coverage": self.coverage(),
            "passed": len(self.passed),
            "failed": len(self.failed),
            "skipped": len(self.skipped),
        }


def discover_manifests(path: str | Path) -> tuple[Path, ...]:
    """Find ``test.yml`` manifests below a file or directory."""
    candidate = Path(path)
    if candidate.is_file():
        return (candidate,)
    if not candidate.is_dir():
        raise ValueError(f"test path must be a file or directory: {candidate}")
    return tuple(sorted(candidate.rglob("test.yml")))


def discover_rule_sources(root: str | Path) -> dict[str, str]:
    """Index rule source by rule identifier below a project root."""
    candidate = Path(root)
    files = (
        (candidate,)
        if candidate.is_file()
        else tuple(candidate.rglob("*.yar")) + tuple(candidate.rglob("*.yara"))
    )
    pattern = re.compile(r"\brule\s+(?:private\s+|global\s+)*([A-Za-z_][A-Za-z0-9_]*)")
    sources: dict[str, str] = {}
    for path in sorted(set(files)):
        source = path.read_text(encoding="utf-8")
        for match in pattern.finditer(source):
            sources[match.group(1)] = source
    return sources


def select_changed_manifests(
    manifests: Iterable[RuleTestManifest],
    root: str | Path,
    revision: str,
) -> tuple[RuleTestManifest, ...]:
    """Select manifests changed directly or linked to changed rule sources."""
    project_root = Path(root).resolve()
    changed = _changed_paths(project_root, revision)
    changed_rule_ids: set[str] = set()
    rule_pattern = re.compile(r"\brule\s+(?:private\s+|global\s+)*([A-Za-z_][A-Za-z0-9_]*)")
    for relative in changed:
        changed_path = project_root / relative
        if changed_path.suffix not in {".yar", ".yara"}:
            continue
        try:
            changed_rule_ids.update(rule_pattern.findall(changed_path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue

    selected = []
    for manifest in manifests:
        relative = _relative_path(manifest.path, project_root)
        parent = _relative_path(manifest.path.parent, project_root)
        manifest_changed = relative in changed or any(
            item.startswith(f"{parent}/") for item in changed
        )
        if manifest_changed or manifest.rule_id in changed_rule_ids:
            selected.append(manifest)
    return tuple(selected)


def _changed_paths(root: Path, revision: str) -> set[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "diff", "--name-only", revision, "--"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"could not determine changed files from {revision!r}") from exc
    return {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def run_manifests(
    manifests: Iterable[RuleTestManifest],
    rule_sources: dict[str, str],
    *,
    engines: Iterable[ReferenceEngine] | None = None,
) -> RuleTestResult:
    """Run manifests against local reference engines."""
    selected = tuple(engines or (LibyaraEngine(), YaraXEngine()))
    loaded = tuple(manifests)
    fixtures: list[FixtureResult] = []
    for manifest in loaded:
        source = rule_sources.get(manifest.rule_id)
        if source is None:
            fixtures.extend(_missing_rule_results(manifest))
            continue
        for engine_name in manifest.engines:
            engine = next((item for item in selected if item.name == engine_name), None)
            if engine is None or not engine.available:
                fixtures.extend(_skipped_results(manifest, engine_name))
                continue
            fixtures.extend(_run_cases(engine, manifest, source))
    return RuleTestResult(loaded, tuple(fixtures))


def _run_cases(
    engine: ReferenceEngine,
    manifest: RuleTestManifest,
    source: str,
) -> list[FixtureResult]:
    results: list[FixtureResult] = []
    compile_error = _compile_budget_error(engine, manifest, source)
    for kind, cases in (("positive", manifest.positive), ("negative", manifest.negative)):
        for case in cases:
            fixture = manifest.path.parent / case.path
            try:
                data = fixture.read_bytes()
            except OSError as exc:
                results.append(FixtureResult(engine.name, kind, case.path, False, error=str(exc)))
                continue
            started = time.perf_counter()
            outcome = engine.evaluate(source, data)
            elapsed_ms = (time.perf_counter() - started) * 1000
            actual = tuple(sorted(outcome.matches or ()))
            passed = outcome.accepted and actual == tuple(sorted(case.expected))
            error = outcome.error
            if compile_error is not None:
                passed = False
                error = compile_error
            if (
                manifest.budgets.max_scan_ms is not None
                and elapsed_ms > manifest.budgets.max_scan_ms
            ):
                passed = False
                error = f"scan exceeded {manifest.budgets.max_scan_ms} ms"
            results.append(
                FixtureResult(
                    engine.name,
                    kind,
                    case.path,
                    passed,
                    expected=case.expected,
                    actual=actual,
                    elapsed_ms=elapsed_ms,
                    error=error,
                )
            )
    if compile_error is not None and not results:
        results.append(
            FixtureResult(
                engine.name,
                "compile",
                manifest.rule_id,
                False,
                error=compile_error,
            )
        )
    return results


def _compile_budget_error(
    engine: ReferenceEngine,
    manifest: RuleTestManifest,
    source: str,
) -> str | None:
    """Compile once when the manifest requests compile or memory accounting."""
    budgets = manifest.budgets
    if budgets.max_compile_ms is None and budgets.max_peak_memory_mb is None:
        return None

    before_memory = _peak_memory_mb()
    started = time.perf_counter()
    outcome = engine.evaluate(source)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if not outcome.accepted:
        return outcome.error or "compile failed"
    if budgets.max_compile_ms is not None and elapsed_ms > budgets.max_compile_ms:
        return f"compile exceeded {budgets.max_compile_ms} ms"
    if budgets.max_peak_memory_mb is not None:
        after_memory = _peak_memory_mb()
        if (
            before_memory is not None
            and after_memory is not None
            and after_memory - before_memory > budgets.max_peak_memory_mb
        ):
            return f"compile exceeded {budgets.max_peak_memory_mb} MB peak memory"
    return None


def _peak_memory_mb() -> float | None:
    """Return process peak RSS in MB when the platform exposes it."""
    try:
        import resource
    except ImportError:
        return None
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value / (1024 * 1024) if sys.platform == "darwin" else value / 1024


def _cases(value: object, field_name: str) -> tuple[FixtureCase, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"{field_name} must be an array")
    cases = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{field_name}[{index}] must be a mapping")
        expected = _string_tuple(item.get("expected", ()), f"{field_name}[{index}].expected")
        cases.append(
            FixtureCase(_string(item.get("path"), f"{field_name}[{index}].path"), expected)
        )
    return tuple(cases)


def _missing_rule_results(manifest: RuleTestManifest) -> list[FixtureResult]:
    return [
        FixtureResult(
            "rules", kind, case.path, False, error=f"rule source not found: {manifest.rule_id}"
        )
        for kind, cases in (("positive", manifest.positive), ("negative", manifest.negative))
        for case in cases
    ]


def _skipped_results(manifest: RuleTestManifest, engine: str) -> list[FixtureResult]:
    return [
        FixtureResult(engine, kind, case.path, True, skipped=True)
        for kind, cases in (("positive", manifest.positive), ("negative", manifest.negative))
        for case in cases
    ]


def _string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"{field_name} must be an array of strings")
    return tuple(_string(item, field_name) for item in value)


def _optional_nonnegative_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value
