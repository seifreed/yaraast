"""Repository checking built from the public parser and analyzers."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path, PurePosixPath
import re

from yaraast.analysis.best_practices import BestPracticesAnalyzer, Suggestion
from yaraast.ast.base import Location, YaraFile
from yaraast.baseline import Baseline
from yaraast.diagnostics import Diagnostic, DiagnosticResult, Severity
from yaraast.parser.source import parse_yara_source
from yaraast.project_config import ProjectConfig
from yaraast.types.semantic_validator import SemanticValidator
from yaraast.types.semantic_validator_core import ValidationError

_RULE_NAME_RE = re.compile(r"rule '([^']+)'")


def discover_rule_files(path: str | Path, config: ProjectConfig) -> tuple[Path, ...]:
    """Discover configured rule files below a path in stable order."""
    candidate = Path(path)
    if candidate.is_file():
        return (candidate,)
    if not candidate.is_dir():
        raise ValueError(f"check path must be a file or directory: {candidate}")

    files: set[Path] = set()
    for pattern in config.include:
        files.update(item for item in candidate.glob(pattern) if item.is_file())
    return tuple(
        sorted(
            (item for item in files if not _is_excluded(item, config.root, config.exclude)),
            key=lambda item: item.as_posix(),
        )
    )


def check_path(
    path: str | Path,
    config: ProjectConfig | None = None,
    *,
    profile: str = "default",
) -> DiagnosticResult:
    """Check configured rule files and return unified diagnostics."""
    candidate = Path(path)
    effective_config = config or ProjectConfig.load(candidate if candidate.is_dir() else candidate.parent, profile)
    files = discover_rule_files(candidate, effective_config)
    diagnostics: list[Diagnostic] = []
    for file_path in files:
        source_path = _display_path(file_path, effective_config.root)
        diagnostics.extend(_check_file(file_path, source_path, effective_config))
    result = DiagnosticResult(tuple(diagnostics))
    return apply_suppressions(result, effective_config)


def check_passes(result: DiagnosticResult, config: ProjectConfig) -> bool:
    """Apply quality-gate thresholds to a diagnostic result."""
    gate = config.quality_gate
    if len(result.errors) > gate.max_errors:
        return False
    if gate.max_warnings is not None and len(result.warnings) > gate.max_warnings:
        return False
    threshold = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2, Severity.NOTE: 3}[
        gate.fail_on
    ]
    return not any(_severity_rank(item.severity) <= threshold for item in result.diagnostics)


def apply_baseline(result: DiagnosticResult, path: str | Path | None) -> DiagnosticResult:
    """Filter a result through an optional baseline file."""
    return result if path is None else Baseline.load(path).filter(result)


def apply_suppressions(result: DiagnosticResult, config: ProjectConfig) -> DiagnosticResult:
    """Filter active project suppressions from a diagnostic result."""
    active = tuple(item for item in config.suppressions if item.active())
    if not active:
        return result
    return DiagnosticResult(
        tuple(
            diagnostic
            for diagnostic in result.diagnostics
            if not any(
                item.diagnostic == diagnostic.diagnostic_id
                and (item.rule is None or item.rule == diagnostic.rule_name)
                for item in active
            )
        )
    )


def _check_file(path: Path, source_path: str, config: ProjectConfig) -> list[Diagnostic]:
    try:
        source = path.read_text(encoding="utf-8")
        ast = parse_yara_source(source)
    except Exception as exc:
        return [_processing_diagnostic(source_path, str(exc))]

    diagnostics = _semantic_diagnostics(ast, source_path, config)
    diagnostics.extend(_practice_diagnostics(ast, source_path, config))
    diagnostics.extend(_policy_diagnostics(ast, source_path, config))
    return diagnostics


def _semantic_diagnostics(
    ast: YaraFile,
    source_path: str,
    config: ProjectConfig,
) -> list[Diagnostic]:
    result = SemanticValidator().validate(ast)
    return [
        _validation_diagnostic(issue, source_path, config)
        for issue in result.errors + result.warnings
    ]


def _practice_diagnostics(
    ast: YaraFile,
    source_path: str,
    config: ProjectConfig,
) -> list[Diagnostic]:
    analyzer = BestPracticesAnalyzer()
    report = analyzer.analyze(ast)
    locations = {rule.name: rule.location for rule in ast.rules}
    return [
        _suggestion_diagnostic(item, source_path, locations.get(item.rule_name), config)
        for item in report.suggestions
    ]


def _policy_diagnostics(
    ast: YaraFile,
    source_path: str,
    config: ProjectConfig,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    policy = config.policy
    for rule in ast.rules:
        location = rule.location
        if policy.max_strings_per_rule is not None and len(rule.strings) > policy.max_strings_per_rule:
            diagnostics.append(
                _new_diagnostic(
                    "YARA204",
                    Severity.ERROR,
                    "policy",
                    f"Rule '{rule.name}' has too many strings ({len(rule.strings)} > {policy.max_strings_per_rule})",
                    source_path,
                    location,
                    rule_name=rule.name,
                    config=config,
                )
            )
    return diagnostics


def _validation_diagnostic(
    issue: ValidationError,
    source_path: str,
    config: ProjectConfig,
) -> Diagnostic:
    diagnostic_id = _validation_id(issue.message)
    return _new_diagnostic(
        diagnostic_id,
        Severity.WARNING if issue.severity == "warning" else Severity.ERROR,
        "semantic",
        issue.message,
        source_path,
        issue.location,
        suggestion=issue.suggestion,
        config=config,
    )


def _suggestion_diagnostic(
    suggestion: Suggestion,
    source_path: str,
    location: Location | None,
    config: ProjectConfig,
) -> Diagnostic:
    severity = Severity(suggestion.severity)
    return _new_diagnostic(
        _suggestion_id(suggestion),
        severity,
        suggestion.category,
        suggestion.message,
        source_path,
        location,
        rule_name=suggestion.rule_name,
        suggestion=suggestion.location,
        config=config,
    )


def _new_diagnostic(
    diagnostic_id: str,
    severity: Severity,
    category: str,
    message: str,
    source_path: str,
    location: Location | None,
    *,
    rule_name: str | None = None,
    suggestion: str | None = None,
    config: ProjectConfig,
) -> Diagnostic:
    start_line = location.line if location else 1
    start_column = location.column if location else 1
    end_line = (location.end_line or start_line) if location else start_line
    end_column = (location.end_column or start_column) if location else start_column
    return Diagnostic(
        diagnostic_id,
        config.severity.get(diagnostic_id, severity),
        category,
        message,
        source_path,
        start_line,
        start_column,
        end_line,
        end_column,
        rule_name=rule_name,
        dialect=config.dialect,
        suggestion=suggestion,
    )


def _processing_diagnostic(source_path: str, message: str) -> Diagnostic:
    return Diagnostic("YARA001", Severity.ERROR, "syntax", message, source_path, 1, 1, 1, 1)


def _validation_id(message: str) -> str:
    lowered = message.lower()
    if "undefined string" in lowered:
        return "YARA101"
    if "duplicate string" in lowered:
        return "YARA102"
    if "unreferenced string" in lowered:
        return "YARA103"
    if "identifier" in lowered:
        return "YARA202"
    return "YARA001"


def _suggestion_id(suggestion: Suggestion) -> str:
    message = suggestion.message.lower()
    if "unused" in message:
        return "YARA103"
    if "duplicate rule" in message:
        return "YARA202"
    if "regex" in message:
        return "YARA301"
    if "hex string" in message and "wildcard" in message:
        return "YARA302"
    return "YARA901"


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_excluded(path: Path, root: Path, patterns: Iterable[str]) -> bool:
    relative = PurePosixPath(path.relative_to(root).as_posix())
    return any(relative.match(pattern) for pattern in patterns)


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.ERROR: 0,
        Severity.WARNING: 1,
        Severity.INFO: 2,
        Severity.NOTE: 3,
    }[severity]

