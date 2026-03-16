"""Diagnostics provider for YARA Language Server."""

from __future__ import annotations

import contextlib
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from lsprotocol.types import (
    Diagnostic,
    DiagnosticRelatedInformation,
    DiagnosticSeverity,
    Position,
    Range,
)

from yaraast.dialects import YaraDialect
from yaraast.libyara.compiler import YARA_AVAILABLE, LibyaraCompiler
from yaraast.lsp.diagnostics_helpers import (
    compiler_error_to_diagnostic as helper_compiler_error_to_diagnostic,
)
from yaraast.lsp.diagnostics_helpers import error_code as helper_error_code
from yaraast.lsp.diagnostics_helpers import metadata_for_error as helper_metadata_for_error
from yaraast.lsp.diagnostics_helpers import (
    parser_error_to_diagnostic as helper_parser_error_to_diagnostic,
)
from yaraast.lsp.diagnostics_helpers import patches_for_error as helper_patches_for_error
from yaraast.lsp.diagnostics_helpers import related_info as helper_related_info
from yaraast.lsp.diagnostics_helpers import (
    suggest_builtin_functions as helper_suggest_builtin_functions,
)
from yaraast.lsp.runtime import LspRuntime
from yaraast.parser.parser import ParserError
from yaraast.types.semantic_validator import SemanticValidator
from yaraast.unified_parser import UnifiedParser

if TYPE_CHECKING:
    from yaraast.types.semantic_validator import ValidationError


@dataclass(slots=True)
class DiagnosticPatch:
    """Text replacement attached to a diagnostic."""

    range: Range
    replacement: str

    def to_dict(self) -> dict[str, object]:
        return {"range": self.range, "replacement": self.replacement}


@dataclass(slots=True)
class DiagnosticData:
    """Structured payload for code actions and richer diagnostics."""

    code: str
    severity: str
    error_type: str
    suggestion: str | None = None
    patches: list[DiagnosticPatch] | None = None
    metadata: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "error_type": self.error_type,
            "suggestion": self.suggestion,
            "patches": [patch.to_dict() for patch in self.patches or []],
            "metadata": self.metadata or {},
        }


class DiagnosticsProvider:
    """Provides real-time diagnostics for YARA files."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime
        self.semantic_validator = SemanticValidator()
        self.compiler = LibyaraCompiler() if YARA_AVAILABLE else None

    def get_diagnostics(self, text: str, uri: str | None = None) -> list[Diagnostic]:
        """
        Analyze YARA code and return diagnostics.

        Args:
            text: The YARA source code to analyze

        Returns:
            List of LSP diagnostics (errors and warnings)
        """
        ctx = self.runtime.ensure_document(uri, text) if self.runtime and uri else None
        if ctx is not None:
            cached = ctx.get_cached("diagnostics")
            if cached is not None:
                return cached

        diagnostics = []
        started = time.perf_counter()

        # Try to parse the file
        try:
            dialect = ctx.dialect() if ctx is not None else None
            ast = UnifiedParser(text, dialect=dialect).parse()

            if dialect not in {None, YaraDialect.YARA}:
                validation_result = None
            else:
                validation_result = self.semantic_validator.validate(ast)

            # Convert validation errors to LSP diagnostics
            if validation_result is not None:
                for error in validation_result.errors:
                    diagnostics.append(
                        self._validation_error_to_diagnostic(error, DiagnosticSeverity.Error)
                    )

                for warning in validation_result.warnings:
                    diagnostics.append(
                        self._validation_error_to_diagnostic(warning, DiagnosticSeverity.Warning)
                    )

            if (
                self.compiler is not None
                and dialect in {None, YaraDialect.YARA}
                and (validation_result is None or not validation_result.errors)
            ):
                compilation = self.compiler.compile_source(text)
                if not compilation.success:
                    diagnostics.extend(
                        self._compiler_error_to_diagnostic(error) for error in compilation.errors
                    )

        except ParserError as e:
            # Convert parser errors to LSP diagnostics
            diagnostics.append(self._parser_error_to_diagnostic(e))

        except Exception as e:
            # Catch any other errors and report them
            diagnostics.append(
                Diagnostic(
                    range=Range(
                        start=Position(line=0, character=0),
                        end=Position(line=0, character=1),
                    ),
                    message=f"Unexpected error: {e!s}",
                    severity=DiagnosticSeverity.Error,
                    source="yaraast",
                )
            )

        # Configurable metadata validation
        if self.runtime and self.runtime.config.metadata_validation:
            with contextlib.suppress(Exception):
                diagnostics.extend(self._validate_metadata(ast, self.runtime.config))

        # Configurable rule name validation
        if self.runtime and self.runtime.config.rule_name_validation:
            with contextlib.suppress(Exception):
                diagnostics.extend(
                    self._validate_rule_names(ast, self.runtime.config.rule_name_validation)
                )

        if ctx is not None:
            ctx.set_cached("diagnostics", diagnostics)
        if self.runtime is not None:
            self.runtime.record_latency("diagnostics", (time.perf_counter() - started) * 1000.0)
        return diagnostics

    def _parser_error_to_diagnostic(self, error: ParserError) -> Diagnostic:
        return helper_parser_error_to_diagnostic(error, DiagnosticData)

    def _compiler_error_to_diagnostic(self, message: str) -> Diagnostic:
        return helper_compiler_error_to_diagnostic(message, DiagnosticData)

    def _validation_error_to_diagnostic(
        self,
        error: ValidationError,
        severity: DiagnosticSeverity,
    ) -> Diagnostic:
        """Convert a ValidationError to an LSP Diagnostic."""
        if error.location:
            line = error.location.line - 1 if error.location.line > 0 else 0
            col = error.location.column - 1 if error.location.column > 0 else 0
            diagnostic_range = Range(
                start=Position(line=line, character=col),
                end=Position(line=line, character=col + 10),
            )
        else:
            # No location information
            diagnostic_range = Range(
                start=Position(line=0, character=0),
                end=Position(line=0, character=1),
            )

        message = error.message
        if error.suggestion:
            message += f"\n💡 Suggestion: {error.suggestion}"

        code = self._error_code(error)
        patches = self._patches_for_error(error, diagnostic_range)
        return Diagnostic(
            range=diagnostic_range,
            message=message,
            severity=severity,
            code=code,
            related_information=self._related_info(error, diagnostic_range),
            source="yaraast-validator",
            data=DiagnosticData(
                code=code,
                severity=error.severity,
                error_type=error.error_type,
                suggestion=error.suggestion,
                patches=patches,
                metadata=self._metadata_for_error(error),
            ).to_dict(),
        )

    def _error_code(self, error: ValidationError) -> str:
        return helper_error_code(error)

    def _related_info(
        self,
        error: ValidationError,
        diagnostic_range: Range,
    ) -> list[DiagnosticRelatedInformation] | None:
        return helper_related_info(error, diagnostic_range)

    def _patches_for_error(
        self,
        error: ValidationError,
        diagnostic_range: Range,
    ) -> list[DiagnosticPatch]:
        return helper_patches_for_error(error, diagnostic_range, DiagnosticPatch)

    def _metadata_for_error(self, error: ValidationError) -> dict[str, object]:
        return helper_metadata_for_error(error)

    def _validate_metadata(self, ast: Any, config: Any) -> list[Diagnostic]:
        """Validate rule metadata against configurable validation rules."""
        results: list[Diagnostic] = []
        if ast is None or not hasattr(ast, "rules"):
            return results
        type_checkers = {
            "string": lambda v: isinstance(v, str),
            "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "bool": lambda v: isinstance(v, bool),
            "boolean": lambda v: isinstance(v, bool),
        }
        for rule in ast.rules:
            # Build a dict of meta entries for lookup
            meta_dict: dict[str, Any] = {}
            meta = getattr(rule, "meta", None)
            if isinstance(meta, dict):
                meta_dict = dict(meta)
            elif isinstance(meta, list):
                for entry in meta:
                    key = getattr(entry, "key", None) or getattr(entry, "identifier", None)
                    val = getattr(entry, "value", None)
                    if key is not None:
                        meta_dict[key] = val

            rule_line = 0
            loc = getattr(rule, "location", None)
            if loc is not None:
                line_val = getattr(loc, "line", None)
                if line_val is not None and line_val > 0:
                    rule_line = line_val - 1

            for validation_rule in config.metadata_validation:
                identifier = validation_rule.get("identifier")
                if not identifier:
                    continue
                required = validation_rule.get("required", False)
                expected_type = validation_rule.get("type")

                if required and identifier not in meta_dict:
                    results.append(
                        Diagnostic(
                            range=Range(
                                start=Position(line=rule_line, character=0),
                                end=Position(line=rule_line, character=1),
                            ),
                            message=f"Rule '{rule.name}' is missing required metadata '{identifier}'",
                            severity=DiagnosticSeverity.Warning,
                            source="yaraast-metadata",
                        )
                    )
                elif identifier in meta_dict and expected_type:
                    checker = type_checkers.get(expected_type.lower())
                    if checker and not checker(meta_dict[identifier]):
                        results.append(
                            Diagnostic(
                                range=Range(
                                    start=Position(line=rule_line, character=0),
                                    end=Position(line=rule_line, character=1),
                                ),
                                message=f"Metadata '{identifier}' in rule '{rule.name}' should be of type '{expected_type}'",
                                severity=DiagnosticSeverity.Warning,
                                source="yaraast-metadata",
                            )
                        )
        return results

    def _validate_rule_names(self, ast: Any, pattern_str: str) -> list[Diagnostic]:
        """Validate rule names against a configurable regex pattern."""
        results: list[Diagnostic] = []
        if ast is None or not hasattr(ast, "rules"):
            return results
        try:
            pattern = re.compile(pattern_str)
        except re.error:
            return results
        for rule in ast.rules:
            if not pattern.match(rule.name):
                rule_line = 0
                loc = getattr(rule, "location", None)
                if loc is not None:
                    line_val = getattr(loc, "line", None)
                    if line_val is not None and line_val > 0:
                        rule_line = line_val - 1
                results.append(
                    Diagnostic(
                        range=Range(
                            start=Position(line=rule_line, character=0),
                            end=Position(line=rule_line, character=1),
                        ),
                        message=f"Rule name '{rule.name}' does not match pattern '{pattern_str}'",
                        severity=DiagnosticSeverity.Warning,
                        source="yaraast-naming",
                    )
                )
        return results

    def _suggest_builtin_functions(self, function_name: str) -> list[str]:
        return helper_suggest_builtin_functions(function_name)
