"""Diagnostics provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Diagnostic, DiagnosticSeverity, Position, Range

from yaraast.parser.parser import Parser, ParserError
from yaraast.types.semantic_validator import SemanticValidator

if TYPE_CHECKING:
    from yaraast.types.semantic_validator import ValidationError


class DiagnosticsProvider:
    """Provides real-time diagnostics for YARA files."""

    def __init__(self) -> None:
        self.semantic_validator = SemanticValidator()

    def get_diagnostics(self, text: str) -> list[Diagnostic]:
        """
        Analyze YARA code and return diagnostics.

        Args:
            text: The YARA source code to analyze

        Returns:
            List of LSP diagnostics (errors and warnings)
        """
        diagnostics = []

        # Try to parse the file
        try:
            parser = Parser(text)
            ast = parser.parse()

            # If parsing succeeds, run semantic validation
            validation_result = self.semantic_validator.validate(ast)

            # Convert validation errors to LSP diagnostics
            for error in validation_result.errors:
                diagnostics.append(
                    self._validation_error_to_diagnostic(error, DiagnosticSeverity.Error)
                )

            for warning in validation_result.warnings:
                diagnostics.append(
                    self._validation_error_to_diagnostic(warning, DiagnosticSeverity.Warning)
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

        return diagnostics

    def _parser_error_to_diagnostic(self, error: ParserError) -> Diagnostic:
        """Convert a ParserError to an LSP Diagnostic."""
        line = error.line - 1 if error.line > 0 else 0
        col = error.column if error.column >= 0 else 0

        return Diagnostic(
            range=Range(
                start=Position(line=line, character=col),
                end=Position(line=line, character=col + 10),
            ),
            message=str(error),
            severity=DiagnosticSeverity.Error,
            source="yaraast-parser",
        )

    def _validation_error_to_diagnostic(
        self,
        error: ValidationError,
        severity: DiagnosticSeverity,
    ) -> Diagnostic:
        """Convert a ValidationError to an LSP Diagnostic."""
        if error.location:
            line = error.location.line - 1 if error.location.line > 0 else 0
            col = error.location.column if error.location.column >= 0 else 0
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

        return Diagnostic(
            range=diagnostic_range,
            message=message,
            severity=severity,
            source="yaraast-validator",
        )
