"""Service helpers for semantic CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, NoReturn

from yaraast.cli.utils import read_text
from yaraast.parser.source import parse_yara_source
from yaraast.types.semantic_validator import SemanticValidator
from yaraast.types.semantic_validator_core import ValidationError, ValidationResult


class DialectAwareParser:
    """Parser adapter for semantic validation across supported YARA dialects."""

    def parse(self, content: str) -> Any:
        return parse_yara_source(content)


def _process_file(file_path: Path, parser: Any, validator: Any) -> Any:
    """Process a single file and return results."""
    content = read_text(file_path)

    ast = parser.parse(content)

    # Set file location for better error reporting
    if hasattr(ast, "location") and ast.location:
        ast.location.file = str(file_path)

    # Validate semantics
    result = validator.validate(ast)

    # Add file path to all errors and warnings
    _add_file_to_issues(result.errors, file_path)
    _add_file_to_issues(result.warnings, file_path)

    return result


def _add_file_to_issues(issues, file_path: Path) -> None:
    """Add file path to all issues."""
    from yaraast.ast.base import Location

    for issue in issues:
        if issue.location:
            issue.location.file = str(file_path)
        else:
            issue.location = Location(line=1, column=1, file=str(file_path))


def _create_validation_context() -> dict[str, Any]:
    """Create validation context with parser and validator."""
    return {"parser": DialectAwareParser(), "validator": SemanticValidator()}


def _create_file_result(file_path: Path, result: ValidationResult) -> dict[str, object]:
    """Create result dictionary for a file."""
    return {
        "file": str(file_path),
        "is_valid": result.is_valid,
        "errors": [error.to_dict() for error in result.errors],
        "warnings": [warning.to_dict() for warning in result.warnings],
        "total_issues": result.total_issues,
    }


def _create_processing_error_result(file_path: Path, error: Exception) -> dict[str, object]:
    """Create a validation-style result for files that could not be processed."""
    from yaraast.ast.base import Location

    result = ValidationResult(is_valid=False)
    result.errors.append(
        ValidationError(
            message=str(error),
            location=Location(line=1, column=1, file=str(file_path)),
            error_type="processing",
        )
    )
    return _create_file_result(file_path, result)


def _exit_with_appropriate_code(
    total_errors: int,
    total_warnings: int,
    strict: bool,
) -> NoReturn:
    """Exit with appropriate code based on results."""
    exit_code = 0
    if total_errors > 0 or (strict and total_warnings > 0):
        exit_code = 1
    sys.exit(exit_code)
