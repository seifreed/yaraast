"""Compiler that converts yaraast AST to libyara rules."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.libyara._availability import is_missing_yara_import
from yaraast.libyara._paths import require_file_path

try:
    import yara

    YARA_AVAILABLE = True
except ImportError as exc:
    if not is_missing_yara_import(exc):
        raise
    yara = None
    YARA_AVAILABLE = False

from yaraast.codegen.generator import CodeGenerator
from yaraast.libyara.compatibility import ensure_libyara_compatible_ast

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


def normalize_libyara_externals(externals: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize libyara external variables."""
    if externals is None:
        return {}
    if not isinstance(externals, dict):
        msg = "libyara externals must be a dictionary"
        raise TypeError(msg)
    normalized: dict[str, Any] = {}
    for name, value in externals.items():
        if not isinstance(name, str):
            msg = "libyara external names must be strings"
            raise TypeError(msg)
        if not name.strip():
            msg = "libyara external names must not be empty"
            raise ValueError(msg)
        normalized[name] = value
    return normalized


def normalize_libyara_includes(includes: dict[str, str] | None) -> dict[str, str] | None:
    """Normalize virtual include mappings passed to libyara."""
    if includes is None:
        return None
    if not isinstance(includes, dict):
        msg = "libyara includes must be a dictionary"
        raise TypeError(msg)
    normalized: dict[str, str] = {}
    for name, content in includes.items():
        if not isinstance(name, str):
            msg = "libyara include names must be strings"
            raise TypeError(msg)
        if not name.strip():
            msg = "libyara include names must not be empty"
            raise ValueError(msg)
        if not isinstance(content, str):
            msg = "libyara include contents must be strings"
            raise TypeError(msg)
        normalized[name] = content
    return normalized


def require_error_on_warning(error_on_warning: object) -> bool:
    """Validate the libyara warning policy flag."""
    if not isinstance(error_on_warning, bool):
        msg = "error_on_warning must be a boolean"
        raise TypeError(msg)
    return error_on_warning


@dataclass
class CompilationResult:
    """Result of compiling AST to libyara."""

    success: bool
    compiled_rules: Any | None = None  # yara.Rules object
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_code: str | None = None


class LibyaraCompiler:
    """Compile yaraast AST to libyara rules."""

    def __init__(self, externals: dict[str, Any] | None = None) -> None:
        """Initialize compiler.

        Args:
            externals: External variables for YARA compilation

        """
        if not YARA_AVAILABLE:
            msg = "yara-python is not installed. Install it with: pip install yara-python"
            raise ImportError(
                msg,
            )

        self.externals = normalize_libyara_externals(externals)
        self.code_generator = CodeGenerator()

    def compile_ast(
        self,
        ast: YaraFile,
        includes: dict[str, str] | None = None,
        error_on_warning: bool = False,
    ) -> CompilationResult:
        """Compile AST to libyara rules.

        Args:
            ast: The YARA AST to compile
            includes: Dictionary mapping include names to their content
            error_on_warning: Treat warnings as errors

        Returns:
            CompilationResult with compiled rules or errors

        """
        try:
            ensure_libyara_compatible_ast(ast, action="compile")

            # Generate YARA source code from AST
            source_code = self.code_generator.generate(ast)

            # Compile using libyara
            return self.compile_source(
                source_code,
                includes=includes,
                error_on_warning=error_on_warning,
            )

        except Exception as e:
            return CompilationResult(
                success=False,
                errors=[f"AST compilation error: {e!s}"],
                source_code=source_code if "source_code" in locals() else None,
            )

    def compile_source(
        self,
        source: str,
        includes: dict[str, str] | None = None,
        error_on_warning: bool = False,
    ) -> CompilationResult:
        """Compile YARA source code using libyara.

        Args:
            source: YARA source code
            includes: Dictionary mapping include names to their content
            error_on_warning: Treat warnings as errors

        Returns:
            CompilationResult with compiled rules or errors

        """
        try:
            compile_kwargs = self._compile_kwargs(includes, error_on_warning)
        except (TypeError, ValueError) as exc:
            return CompilationResult(
                success=False,
                errors=[str(exc)],
                source_code=source if isinstance(source, str) else None,
            )

        try:
            if "\x00" in source:
                compiled = self._compile_via_tempfile(source, includes, error_on_warning)
            else:
                compiled = yara.compile(
                    source=source,
                    **compile_kwargs,
                )

            return CompilationResult(
                success=True,
                compiled_rules=compiled,
                source_code=source,
            )

        except yara.SyntaxError as e:
            return CompilationResult(
                success=False, errors=[f"Syntax error: {e!s}"], source_code=source
            )
        except yara.Error as e:
            return CompilationResult(
                success=False, errors=[f"Compilation error: {e!s}"], source_code=source
            )
        except Exception as e:
            return CompilationResult(
                success=False, errors=[f"Unexpected error: {e!s}"], source_code=source
            )

    def _compile_via_tempfile(
        self,
        source: str,
        includes: dict[str, str] | None,
        error_on_warning: bool,
    ) -> Any:
        """Compile source containing null bytes by writing to a temporary file."""
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".yar",
            delete=False,
        ) as f:
            f.write(source)
            temp_path = f.name

        try:
            return yara.compile(
                filepath=temp_path,
                **self._compile_kwargs(includes, error_on_warning),
            )
        finally:
            os.unlink(temp_path)

    def _compile_kwargs(
        self,
        includes: dict[str, str] | None,
        error_on_warning: bool,
    ) -> dict[str, Any]:
        error_on_warning = require_error_on_warning(error_on_warning)
        kwargs: dict[str, Any] = {
            "externals": self.externals,
            "error_on_warning": error_on_warning,
        }
        if includes is None:
            kwargs["includes"] = False
            return kwargs
        normalized_includes = normalize_libyara_includes(includes)
        if normalized_includes is None:
            kwargs["includes"] = False
            return kwargs
        kwargs["include_callback"] = self._include_callback(normalized_includes)
        return kwargs

    def _include_callback(self, includes: dict[str, str]) -> Callable[..., str | None]:
        def callback(requested_filename: str, *_args: Any) -> str | None:
            return includes.get(requested_filename)

        return callback

    def compile_file(
        self,
        filepath: str | PathLike[str],
        error_on_warning: bool = False,
        includes: dict[str, str] | None = None,
    ) -> CompilationResult:
        """Compile YARA file using libyara.

        Args:
            filepath: Path to YARA file
            error_on_warning: Treat warnings as errors
            includes: Dictionary mapping include names to their content

        Returns:
            CompilationResult with compiled rules or errors

        """
        try:
            filepath = require_file_path(filepath, "filepath")
        except (TypeError, ValueError) as exc:
            return CompilationResult(success=False, errors=[str(exc)])

        if not filepath.exists():
            return CompilationResult(
                success=False,
                errors=[f"File not found: {filepath}"],
            )

        try:
            source = filepath.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return CompilationResult(
                success=False,
                errors=["YARA file must contain valid UTF-8 text"],
            )
        except Exception as e:
            return CompilationResult(
                success=False,
                errors=[f"Error reading file: {e!s}"],
            )

        try:
            compile_kwargs: dict[str, Any] = {
                "externals": self.externals,
                "error_on_warning": error_on_warning,
            }
            if includes is not None:
                normalized_includes = normalize_libyara_includes(includes)
                if normalized_includes is None:
                    compile_kwargs["includes"] = False
                else:
                    compile_kwargs["include_callback"] = self._include_callback(normalized_includes)
            compiled = yara.compile(
                filepath=str(filepath),
                **compile_kwargs,
            )
            return CompilationResult(
                success=True,
                compiled_rules=compiled,
                source_code=source,
            )
        except yara.SyntaxError as e:
            return CompilationResult(
                success=False, errors=[f"Syntax error: {e!s}"], source_code=source
            )
        except yara.Error as e:
            return CompilationResult(
                success=False, errors=[f"Compilation error: {e!s}"], source_code=source
            )
        except (TypeError, ValueError) as e:
            return CompilationResult(success=False, errors=[str(e)], source_code=source)
        except Exception as e:
            return CompilationResult(
                success=False, errors=[f"Unexpected error: {e!s}"], source_code=source
            )

    def save_compiled_rules(self, rules: Any, filepath: str | Path) -> bool:
        """Save compiled rules to file.

        Args:
            rules: Compiled yara.Rules object
            filepath: Output file path

        Returns:
            True if successful

        """
        try:
            rules.save(str(filepath))
            return True
        except (ValueError, TypeError, AttributeError, OSError, yara.Error):
            return False
