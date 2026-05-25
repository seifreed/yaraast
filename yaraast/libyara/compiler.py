"""Compiler that converts yaraast AST to libyara rules."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
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
    return dict(externals)


@dataclass
class CompilationResult:
    """Result of compiling AST to libyara."""

    success: bool
    compiled_rules: Any | None = None  # yara.Rules object
    errors: list[str] = None
    warnings: list[str] = None
    source_code: str | None = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


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
        kwargs: dict[str, Any] = {
            "externals": self.externals,
            "error_on_warning": error_on_warning,
        }
        if includes is None:
            kwargs["includes"] = False
            return kwargs
        kwargs["include_callback"] = self._include_callback(includes)
        return kwargs

    def _include_callback(self, includes: dict[str, str]) -> Callable[..., str | None]:
        def callback(requested_filename: str, *_args: Any) -> str | None:
            return includes.get(requested_filename)

        return callback

    def compile_file(
        self,
        filepath: str | Path,
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
        filepath = Path(filepath)

        if not filepath.exists():
            return CompilationResult(
                success=False,
                errors=[f"File not found: {filepath}"],
            )

        try:
            source = filepath.read_text(encoding="utf-8")
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
                compile_kwargs["include_callback"] = self._include_callback(includes)
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
        except (ValueError, TypeError, AttributeError):
            return False
