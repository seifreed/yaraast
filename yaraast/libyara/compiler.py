"""Compiler that converts yaraast AST to libyara rules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

from yaraast.codegen import CodeGenerator

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


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

    def __init__(self, externals: dict[str, Any] | None = None):
        """Initialize compiler.

        Args:
            externals: External variables for YARA compilation
        """
        if not YARA_AVAILABLE:
            raise ImportError(
                "yara-python is not installed. " "Install it with: pip install yara-python"
            )

        self.externals = externals or {}
        self.code_generator = CodeGenerator()

    def compile_ast(
        self, ast: YaraFile, includes: dict[str, str] | None = None, error_on_warning: bool = False
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
            # Generate YARA source code from AST
            source_code = self.code_generator.generate(ast)

            # Compile using libyara
            return self.compile_source(
                source_code, includes=includes, error_on_warning=error_on_warning
            )

        except Exception as e:
            return CompilationResult(
                success=False,
                errors=[f"AST compilation error: {e!s}"],
                source_code=source_code if "source_code" in locals() else None,
            )

    def compile_source(
        self, source: str, includes: dict[str, str] | None = None, error_on_warning: bool = False
    ) -> CompilationResult:
        """Compile YARA source code using libyara.

        Args:
            source: YARA source code
            includes: Dictionary mapping include names to their content
            error_on_warning: Treat warnings as errors

        Returns:
            CompilationResult with compiled rules or errors
        """
        errors = []
        warnings = []

        def error_callback(error_data):
            """Callback for compilation errors."""
            if error_data.get("warning", False):
                warnings.append(
                    f"{error_data.get('filename', 'unknown')}:"
                    f"{error_data.get('line_number', 0)}: "
                    f"{error_data.get('message', 'unknown warning')}"
                )
            else:
                errors.append(
                    f"{error_data.get('filename', 'unknown')}:"
                    f"{error_data.get('line_number', 0)}: "
                    f"{error_data.get('message', 'unknown error')}"
                )

        try:
            # Create compiler
            compiler = yara.compile(
                source=source,
                externals=self.externals,
                includes=includes or {},
                error_on_warning=error_on_warning,
                error_callback=error_callback,
            )

            # Check if compilation succeeded
            if errors or (error_on_warning and warnings):
                return CompilationResult(
                    success=False, errors=errors, warnings=warnings, source_code=source
                )

            return CompilationResult(
                success=True, compiled_rules=compiler, warnings=warnings, source_code=source
            )

        except yara.SyntaxError as e:
            errors.append(f"Syntax error: {e!s}")
        except yara.Error as e:
            errors.append(f"Compilation error: {e!s}")
        except Exception as e:
            errors.append(f"Unexpected error: {e!s}")

        return CompilationResult(
            success=False, errors=errors, warnings=warnings, source_code=source
        )

    def compile_file(
        self, filepath: str | Path, error_on_warning: bool = False
    ) -> CompilationResult:
        """Compile YARA file using libyara.

        Args:
            filepath: Path to YARA file
            error_on_warning: Treat warnings as errors

        Returns:
            CompilationResult with compiled rules or errors
        """
        filepath = Path(filepath)

        if not filepath.exists():
            return CompilationResult(success=False, errors=[f"File not found: {filepath}"])

        try:
            source = filepath.read_text()
            return self.compile_source(source, error_on_warning=error_on_warning)
        except Exception as e:
            return CompilationResult(success=False, errors=[f"Error reading file: {e!s}"])

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
        except Exception:
            return False
