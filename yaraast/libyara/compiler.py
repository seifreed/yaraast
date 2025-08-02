"""Compiler that converts yaraast AST to libyara rules."""

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

from yaraast.ast.base import YaraFile
from yaraast.codegen import CodeGenerator


@dataclass
class CompilationResult:
    """Result of compiling AST to libyara."""
    success: bool
    compiled_rules: Optional[Any] = None  # yara.Rules object
    errors: List[str] = None
    warnings: List[str] = None
    source_code: Optional[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class LibyaraCompiler:
    """Compile yaraast AST to libyara rules."""

    def __init__(self, externals: Optional[Dict[str, Any]] = None):
        """Initialize compiler.

        Args:
            externals: External variables for YARA compilation
        """
        if not YARA_AVAILABLE:
            raise ImportError(
                "yara-python is not installed. "
                "Install it with: pip install yara-python"
            )

        self.externals = externals or {}
        self.code_generator = CodeGenerator()

    def compile_ast(self, ast: YaraFile,
                    includes: Optional[Dict[str, str]] = None,
                    error_on_warning: bool = False) -> CompilationResult:
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
                source_code,
                includes=includes,
                error_on_warning=error_on_warning
            )

        except Exception as e:
            return CompilationResult(
                success=False,
                errors=[f"AST compilation error: {str(e)}"],
                source_code=source_code if 'source_code' in locals() else None
            )

    def compile_source(self, source: str,
                      includes: Optional[Dict[str, str]] = None,
                      error_on_warning: bool = False) -> CompilationResult:
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
            if error_data.get('warning', False):
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
                error_callback=error_callback
            )

            # Check if compilation succeeded
            if errors or (error_on_warning and warnings):
                return CompilationResult(
                    success=False,
                    errors=errors,
                    warnings=warnings,
                    source_code=source
                )

            return CompilationResult(
                success=True,
                compiled_rules=compiler,
                warnings=warnings,
                source_code=source
            )

        except yara.SyntaxError as e:
            errors.append(f"Syntax error: {str(e)}")
        except yara.Error as e:
            errors.append(f"Compilation error: {str(e)}")
        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")

        return CompilationResult(
            success=False,
            errors=errors,
            warnings=warnings,
            source_code=source
        )

    def compile_file(self, filepath: Union[str, Path],
                    error_on_warning: bool = False) -> CompilationResult:
        """Compile YARA file using libyara.

        Args:
            filepath: Path to YARA file
            error_on_warning: Treat warnings as errors

        Returns:
            CompilationResult with compiled rules or errors
        """
        filepath = Path(filepath)

        if not filepath.exists():
            return CompilationResult(
                success=False,
                errors=[f"File not found: {filepath}"]
            )

        try:
            source = filepath.read_text()
            return self.compile_source(source, error_on_warning=error_on_warning)
        except Exception as e:
            return CompilationResult(
                success=False,
                errors=[f"Error reading file: {str(e)}"]
            )

    def save_compiled_rules(self, rules: Any, filepath: Union[str, Path]) -> bool:
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
