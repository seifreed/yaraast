"""Direct AST to libyara compilation bypassing text generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.libyara.ast_optimizer import ASTOptimizer

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False


if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile


@dataclass
class OptimizationStats:
    """Statistics about AST optimizations performed."""

    rules_optimized: int = 0
    strings_optimized: int = 0
    conditions_simplified: int = 0
    dead_code_removed: int = 0
    constant_folded: int = 0


@dataclass
class DirectCompilationResult:
    """Result of direct AST compilation."""

    success: bool
    compiled_rules: Any | None = None  # yara.Rules object
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    optimization_stats: OptimizationStats | None = None
    compilation_time: float = 0.0
    ast_node_count: int = 0
    generated_source: str | None = None  # For debugging

    @property
    def optimized(self) -> bool:
        """Check if optimizations were applied."""
        if not self.optimization_stats:
            return False
        stats = self.optimization_stats
        return (
            stats.rules_optimized > 0
            or stats.strings_optimized > 0
            or stats.conditions_simplified > 0
            or stats.dead_code_removed > 0
            or stats.constant_folded > 0
        )


class DirectASTCompiler:
    """Compile yaraast AST directly to libyara rules without text generation."""

    def __init__(
        self,
        externals: dict[str, Any] | None = None,
        enable_optimization: bool = True,
        debug_mode: bool = False,
    ) -> None:
        """Initialize direct compiler.

        Args:
            externals: External variables for YARA compilation
            enable_optimization: Apply AST optimizations before compilation
            debug_mode: Generate source code for debugging

        """
        if not YARA_AVAILABLE:
            msg = "yara-python is not installed. Install it with: pip install yara-python"
            raise ImportError(
                msg,
            )

        self.externals = externals or {}
        self.enable_optimization = enable_optimization
        self.debug_mode = debug_mode
        self.optimizer = ASTOptimizer() if enable_optimization else None

        # Compile-time statistics
        self.compilation_stats = {
            "total_compilations": 0,
            "successful_compilations": 0,
            "failed_compilations": 0,
            "total_rules_compiled": 0,
            "total_optimization_time": 0.0,
            "total_compilation_time": 0.0,
        }

    def compile_ast(
        self,
        ast: YaraFile,
        includes: dict[str, str] | None = None,
        error_on_warning: bool = False,
    ) -> DirectCompilationResult:
        """Compile AST directly to libyara rules.

        Args:
            ast: The YARA AST to compile
            includes: Dictionary mapping include names to their content
            error_on_warning: Treat warnings as errors

        Returns:
            DirectCompilationResult with compiled rules or errors

        """
        import time

        start_time = time.time()

        try:
            self.compilation_stats["total_compilations"] += 1

            # Step 1: Apply optimizations if enabled
            optimization_stats = None
            if self.enable_optimization and self.optimizer:
                opt_start = time.time()
                optimized_ast = self.optimizer.optimize(ast)
                opt_time = time.time() - opt_start

                optimization_stats = self.optimizer.stats
                self.compilation_stats["total_optimization_time"] += opt_time
            else:
                optimized_ast = ast

            # Step 2: Generate optimized YARA source
            source_code = self._generate_optimized_source(optimized_ast)

            # Step 3: Count AST nodes for statistics
            node_count = self._count_ast_nodes(optimized_ast)

            # Step 4: Compile using libyara with generated source
            # (For now, still uses text compilation but with optimized AST)
            compile_result = self._compile_optimized_source(
                source_code,
                includes=includes,
                error_on_warning=error_on_warning,
            )

            compilation_time = time.time() - start_time
            self.compilation_stats["total_compilation_time"] += compilation_time

            if compile_result.success:
                self.compilation_stats["successful_compilations"] += 1
                self.compilation_stats["total_rules_compiled"] += len(
                    optimized_ast.rules,
                )
            else:
                self.compilation_stats["failed_compilations"] += 1

            return DirectCompilationResult(
                success=compile_result.success,
                compiled_rules=compile_result.compiled_rules,
                errors=compile_result.errors,
                warnings=compile_result.warnings,
                optimization_stats=optimization_stats,
                compilation_time=compilation_time,
                ast_node_count=node_count,
                generated_source=source_code if self.debug_mode else None,
            )

        except Exception as e:
            compilation_time = time.time() - start_time
            self.compilation_stats["failed_compilations"] += 1

            return DirectCompilationResult(
                success=False,
                errors=[f"Direct compilation error: {e!s}"],
                compilation_time=compilation_time,
            )

    def compile_to_yara(self, ast: YaraFile) -> str:
        """Compile AST to YARA source code.

        Args:
            ast: The YARA AST to compile

        Returns:
            Generated YARA source code

        """
        return self._generate_optimized_source(ast)

    def _generate_optimized_source(self, ast: YaraFile) -> str:
        """Generate YARA source from optimized AST."""
        from yaraast.codegen import CodeGenerator

        generator = CodeGenerator()
        return generator.generate(ast)

    def _compile_optimized_source(
        self,
        source: str,
        includes: dict[str, str] | None = None,
        error_on_warning: bool = False,
    ) -> DirectCompilationResult:
        """Compile optimized source using libyara."""
        from yaraast.libyara.compiler import LibyaraCompiler

        compiler = LibyaraCompiler(externals=self.externals)
        result = compiler.compile_source(source, includes, error_on_warning)

        return DirectCompilationResult(
            success=result.success,
            compiled_rules=result.compiled_rules,
            errors=result.errors,
            warnings=result.warnings,
        )

    def _count_ast_nodes(self, ast: YaraFile) -> int:
        """Count total AST nodes."""
        count = 1  # YaraFile itself

        def count_node(node: ASTNode) -> int:
            node_count = 1
            for child in node.children():
                node_count += count_node(child)
            return node_count

        for child in ast.children():
            count += count_node(child)

        return count

    def get_compilation_stats(self) -> dict[str, Any]:
        """Get compilation statistics."""
        return self.compilation_stats.copy()

    def reset_stats(self) -> None:
        """Reset compilation statistics."""
        self.compilation_stats = {
            "total_compilations": 0,
            "successful_compilations": 0,
            "failed_compilations": 0,
            "total_rules_compiled": 0,
            "total_optimization_time": 0.0,
            "total_compilation_time": 0.0,
        }


class OptimizedMatcher:
    """Optimized matcher using AST structure for efficient scanning."""

    def __init__(self, rules: Any, ast: YaraFile | None = None) -> None:
        """Initialize optimized matcher.

        Args:
            rules: Compiled yara.Rules object
            ast: Original AST for optimization hints

        """
        if not YARA_AVAILABLE:
            msg = "yara-python is not installed."
            raise ImportError(msg)

        self.rules = rules
        self.ast = ast
        self.scan_stats = {
            "total_scans": 0,
            "successful_scans": 0,
            "total_scan_time": 0.0,
            "total_data_scanned": 0,
        }

    def scan(
        self,
        data: bytes | str | Path,
        timeout: int | None = None,
        fast_mode: bool = False,
        **kwargs,
    ) -> dict[str, Any]:
        """Optimized scan using AST structure.

        Args:
            data: Data to scan (bytes, file path, or PID)
            timeout: Scan timeout in seconds
            fast_mode: Stop on first match
            **kwargs: Additional arguments for yara.Rules.match()

        Returns:
            Enhanced scan result with AST context

        """
        import time

        start_time = time.time()

        try:
            self.scan_stats["total_scans"] += 1

            # Prepare scan arguments
            scan_args = {"fast": fast_mode, **kwargs}
            # Only add timeout if it's not None
            if timeout is not None:
                scan_args["timeout"] = timeout

            # Determine scan type and execute
            if isinstance(data, bytes):
                scan_args["data"] = data
                data_size = len(data)
            elif isinstance(data, str | Path):
                scan_args["filepath"] = str(data)
                data_size = Path(data).stat().st_size if Path(data).exists() else 0
            elif isinstance(data, int):  # PID
                scan_args["pid"] = data
                data_size = 0  # Unknown for process scans
            else:
                msg = f"Unsupported data type: {type(data)}"
                raise ValueError(msg)

            # Perform scan
            matches = self.rules.match(**scan_args)

            # Enhance matches with AST context
            enhanced_matches = self._enhance_matches_with_ast(matches)

            scan_time = time.time() - start_time
            self.scan_stats["successful_scans"] += 1
            self.scan_stats["total_scan_time"] += scan_time
            self.scan_stats["total_data_scanned"] += data_size

            return {
                "success": True,
                "matches": enhanced_matches,
                "scan_time": scan_time,
                "data_size": data_size,
                "ast_enhanced": self.ast is not None,
                "rule_count": len(self.ast.rules) if self.ast else 0,
                "optimization_hints": self._get_optimization_hints(enhanced_matches),
            }

        except Exception as e:
            scan_time = time.time() - start_time
            return {
                "success": False,
                "error": str(e),
                "scan_time": scan_time,
                "ast_enhanced": False,
            }

    def _enhance_matches_with_ast(self, matches: list[Any]) -> list[dict[str, Any]]:
        """Enhance yara matches with AST context."""
        enhanced = []

        for match in matches:
            # Process strings - each string is a StringMatch object
            string_matches = []
            for string_match in match.strings:
                # StringMatch has instances attribute which is a list of (offset, matched_data) tuples
                for instance in string_match.instances:
                    string_matches.append(
                        {
                            "offset": instance.offset,
                            "identifier": string_match.identifier,
                            "data": instance.matched_data,
                        },
                    )

            enhanced_match = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta),
                "strings": string_matches,
                "ast_context": self._get_ast_context_for_rule(match.rule),
            }
            enhanced.append(enhanced_match)

        return enhanced

    def _get_ast_context_for_rule(self, rule_name: str) -> dict[str, Any] | None:
        """Get AST context for a specific rule."""
        if not self.ast:
            return None

        for rule in self.ast.rules:
            if rule.name == rule_name:
                return {
                    "rule_type": ("regular" if not rule.modifiers else str(rule.modifiers)),
                    "string_count": len(rule.strings),
                    "has_meta": len(rule.meta) > 0,
                    "has_tags": len(rule.tags) > 0,
                    "condition_complexity": self._estimate_condition_complexity(
                        rule.condition,
                    ),
                }

        return None

    def _estimate_condition_complexity(self, condition) -> int:
        """Estimate condition complexity for optimization hints."""
        if not condition:
            return 0

        complexity = 1
        for child in condition.children():
            complexity += self._estimate_condition_complexity(child)

        return complexity

    def _get_optimization_hints(self, matches: list[dict[str, Any]]) -> list[str]:
        """Generate optimization hints based on scan results."""
        hints = []

        if not matches:
            hints.append("No matches found - consider rule optimization")

        for match in matches:
            if match.get("ast_context"):
                ctx = match["ast_context"]
                if ctx.get("condition_complexity", 0) > 10:
                    hints.append(
                        f"Rule '{match['rule']}' has complex condition - consider simplification",
                    )
                if ctx.get("string_count", 0) > 20:
                    hints.append(
                        f"Rule '{match['rule']}' has many strings - check for unused strings",
                    )

        return hints

    def get_scan_stats(self) -> dict[str, Any]:
        """Get scan statistics."""
        stats = self.scan_stats.copy()
        if stats["total_scans"] > 0:
            stats["average_scan_time"] = stats["total_scan_time"] / stats["total_scans"]
            stats["success_rate"] = stats["successful_scans"] / stats["total_scans"]
        else:
            stats["average_scan_time"] = 0.0
            stats["success_rate"] = 0.0

        return stats


# For backward compatibility
DirectCompiler = DirectASTCompiler
