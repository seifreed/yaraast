"""Memory optimization utilities for YARA AST processing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.performance.memory_runtime import (
    batch_process_with_memory_limit as runtime_batch_process_with_memory_limit,
)
from yaraast.performance.memory_runtime import clear_caches as runtime_clear_caches
from yaraast.performance.memory_runtime import (
    create_memory_efficient_ast as runtime_create_memory_efficient_ast,
)
from yaraast.performance.memory_runtime import force_cleanup as runtime_force_cleanup
from yaraast.performance.memory_runtime import get_memory_stats as runtime_get_memory_stats
from yaraast.performance.memory_runtime import get_memory_usage as runtime_get_memory_usage
from yaraast.performance.memory_runtime import get_statistics as runtime_get_statistics
from yaraast.performance.memory_runtime import init_optimizer_state, maybe_post_optimize_collect
from yaraast.performance.memory_runtime import (
    memory_managed_context as runtime_memory_managed_context,
)
from yaraast.performance.memory_transformer_visitors import (
    visit_binary_expression as transformer_visit_binary_expression,
)
from yaraast.performance.memory_transformer_visitors import (
    visit_hex_string as transformer_visit_hex_string,
)
from yaraast.performance.memory_transformer_visitors import (
    visit_identifier as transformer_visit_identifier,
)
from yaraast.performance.memory_transformer_visitors import visit_import as transformer_visit_import
from yaraast.performance.memory_transformer_visitors import (
    visit_include as transformer_visit_include,
)
from yaraast.performance.memory_transformer_visitors import visit_meta as transformer_visit_meta
from yaraast.performance.memory_transformer_visitors import (
    visit_plain_string as transformer_visit_plain_string,
)
from yaraast.performance.memory_transformer_visitors import (
    visit_regex_string as transformer_visit_regex_string,
)
from yaraast.performance.memory_transformer_visitors import visit_rule as transformer_visit_rule
from yaraast.performance.memory_transformer_visitors import (
    visit_string_identifier as transformer_visit_string_identifier,
)
from yaraast.performance.memory_transformer_visitors import (
    visit_string_literal as transformer_visit_string_literal,
)
from yaraast.performance.memory_transformer_visitors import (
    visit_string_wildcard as transformer_visit_string_wildcard,
)
from yaraast.performance.memory_transformer_visitors import visit_tag as transformer_visit_tag
from yaraast.performance.memory_transformer_visitors import (
    visit_unary_expression as transformer_visit_unary_expression,
)
from yaraast.performance.memory_transformer_visitors import (
    visit_yara_file as transformer_visit_yara_file,
)
from yaraast.visitor.base import ASTTransformer

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.rules import Rule


class MemoryOptimizer:
    """Optimizes memory usage when processing large YARA ASTs."""

    def __init__(
        self,
        aggressive: bool = False,
        memory_limit_mb: int | None = None,
        gc_threshold: int | None = None,
        enable_tracking: bool = False,
    ) -> None:
        """Initialize memory optimizer.

        Args:
            aggressive: If True, applies more aggressive memory optimizations
            memory_limit_mb: Memory limit in MB
            gc_threshold: Garbage collection threshold
            enable_tracking: Enable object tracking

        """
        self.aggressive = aggressive
        self.memory_limit_mb = memory_limit_mb
        self.gc_threshold = gc_threshold or 10
        self.enable_tracking = enable_tracking
        init_optimizer_state(self)

    def optimize(self, yara_file: YaraFile) -> YaraFile:
        """Optimize memory usage for a YARA file."""
        # Clear caches
        self._string_pool.clear()

        # Optimize the AST
        optimizer = MemoryOptimizerTransformer(self._string_pool, self.aggressive)
        optimized = optimizer.visit(yara_file)

        # Update stats
        self._stats["nodes_processed"] += optimizer.nodes_processed
        self._stats["strings_pooled"] += len(self._string_pool)

        # Force garbage collection if aggressive
        maybe_post_optimize_collect(self)

        return optimized

    def optimize_rule(self, rule: Rule) -> Rule:
        """Optimize memory usage for a single rule."""
        optimizer = MemoryOptimizerTransformer(self._string_pool, self.aggressive)
        return optimizer.visit(rule)

    def optimize_rules(self, rules: list[Rule]) -> list[Rule]:
        """Optimize memory usage for a list of rules."""
        return [self.optimize_rule(rule) for rule in rules]

    def get_memory_usage(self) -> dict[str, Any]:
        """Get current memory usage statistics."""
        return runtime_get_memory_usage()

    def clear_caches(self) -> None:
        """Clear all internal caches."""
        runtime_clear_caches(self)

    def get_statistics(self) -> dict[str, Any]:
        """Get optimization statistics."""
        return runtime_get_statistics(self)

    def memory_managed_context(self):
        """Create a memory-managed context."""
        return runtime_memory_managed_context(self)

    def track_object(self, obj: Any) -> None:
        """Track an object for memory management."""
        if self.enable_tracking:
            self._tracked_objects.append(obj)
            self._stats["total_objects"] = len(self._tracked_objects)

    def get_memory_stats(self):
        """Get memory statistics as an object."""
        return runtime_get_memory_stats(self)

    def force_cleanup(self) -> int:
        """Force garbage collection and cleanup."""
        return runtime_force_cleanup(self)

    def create_memory_efficient_ast(self):
        """Create or reuse an AST from pool."""
        return runtime_create_memory_efficient_ast(self)

    def return_ast_to_pool(self, ast: Any) -> None:
        """Return an AST to the pool for reuse."""
        self._ast_pool.append(ast)

    def batch_process_with_memory_limit(
        self,
        items: list[Any],
        processor: Any,
        batch_size: int = 10,
    ):
        """Process items in batches with memory management."""
        yield from runtime_batch_process_with_memory_limit(self, items, processor, batch_size)

    def optimize_for_large_collection(self, size: int) -> dict[str, Any]:
        """Get optimization recommendations for a collection size."""
        recommendations = {
            "batch_size": 10,
            "use_streaming": False,
            "enable_pooling": False,
            "memory_limit_mb": 100,
        }

        if size < 100:
            recommendations["batch_size"] = 10
        elif size < 1000:
            recommendations["batch_size"] = 50
            recommendations["enable_pooling"] = True
        else:
            recommendations["batch_size"] = 100
            recommendations["use_streaming"] = True
            recommendations["enable_pooling"] = True
            recommendations["memory_limit_mb"] = 500 + (size // 100)

        return recommendations


class MemoryOptimizerTransformer(ASTTransformer):
    """AST transformer that optimizes memory usage."""

    def __init__(self, string_pool: dict[str, str], aggressive: bool = False) -> None:
        super().__init__()
        self.string_pool = string_pool
        self.aggressive = aggressive
        self.nodes_processed = 0

    def visit(self, node: ASTNode) -> ASTNode:
        """Visit a node and optimize its memory usage."""
        self.nodes_processed += 1
        return super().visit(node)

    def visit_string_literal(self, node: Any) -> Any:
        return transformer_visit_string_literal(self, node)

    def visit_identifier(self, node: Any) -> Any:
        return transformer_visit_identifier(self, node)

    def visit_rule(self, node: Rule) -> Rule:
        return transformer_visit_rule(self, node)

    def visit_plain_string(self, node: Any) -> Any:
        return transformer_visit_plain_string(self, node)

    def visit_meta(self, node: Any) -> Any:
        return transformer_visit_meta(self, node)

    def visit_tag(self, node: Any) -> Any:
        return transformer_visit_tag(self, node)

    # Pass-through methods for other node types
    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        return transformer_visit_yara_file(self, node)

    def visit_import(self, node: Any) -> Any:
        return transformer_visit_import(self, node)

    def visit_include(self, node: Any) -> Any:
        return transformer_visit_include(self, node)

    def visit_boolean_literal(self, node: Any) -> Any:
        return node

    def visit_integer_literal(self, node: Any) -> Any:
        return node

    def visit_double_literal(self, node: Any) -> Any:
        return node

    def visit_string_identifier(self, node: Any) -> Any:
        return transformer_visit_string_identifier(self, node)

    def visit_string_wildcard(self, node: Any) -> Any:
        return transformer_visit_string_wildcard(self, node)

    def visit_binary_expression(self, node: Any) -> Any:
        return transformer_visit_binary_expression(self, node)

    def visit_unary_expression(self, node: Any) -> Any:
        return transformer_visit_unary_expression(self, node)

    def visit_hex_string(self, node: Any) -> Any:
        return transformer_visit_hex_string(self, node)

    def visit_regex_string(self, node: Any) -> Any:
        return transformer_visit_regex_string(self, node)
