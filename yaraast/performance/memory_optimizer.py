"""Memory optimization utilities for YARA AST processing."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, TypeVar, cast

from yaraast.performance.memory_helpers import MemoryStats
from yaraast.performance.memory_runtime import (
    batch_process_with_memory_limit as runtime_batch_process_with_memory_limit,
    clear_caches as runtime_clear_caches,
    create_memory_efficient_ast as runtime_create_memory_efficient_ast,
    force_cleanup as runtime_force_cleanup,
    get_memory_stats as runtime_get_memory_stats,
    get_memory_usage as runtime_get_memory_usage,
    get_statistics as runtime_get_statistics,
    init_optimizer_state,
    maybe_post_optimize_collect,
    memory_managed_context as runtime_memory_managed_context,
)
from yaraast.performance.memory_transformer_visitors import (
    visit_binary_expression as transformer_visit_binary_expression,
    visit_extern_import as transformer_visit_extern_import,
    visit_extern_namespace as transformer_visit_extern_namespace,
    visit_extern_rule as transformer_visit_extern_rule,
    visit_extern_rule_reference as transformer_visit_extern_rule_reference,
    visit_hex_string as transformer_visit_hex_string,
    visit_identifier as transformer_visit_identifier,
    visit_import as transformer_visit_import,
    visit_in_rule_pragma as transformer_visit_in_rule_pragma,
    visit_include as transformer_visit_include,
    visit_meta as transformer_visit_meta,
    visit_plain_string as transformer_visit_plain_string,
    visit_pragma as transformer_visit_pragma,
    visit_pragma_block as transformer_visit_pragma_block,
    visit_regex_string as transformer_visit_regex_string,
    visit_rule as transformer_visit_rule,
    visit_string_identifier as transformer_visit_string_identifier,
    visit_string_literal as transformer_visit_string_literal,
    visit_string_wildcard as transformer_visit_string_wildcard,
    visit_tag as transformer_visit_tag,
    visit_unary_expression as transformer_visit_unary_expression,
    visit_yara_file as transformer_visit_yara_file,
)
from yaraast.performance.validation import (
    validate_non_negative_int_setting,
    validate_positive_int_setting,
)
from yaraast.visitor.base import ASTTransformer

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.expressions import (
        BinaryExpression,
        BooleanLiteral,
        DoubleLiteral,
        Identifier,
        IntegerLiteral,
        StringIdentifier,
        StringLiteral,
        StringWildcard,
        UnaryExpression,
    )
    from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
    from yaraast.ast.meta import Meta
    from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock
    from yaraast.ast.rules import Import, Include, Rule, Tag
    from yaraast.ast.strings import HexString, PlainString, RegexString

_Node = TypeVar("_Node", bound="ASTNode")


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
        if memory_limit_mb is not None:
            validate_positive_int_setting(memory_limit_mb, "memory_limit_mb")
        if gc_threshold is not None:
            validate_positive_int_setting(gc_threshold, "gc_threshold")

        self.aggressive = aggressive
        self.memory_limit_mb = memory_limit_mb
        self.gc_threshold = gc_threshold if gc_threshold is not None else 10
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

    def memory_managed_context(self) -> AbstractContextManager[None]:
        """Create a memory-managed context."""
        return runtime_memory_managed_context(self)

    def track_object(self, obj: object) -> None:
        """Track an object for memory management."""
        if self.enable_tracking:
            self._tracked_objects.append(obj)
            self._stats["total_objects"] = len(self._tracked_objects)

    def get_memory_stats(self) -> MemoryStats:
        """Get memory statistics as an object."""
        return runtime_get_memory_stats(self)

    def force_cleanup(self) -> int:
        """Force garbage collection and cleanup."""
        return runtime_force_cleanup(self)

    def create_memory_efficient_ast(self) -> ASTNode:
        """Create or reuse an AST from pool."""
        return runtime_create_memory_efficient_ast(self)

    def return_ast_to_pool(self, ast: ASTNode) -> None:
        """Return an AST to the pool for reuse."""
        self._ast_pool.append(ast)

    def batch_process_with_memory_limit[Item, Result](
        self,
        items: Sequence[Item],
        processor: Callable[[Item], Result],
        batch_size: int = 10,
    ) -> Iterator[list[Result]]:
        """Process items in batches with memory management."""
        yield from runtime_batch_process_with_memory_limit(self, items, processor, batch_size)

    def optimize_for_large_collection(self, size: int) -> dict[str, Any]:
        """Get optimization recommendations for a collection size."""
        validate_non_negative_int_setting(size, "size")

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

    def visit(self, node: _Node) -> _Node:
        """Visit a node and optimize its memory usage."""
        self.nodes_processed += 1
        return cast(_Node, super().visit(node))

    def visit_string_literal(self, node: StringLiteral) -> StringLiteral:
        return transformer_visit_string_literal(self, node)

    def visit_identifier(self, node: Identifier) -> Identifier:
        return transformer_visit_identifier(self, node)

    def visit_rule(self, node: Rule) -> Rule:
        return transformer_visit_rule(self, node)

    def visit_plain_string(self, node: PlainString) -> PlainString:
        return transformer_visit_plain_string(self, node)

    def visit_meta(self, node: Meta) -> Meta:
        return transformer_visit_meta(self, node)

    def visit_tag(self, node: Tag) -> Tag:
        return transformer_visit_tag(self, node)

    # Pass-through methods for other node types
    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        return transformer_visit_yara_file(self, node)

    def visit_import(self, node: Import) -> Import:
        return transformer_visit_import(self, node)

    def visit_include(self, node: Include) -> Include:
        return transformer_visit_include(self, node)

    def visit_extern_rule(self, node: ExternRule) -> ExternRule:
        return transformer_visit_extern_rule(self, node)

    def visit_extern_rule_reference(self, node: ExternRuleReference) -> ExternRuleReference:
        return transformer_visit_extern_rule_reference(self, node)

    def visit_extern_import(self, node: ExternImport) -> ExternImport:
        return transformer_visit_extern_import(self, node)

    def visit_extern_namespace(self, node: ExternNamespace) -> ExternNamespace:
        return transformer_visit_extern_namespace(self, node)

    def visit_pragma(self, node: Pragma) -> Pragma:
        return transformer_visit_pragma(self, node)

    def visit_in_rule_pragma(self, node: InRulePragma) -> InRulePragma:
        return transformer_visit_in_rule_pragma(self, node)

    def visit_pragma_block(self, node: PragmaBlock) -> PragmaBlock:
        return transformer_visit_pragma_block(self, node)

    def visit_boolean_literal(self, node: BooleanLiteral) -> BooleanLiteral:
        return node

    def visit_integer_literal(self, node: IntegerLiteral) -> IntegerLiteral:
        return node

    def visit_double_literal(self, node: DoubleLiteral) -> DoubleLiteral:
        return node

    def visit_string_identifier(self, node: StringIdentifier) -> StringIdentifier:
        return transformer_visit_string_identifier(self, node)

    def visit_string_wildcard(self, node: StringWildcard) -> StringWildcard:
        return transformer_visit_string_wildcard(self, node)

    def visit_binary_expression(self, node: BinaryExpression) -> BinaryExpression:
        return transformer_visit_binary_expression(self, node)

    def visit_unary_expression(self, node: UnaryExpression) -> UnaryExpression:
        return transformer_visit_unary_expression(self, node)

    def visit_hex_string(self, node: HexString) -> HexString:
        return transformer_visit_hex_string(self, node)

    def visit_regex_string(self, node: RegexString) -> RegexString:
        return transformer_visit_regex_string(self, node)
