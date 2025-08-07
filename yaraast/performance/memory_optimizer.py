"""Memory optimization utilities for YARA AST processing."""

from __future__ import annotations

import gc
import weakref
from typing import TYPE_CHECKING, Any

from yaraast.visitor.visitor import ASTTransformer

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.rules import Rule


class MemoryOptimizer:
    """Optimizes memory usage when processing large YARA ASTs."""

    def __init__(self, aggressive: bool = False) -> None:
        """Initialize memory optimizer.

        Args:
            aggressive: If True, applies more aggressive memory optimizations

        """
        self.aggressive = aggressive
        self._cache = weakref.WeakValueDictionary()
        self._string_pool = {}
        self._stats = {
            "nodes_processed": 0,
            "strings_pooled": 0,
            "memory_saved": 0,
        }

    def optimize(self, yara_file: YaraFile) -> YaraFile:
        """Optimize memory usage for a YARA file."""
        # Clear caches
        self._string_pool.clear()

        # Optimize the AST
        optimizer = MemoryOptimizerTransformer(self._string_pool, self.aggressive)
        _ = optimizer.visit(yara_file)

        # Update stats
        self._stats["nodes_processed"] += optimizer.nodes_processed
        self._stats["strings_pooled"] += len(self._string_pool)

        # Force garbage collection if aggressive
        if self.aggressive:
            gc.collect()

        return yara_file

    def optimize_rule(self, rule: Rule) -> Rule:
        """Optimize memory usage for a single rule."""
        optimizer = MemoryOptimizerTransformer(self._string_pool, self.aggressive)
        return optimizer.visit(rule)

    def optimize_rules(self, rules: list[Rule]) -> list[Rule]:
        """Optimize memory usage for a list of rules."""
        return [self.optimize_rule(rule) for rule in rules]

    def get_memory_usage(self) -> dict[str, Any]:
        """Get current memory usage statistics."""
        import os

        import psutil

        process = psutil.Process(os.getpid())
        mem_info = process.memory_info()

        return {
            "rss_mb": mem_info.rss / 1024 / 1024,
            "vms_mb": mem_info.vms / 1024 / 1024,
            "percent": process.memory_percent(),
            "available_mb": psutil.virtual_memory().available / 1024 / 1024,
        }

    def clear_caches(self) -> None:
        """Clear all internal caches."""
        self._cache.clear()
        self._string_pool.clear()
        gc.collect()

    def get_statistics(self) -> dict[str, Any]:
        """Get optimization statistics."""
        return {
            **self._stats,
            "string_pool_size": len(self._string_pool),
            "cache_size": len(self._cache),
        }


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
        """Pool string literals to reduce memory usage."""
        if hasattr(node, "value") and isinstance(node.value, str):
            # Use string pooling
            pooled = self.string_pool.get(node.value)
            if pooled is None:
                self.string_pool[node.value] = node.value
                pooled = node.value
            else:
                # Reuse existing string
                node.value = pooled
        return node

    def visit_identifier(self, node: Any) -> Any:
        """Pool identifier names."""
        if hasattr(node, "name") and isinstance(node.name, str):
            pooled = self.string_pool.get(node.name)
            if pooled is None:
                self.string_pool[node.name] = node.name
                pooled = node.name
            else:
                node.name = pooled
        return node

    def visit_rule(self, node: Rule) -> Rule:
        """Optimize rule memory usage."""
        # Pool rule name
        if node.name:
            pooled = self.string_pool.get(node.name)
            if pooled is None:
                self.string_pool[node.name] = node.name
            else:
                node.name = pooled

        # Visit children
        if node.condition:
            node.condition = self.visit(node.condition)

        if node.strings:
            node.strings = [self.visit(s) for s in node.strings]

        if node.meta:
            node.meta = [self.visit(m) for m in node.meta]

        if node.tags:
            node.tags = [self.visit(t) for t in node.tags]

        # Clear unnecessary attributes if aggressive
        if self.aggressive and hasattr(node, "location"):
            # Remove location info if not needed
            node.location = None

        return node

    def visit_plain_string(self, node: Any) -> Any:
        """Optimize plain string memory usage."""
        # Pool string value
        if hasattr(node, "value") and isinstance(node.value, str):
            pooled = self.string_pool.get(node.value)
            if pooled is None:
                self.string_pool[node.value] = node.value
            else:
                node.value = pooled

        # Pool identifier
        if hasattr(node, "identifier") and isinstance(node.identifier, str):
            pooled = self.string_pool.get(node.identifier)
            if pooled is None:
                self.string_pool[node.identifier] = node.identifier
            else:
                node.identifier = pooled

        return node

    def visit_meta(self, node: Any) -> Any:
        """Optimize meta memory usage."""
        # Pool meta key
        if hasattr(node, "key") and isinstance(node.key, str):
            pooled = self.string_pool.get(node.key)
            if pooled is None:
                self.string_pool[node.key] = node.key
            else:
                node.key = pooled

        # Pool string values
        if hasattr(node, "value") and isinstance(node.value, str):
            pooled = self.string_pool.get(node.value)
            if pooled is None:
                self.string_pool[node.value] = node.value
            else:
                node.value = pooled

        return node

    def visit_tag(self, node: Any) -> Any:
        """Optimize tag memory usage."""
        if hasattr(node, "name") and isinstance(node.name, str):
            pooled = self.string_pool.get(node.name)
            if pooled is None:
                self.string_pool[node.name] = node.name
            else:
                node.name = pooled
        return node

    # Pass-through methods for other node types
    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        """Optimize YaraFile memory usage."""
        if node.imports:
            node.imports = [self.visit(imp) for imp in node.imports]
        if node.includes:
            node.includes = [self.visit(inc) for inc in node.includes]
        if node.rules:
            node.rules = [self.visit(rule) for rule in node.rules]
        return node

    def visit_import(self, node: Any) -> Any:
        """Optimize import memory usage."""
        if hasattr(node, "module") and isinstance(node.module, str):
            pooled = self.string_pool.get(node.module)
            if pooled is None:
                self.string_pool[node.module] = node.module
            else:
                node.module = pooled
        return node

    def visit_include(self, node: Any) -> Any:
        """Optimize include memory usage."""
        if hasattr(node, "path") and isinstance(node.path, str):
            pooled = self.string_pool.get(node.path)
            if pooled is None:
                self.string_pool[node.path] = node.path
            else:
                node.path = pooled
        return node

    def visit_boolean_literal(self, node: Any) -> Any:
        return node

    def visit_integer_literal(self, node: Any) -> Any:
        return node

    def visit_double_literal(self, node: Any) -> Any:
        return node

    def visit_string_identifier(self, node: Any) -> Any:
        if hasattr(node, "name") and isinstance(node.name, str):
            pooled = self.string_pool.get(node.name)
            if pooled is None:
                self.string_pool[node.name] = node.name
            else:
                node.name = pooled
        return node

    def visit_binary_expression(self, node: Any) -> Any:
        if hasattr(node, "left"):
            node.left = self.visit(node.left)
        if hasattr(node, "right"):
            node.right = self.visit(node.right)
        if hasattr(node, "operator") and isinstance(node.operator, str):
            pooled = self.string_pool.get(node.operator)
            if pooled is None:
                self.string_pool[node.operator] = node.operator
            else:
                node.operator = pooled
        return node

    def visit_unary_expression(self, node: Any) -> Any:
        if hasattr(node, "operand"):
            node.operand = self.visit(node.operand)
        if hasattr(node, "operator") and isinstance(node.operator, str):
            pooled = self.string_pool.get(node.operator)
            if pooled is None:
                self.string_pool[node.operator] = node.operator
            else:
                node.operator = pooled
        return node

    def visit_hex_string(self, node: Any) -> Any:
        if hasattr(node, "identifier") and isinstance(node.identifier, str):
            pooled = self.string_pool.get(node.identifier)
            if pooled is None:
                self.string_pool[node.identifier] = node.identifier
            else:
                node.identifier = pooled
        return node

    def visit_regex_string(self, node: Any) -> Any:
        if hasattr(node, "identifier") and isinstance(node.identifier, str):
            pooled = self.string_pool.get(node.identifier)
            if pooled is None:
                self.string_pool[node.identifier] = node.identifier
            else:
                node.identifier = pooled
        if hasattr(node, "regex") and isinstance(node.regex, str):
            pooled = self.string_pool.get(node.regex)
            if pooled is None:
                self.string_pool[node.regex] = node.regex
            else:
                node.regex = pooled
        return node
