"""CLI facade for AST tools."""

from __future__ import annotations

from yaraast.cli.ast_visualization import (
    _add_condition_to_rule,
    _add_imports_to_tree,
    _add_includes_to_tree,
    _add_meta_to_rule,
    _add_rule_components,
    _add_rules_to_tree,
    _add_strings_to_rule,
    _add_tags_to_rule,
    _create_rule_branch,
    print_ast,
    visualize_ast,
)
from yaraast.cli.benchmark_tools import ASTBenchmarker, BenchmarkResult
from yaraast.shared.ast_analysis import (
    ASTDiffer,
    ASTDiffResult,
    ASTFormatter,
    ASTStructuralAnalyzer,
)

__all__ = [
    "ASTBenchmarker",
    "ASTDiffResult",
    "ASTDiffer",
    "ASTFormatter",
    "ASTStructuralAnalyzer",
    "BenchmarkResult",
    "_add_condition_to_rule",
    "_add_imports_to_tree",
    "_add_includes_to_tree",
    "_add_meta_to_rule",
    "_add_rule_components",
    "_add_rules_to_tree",
    "_add_strings_to_rule",
    "_add_tags_to_rule",
    "_create_rule_branch",
    "print_ast",
    "visualize_ast",
]
