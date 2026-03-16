"""Statistics helpers for DependencyGraphGenerator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator


def get_dependency_stats(generator: DependencyGraphGenerator) -> dict[str, Any]:
    """Build summary statistics from collected dependency graph state."""
    return {
        "total_rules": len(generator.rules),
        "total_imports": len(generator.imports),
        "total_includes": len(generator.includes),
        "rules_with_strings": sum(
            1 for rule in generator.rules.values() if rule["string_count"] > 0
        ),
        "rules_using_modules": len(
            [rule for rule in generator.module_references if generator.module_references[rule]],
        ),
        "most_used_modules": sorted(
            [
                (
                    module,
                    len([refs for refs in generator.module_references.values() if module in refs]),
                )
                for module in generator.imports
            ],
            key=lambda item: item[1],
            reverse=True,
        )[:5],
        "average_strings_per_rule": sum(rule["string_count"] for rule in generator.rules.values())
        / max(1, len(generator.rules)),
        "complex_rules": [
            name for name, info in generator.rules.items() if info["string_count"] > 10
        ],
    }
