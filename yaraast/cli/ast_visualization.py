"""AST visualization helpers for CLI output."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.tree import Tree

from yaraast.ast.base import YaraFile
from yaraast.cli.utils import format_json
from yaraast.cli.visitors import ASTDumper


def print_ast(ast: YaraFile, console: Console | None = None) -> None:
    """Print AST in a readable format."""
    if console is None:
        console = Console()

    tree = Tree("YaraFile")
    _add_imports_to_tree(tree, ast.imports)
    _add_includes_to_tree(tree, ast.includes)
    _add_rules_to_tree(tree, ast.rules)
    console.print(tree)


def visualize_ast(ast: YaraFile, output_format: str = "json") -> str:
    """Visualize AST in a simple serializable format."""
    dumper = ASTDumper()
    data = dumper.visit(ast)

    if output_format == "json":
        return format_json(data, sort_keys=True)
    if output_format == "dict":
        return format_json(data, indent=None)

    msg = f"Unsupported output format: {output_format}"
    raise ValueError(msg)


def _add_imports_to_tree(tree: Tree, imports: Any) -> None:
    """Add imports to the tree."""
    if not imports:
        return

    imports_branch = tree.add("imports")
    for imp in imports:
        imp_text = f'import "{imp.module}"'
        if hasattr(imp, "alias") and imp.alias:
            imp_text += f" as {imp.alias}"
        imports_branch.add(imp_text)


def _add_includes_to_tree(tree: Tree, includes: Any) -> None:
    """Add includes to the tree."""
    if not includes:
        return

    includes_branch = tree.add("includes")
    for inc in includes:
        includes_branch.add(f'include "{inc.path}"')


def _add_rules_to_tree(tree: Tree, rules: Any) -> None:
    """Add rules to the tree."""
    if not rules:
        return

    rules_branch = tree.add("rules")
    for rule in rules:
        rule_branch = _create_rule_branch(rules_branch, rule)
        _add_rule_components(rule_branch, rule)


def _create_rule_branch(rules_branch: Tree, rule: Any) -> Tree:
    """Create a rule branch in the tree."""
    rule_text = f"rule {rule.name}"
    if hasattr(rule, "modifiers") and rule.modifiers:
        rule_text = f"{' '.join(str(m) for m in rule.modifiers)} {rule_text}"
    return rules_branch.add(rule_text)


def _add_rule_components(rule_branch: Tree, rule: Any) -> None:
    """Add rule components to the rule branch."""
    _add_tags_to_rule(rule_branch, rule)
    _add_meta_to_rule(rule_branch, rule)
    _add_strings_to_rule(rule_branch, rule)
    _add_condition_to_rule(rule_branch, rule)


def _add_tags_to_rule(rule_branch: Tree, rule: Any) -> None:
    """Add tags to the rule branch."""
    if not (hasattr(rule, "tags") and rule.tags):
        return

    tags_branch = rule_branch.add("tags")
    for tag in rule.tags:
        tag_name = tag.name if hasattr(tag, "name") else str(tag)
        tags_branch.add(tag_name)


def _add_meta_to_rule(rule_branch: Tree, rule: Any) -> None:
    """Add meta to the rule branch."""
    if not (hasattr(rule, "meta") and rule.meta):
        return

    meta_branch = rule_branch.add("meta")
    if isinstance(rule.meta, dict):
        for key, value in rule.meta.items():
            meta_branch.add(f"{key} = {value}")
    else:
        for meta_item in rule.meta:
            if hasattr(meta_item, "key"):
                meta_branch.add(f"{meta_item.key} = {meta_item.value}")


def _add_strings_to_rule(rule_branch: Tree, rule: Any) -> None:
    """Add strings to the rule branch."""
    if not (hasattr(rule, "strings") and rule.strings):
        return

    strings_branch = rule_branch.add("strings")
    for string_def in rule.strings:
        string_type = type(string_def).__name__
        strings_branch.add(f"{string_def.identifier} ({string_type})")


def _add_condition_to_rule(rule_branch: Tree, rule: Any) -> None:
    """Add condition to the rule branch."""
    if not (hasattr(rule, "condition") and rule.condition):
        return

    condition_branch = rule_branch.add("condition")
    condition_branch.add(str(rule.condition))


__all__ = [
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
