"""Rich tree builder for CLI AST output."""

from typing import Any

from rich.tree import Tree

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import StringWildcard
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString, RegexString

from .formatters import ConditionStringFormatter


class ASTTreeBuilder:
    """Build Rich tree visualization of AST."""

    def __getattr__(self, name: str):
        if name.startswith("visit_"):
            return self._visit_unhandled
        raise AttributeError(name)

    def _visit_unhandled(self, _node: Any) -> Tree:
        return Tree("")

    def visit_string_wildcard(self, node: StringWildcard) -> Tree:
        """Visit StringWildcard node."""
        return Tree(f"StringWildcard: {node.pattern}")

    def visit(self, node) -> Tree:
        """Generic visit method with fallback."""
        if node is None:
            return Tree("None")

        if hasattr(node, "accept"):
            import contextlib

            with contextlib.suppress(Exception):
                return node.accept(self)

        method_name = f"visit_{type(node).__name__.lower()}"
        return getattr(self, method_name)(node)

    def visit_yara_file(self, node: YaraFile) -> Tree:
        tree = Tree("YARA File")

        if node.imports:
            imports_tree = tree.add("Imports")
            for imp in node.imports:
                imports_tree.add(f'"{imp.module}"')

        if node.includes:
            includes_tree = tree.add("Includes")
            for inc in node.includes:
                includes_tree.add(f'"{inc.path}"')

        if node.rules:
            rules_tree = tree.add("Rules")
            for rule in node.rules:
                rules_tree.add(self.visit(rule))

        return tree

    def visit_rule(self, node: Rule) -> Tree:
        """Visit a rule node and create its tree representation."""
        rule_tree = self._create_rule_tree_with_modifiers(node)

        if node.tags:
            self._add_tags_to_tree(rule_tree, node.tags)

        if node.meta:
            self._add_meta_to_tree(rule_tree, node.meta)

        if node.strings:
            self._add_strings_to_tree(rule_tree, node.strings)

        if node.condition:
            self._add_condition_to_tree(rule_tree, node.condition)

        return rule_tree

    def _create_rule_tree_with_modifiers(self, node: Rule) -> Tree:
        """Create rule tree with modifiers in the name."""
        name_with_modifiers = node.name
        if node.modifiers:
            modifier_strs: list[str] = []
            if isinstance(node.modifiers, list | tuple):
                iterable = node.modifiers
            else:
                iterable = [node.modifiers]
            for mod in iterable:
                if isinstance(mod, str):
                    modifier_strs.append(mod)
                elif hasattr(mod, "name"):
                    modifier_strs.append(mod.name)
                else:
                    modifier_strs.append(str(mod))
            if modifier_strs:
                name_with_modifiers = f"[{'|'.join(modifier_strs)}] {name_with_modifiers}"

        return Tree(f"Rule: {name_with_modifiers}")

    def _add_tags_to_tree(self, rule_tree: Tree, tags) -> None:
        """Add tags section to rule tree."""
        tags_tree = rule_tree.add("Tags")
        for tag in tags:
            if isinstance(tag, str):
                tags_tree.add(tag)
            else:
                tags_tree.add(tag.name)

    def _add_meta_to_tree(self, rule_tree: Tree, meta) -> None:
        """Add meta section to rule tree."""
        from rich.markup import escape

        meta_tree = rule_tree.add("Meta")

        self._add_list_meta_to_tree(meta_tree, meta, escape)

    def _add_dict_meta_to_tree(self, meta_tree: Tree, meta_dict: dict, escape) -> None:
        """Add dictionary meta to tree."""
        for key, value in meta_dict.items():
            if isinstance(value, str):
                meta_tree.add(f'{escape(key)} = "{escape(value)}"')
            else:
                meta_tree.add(f"{escape(key)} = {value}")

    def _add_list_meta_to_tree(self, meta_tree: Tree, meta_list: list, escape) -> None:
        """Add list meta to tree."""
        for m in meta_list:
            if hasattr(m, "key") and hasattr(m, "value"):
                if isinstance(m.value, str):
                    meta_tree.add(f'{escape(m.key)} = "{escape(m.value)}"')
                else:
                    meta_tree.add(f"{escape(m.key)} = {m.value}")

    def _add_strings_to_tree(self, rule_tree: Tree, strings) -> None:
        """Add strings section to rule tree."""
        from rich.markup import escape

        strings_tree = rule_tree.add("Strings")
        for string in strings:
            string_type = string.__class__.__name__
            value_preview = self._get_string_preview(string, escape)
            strings_tree.add(f"{string.identifier}{value_preview} [{string_type}]")

    def _get_string_preview(self, string, escape) -> str:
        """Get string value preview for display."""
        if isinstance(string, PlainString):
            escaped_val = escape(string.value[:30]) if string.value else ""
            ellipsis = "..." if len(string.value) > 30 else ""
            return f' = "{escaped_val}{ellipsis}"'

        if isinstance(string, RegexString):
            escaped_regex = escape(string.regex[:30]) if string.regex else ""
            ellipsis = "..." if len(string.regex) > 30 else ""
            return f" = /{escaped_regex}{ellipsis}/"

        return ""

    def _add_condition_to_tree(self, rule_tree: Tree, condition) -> None:
        """Add condition section to rule tree."""
        condition_tree = rule_tree.add("Condition")
        condition_str = self._get_condition_string(condition)
        condition_str = self._truncate_condition_string(condition_str)

        if condition_str:
            condition_tree.add(condition_str)
        else:
            condition_tree.add("<complex condition>")

    def _get_condition_string(self, condition) -> str:
        """Get condition string using generator or fallback."""
        try:
            from yaraast.codegen.generator import CodeGenerator

            condition_str = CodeGenerator().generate(condition).strip()
            if not condition_str:
                condition_str = self._condition_to_string(condition)
        except (ValueError, TypeError, AttributeError):
            condition_str = self._condition_to_string(condition)
        return condition_str

    def _truncate_condition_string(self, condition_str: str) -> str:
        """Truncate condition string based on content type."""
        hash_prefix = "hash."
        is_hash_heavy = hash_prefix in condition_str and condition_str.count("==") > 2
        hash_count = condition_str.count(hash_prefix)

        max_length = self._get_condition_max_length(hash_count, is_hash_heavy)

        if len(condition_str) > max_length:
            return self._truncate_at_boundary(condition_str, max_length)

        return condition_str

    def _get_condition_max_length(self, hash_count: int, is_hash_heavy: bool) -> int:
        """Determine max length for condition based on content."""
        if hash_count > 10:
            return 1000
        if hash_count > 5:
            return 700
        if is_hash_heavy:
            return 400
        return 200

    def _truncate_at_boundary(self, condition_str: str, max_length: int) -> str:
        """Truncate condition string at logical boundary."""
        for boundary in [" or ", " and ", ", "]:
            if boundary in condition_str[:max_length]:
                cut_point = condition_str[:max_length].rfind(boundary)
                return condition_str[: cut_point + len(boundary)] + "..."
        return condition_str[:max_length] + "..."

    def _condition_to_string(self, condition, depth=0) -> str:
        """Convert condition to string representation."""
        formatter = ConditionStringFormatter()
        return formatter.format_condition(condition, depth)

    def visit_plain_string(self, node: Any) -> Tree:
        from rich.markup import escape

        value = (
            escape(node.value)
            if hasattr(node, "value") and isinstance(node.value, str)
            else str(node.value)
        )
        mods = (
            f" [{', '.join(m.name if hasattr(m, 'name') else str(m) for m in node.modifiers)}]"
            if hasattr(node, "modifiers") and node.modifiers
            else ""
        )
        return Tree(f'{node.identifier} = "{value}"{mods}')

    def visit_hex_string(self, node: Any) -> Tree:
        mods = (
            f" [{', '.join(m.name if hasattr(m, 'name') else str(m) for m in node.modifiers)}]"
            if hasattr(node, "modifiers") and node.modifiers
            else ""
        )
        return Tree(f"{node.identifier} [HexString]{mods}")

    def visit_regex_string(self, node: Any) -> Tree:
        from rich.markup import escape

        regex = escape(node.regex) if hasattr(node, "regex") and isinstance(node.regex, str) else ""
        mods = (
            f" [{', '.join(m.name if hasattr(m, 'name') else str(m) for m in node.modifiers)}]"
            if hasattr(node, "modifiers") and node.modifiers
            else ""
        )
        return Tree(f"{node.identifier} = /{regex}/{mods}")

    def visit_comment(self, node: Any) -> Tree:
        return Tree(f"Comment: {node.text if hasattr(node, 'text') else ''}")

    def visit_comment_group(self, node: Any) -> Tree:
        return Tree("Comments")

    def visit_defined_expression(self, node: Any) -> Tree:
        return Tree("defined(...)")

    def visit_dictionary_access(self, node: Any) -> Tree:
        return Tree("dict[...]")

    def visit_extern_import(self, node: Any) -> Tree:
        return Tree(f"extern import {node.module if hasattr(node, 'module') else ''}")

    def visit_extern_namespace(self, node: Any) -> Tree:
        return Tree(f"extern namespace {node.name if hasattr(node, 'name') else ''}")

    def visit_extern_rule(self, node: Any) -> Tree:
        return Tree(f"extern rule {node.name if hasattr(node, 'name') else ''}")

    def visit_extern_rule_reference(self, node: Any) -> Tree:
        return Tree("extern rule ref")

    def visit_hex_nibble(self, node: Any) -> Tree:
        return Tree("~")

    def visit_in_rule_pragma(self, node: Any) -> Tree:
        return Tree("pragma")

    def visit_module_reference(self, node: Any) -> Tree:
        return Tree(f"module {node.name if hasattr(node, 'name') else ''}")

    def visit_pragma(self, node: Any) -> Tree:
        return Tree(f"pragma {node.name if hasattr(node, 'name') else ''}")

    def visit_pragma_block(self, node: Any) -> Tree:
        return Tree("pragma block")

    def visit_regex_literal(self, node: Any) -> Tree:
        return Tree(f"/{node.value if hasattr(node, 'value') else ''}/..")

    def visit_string_operator_expression(self, node: Any) -> Tree:
        return Tree("string op")
