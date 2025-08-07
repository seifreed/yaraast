"""CLI interface for YARA AST."""

import json
import time
from difflib import unified_diff
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree

from yaraast import CodeGenerator, Parser
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
    StringModifier,
)

# Import CLI commands
from yaraast.cli.commands.analyze import analyze
from yaraast.cli.commands.fluent import fluent
from yaraast.cli.commands.metrics import metrics
from yaraast.cli.commands.optimize import optimize_cmd
from yaraast.cli.commands.performance import performance
from yaraast.cli.commands.performance_check import performance_check_cmd
from yaraast.cli.commands.roundtrip import roundtrip
from yaraast.cli.commands.semantic import semantic
from yaraast.cli.commands.serialize import serialize
from yaraast.cli.commands.validate import validate
from yaraast.cli.commands.workspace import workspace
from yaraast.cli.commands.yaral import yaral
from yaraast.cli.commands.yarax import yarax
from yaraast.dialects import YaraDialect
from yaraast.unified_parser import UnifiedParser
from yaraast.visitor import ASTVisitor

console = Console()


class ASTDumper(ASTVisitor[dict]):
    """Dump AST to dictionary format."""

    def visit_yara_file(self, node: YaraFile) -> dict:
        return {
            "type": "YaraFile",
            "imports": [self.visit(imp) for imp in node.imports],
            "includes": [self.visit(inc) for inc in node.includes],
            "rules": [self.visit(rule) for rule in node.rules],
        }

    def visit_import(self, node: Import) -> dict:
        return {"type": "Import", "module": node.module}

    def visit_include(self, node: Include) -> dict:
        return {"type": "Include", "path": node.path}

    def visit_rule(self, node: Rule) -> dict:
        # Handle tags - they might be strings or Tag objects
        tags = []
        for tag in node.tags:
            if isinstance(tag, str):
                tags.append(tag)
            else:
                tags.append(self.visit(tag))

        # Handle meta - it might be a dict or list of Meta objects
        meta = {}
        if isinstance(node.meta, dict):
            meta = node.meta
        elif isinstance(node.meta, list):
            for m in node.meta:
                if hasattr(m, "key") and hasattr(m, "value"):
                    meta[m.key] = m.value

        # Handle modifiers - they can be lists, strings, or AST objects
        modifiers = []
        if hasattr(node, "modifiers") and node.modifiers:
            if isinstance(node.modifiers, list | tuple):
                for mod in node.modifiers:
                    if isinstance(mod, str):
                        modifiers.append(mod)
                    elif hasattr(mod, "accept"):
                        modifiers.append(self.visit(mod))
                    else:
                        modifiers.append(str(mod))
            elif isinstance(node.modifiers, str):
                modifiers.append(node.modifiers)
            elif hasattr(node.modifiers, "accept"):
                # It's an AST node, don't include it as a modifier
                pass
            else:
                modifiers.append(str(node.modifiers))

        return {
            "type": "Rule",
            "name": node.name,
            "modifiers": modifiers,
            "tags": tags,
            "meta": meta,
            "strings": [self.visit(s) for s in node.strings],
            "condition": self.visit(node.condition) if node.condition else None,
        }

    def visit_tag(self, node: Tag) -> dict:
        return {"type": "Tag", "name": node.name}

    def visit_string_definition(self, node: StringDefinition) -> dict:
        return {"type": "StringDefinition", "identifier": node.identifier}

    def visit_plain_string(self, node: PlainString) -> dict:
        # Handle modifiers - they can be strings or objects
        modifiers = []
        if hasattr(node, "modifiers") and node.modifiers:
            if isinstance(node.modifiers, list | tuple):
                for mod in node.modifiers:
                    if isinstance(mod, str):
                        modifiers.append(mod)
                    elif hasattr(mod, "accept"):  # It's an AST node
                        modifiers.append(self.visit(mod))
                    else:
                        modifiers.append(str(mod))
            else:
                modifiers.append(str(node.modifiers))

        return {
            "type": "PlainString",
            "identifier": node.identifier,
            "value": node.value,
            "modifiers": modifiers,
        }

    def visit_hex_string(self, node: HexString) -> dict:
        # Handle modifiers safely
        modifiers = []
        if hasattr(node, "modifiers") and node.modifiers:
            if isinstance(node.modifiers, list | tuple):
                for mod in node.modifiers:
                    if isinstance(mod, str):
                        modifiers.append(mod)
                    elif hasattr(mod, "accept"):
                        modifiers.append(self.visit(mod))
                    else:
                        modifiers.append(str(mod))
            else:
                modifiers.append(str(node.modifiers))

        return {
            "type": "HexString",
            "identifier": node.identifier,
            "tokens": [self.visit(token) for token in node.tokens],
            "modifiers": modifiers,
        }

    def visit_regex_string(self, node: RegexString) -> dict:
        # Handle modifiers safely
        modifiers = []
        if hasattr(node, "modifiers") and node.modifiers:
            if isinstance(node.modifiers, list | tuple):
                for mod in node.modifiers:
                    if isinstance(mod, str):
                        modifiers.append(mod)
                    elif hasattr(mod, "accept"):
                        modifiers.append(self.visit(mod))
                    else:
                        modifiers.append(str(mod))
            else:
                modifiers.append(str(node.modifiers))

        return {
            "type": "RegexString",
            "identifier": node.identifier,
            "regex": node.regex,
            "modifiers": modifiers,
        }

    def visit_string_modifier(self, node: StringModifier) -> dict:
        return {"type": "StringModifier", "name": node.name, "value": node.value}

    def visit_hex_token(self, node: HexToken) -> dict:
        return {"type": "HexToken"}

    def visit_hex_byte(self, node: HexByte) -> dict:
        return {"type": "HexByte", "value": node.value}

    def visit_hex_wildcard(self, node: HexWildcard) -> dict:
        return {"type": "HexWildcard"}

    def visit_hex_jump(self, node: HexJump) -> dict:
        return {"type": "HexJump", "min_jump": node.min_jump, "max_jump": node.max_jump}

    def visit_hex_alternative(self, node: HexAlternative) -> dict:
        return {
            "type": "HexAlternative",
            "alternatives": [[self.visit(token) for token in alt] for alt in node.alternatives],
        }

    def visit_expression(self, node: Expression) -> dict:
        return {"type": "Expression"}

    def visit_identifier(self, node: Identifier) -> dict:
        return {"type": "Identifier", "name": node.name}

    def visit_string_identifier(self, node: StringIdentifier) -> dict:
        return {"type": "StringIdentifier", "name": node.name}

    def visit_string_count(self, node: StringCount) -> dict:
        return {"type": "StringCount", "string_id": node.string_id}

    def visit_string_offset(self, node: StringOffset) -> dict:
        return {
            "type": "StringOffset",
            "string_id": node.string_id,
            "index": self.visit(node.index) if node.index else None,
        }

    def visit_string_length(self, node: StringLength) -> dict:
        return {
            "type": "StringLength",
            "string_id": node.string_id,
            "index": self.visit(node.index) if node.index else None,
        }

    def visit_integer_literal(self, node: IntegerLiteral) -> dict:
        return {"type": "IntegerLiteral", "value": node.value}

    def visit_double_literal(self, node: DoubleLiteral) -> dict:
        return {"type": "DoubleLiteral", "value": node.value}

    def visit_string_literal(self, node: StringLiteral) -> dict:
        return {"type": "StringLiteral", "value": node.value}

    def visit_boolean_literal(self, node: BooleanLiteral) -> dict:
        return {"type": "BooleanLiteral", "value": node.value}

    def visit_binary_expression(self, node: BinaryExpression) -> dict:
        return {
            "type": "BinaryExpression",
            "left": self.visit(node.left),
            "operator": node.operator,
            "right": self.visit(node.right),
        }

    def visit_unary_expression(self, node: UnaryExpression) -> dict:
        return {
            "type": "UnaryExpression",
            "operator": node.operator,
            "operand": self.visit(node.operand),
        }

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> dict:
        return {
            "type": "ParenthesesExpression",
            "expression": self.visit(node.expression),
        }

    def visit_set_expression(self, node: SetExpression) -> dict:
        return {
            "type": "SetExpression",
            "elements": [self.visit(elem) for elem in node.elements],
        }

    def visit_range_expression(self, node: RangeExpression) -> dict:
        return {
            "type": "RangeExpression",
            "low": self.visit(node.low),
            "high": self.visit(node.high),
        }

    def visit_function_call(self, node: FunctionCall) -> dict:
        return {
            "type": "FunctionCall",
            "function": node.function,
            "arguments": [self.visit(arg) for arg in node.arguments],
        }

    def visit_array_access(self, node: ArrayAccess) -> dict:
        return {
            "type": "ArrayAccess",
            "array": self.visit(node.array),
            "index": self.visit(node.index),
        }

    def visit_member_access(self, node: MemberAccess) -> dict:
        return {
            "type": "MemberAccess",
            "object": self.visit(node.object),
            "member": node.member,
        }

    def visit_condition(self, node: Condition) -> dict:
        return {"type": "Condition"}

    def visit_for_expression(self, node: ForExpression) -> dict:
        return {
            "type": "ForExpression",
            "quantifier": node.quantifier,
            "variable": node.variable,
            "iterable": self.visit(node.iterable),
            "body": self.visit(node.body),
        }

    def visit_for_of_expression(self, node: ForOfExpression) -> dict:
        return {
            "type": "ForOfExpression",
            "quantifier": (
                node.quantifier
                if isinstance(node.quantifier, str | int)
                else self.visit(node.quantifier)
            ),
            "string_set": self.visit(node.string_set),
            "condition": self.visit(node.condition) if node.condition else None,
        }

    def visit_at_expression(self, node: AtExpression) -> dict:
        return {
            "type": "AtExpression",
            "string_id": node.string_id,
            "offset": self.visit(node.offset),
        }

    def visit_in_expression(self, node: InExpression) -> dict:
        return {
            "type": "InExpression",
            "string_id": node.string_id,
            "range": self.visit(node.range),
        }

    def visit_of_expression(self, node: OfExpression) -> dict:
        return {
            "type": "OfExpression",
            "quantifier": (
                node.quantifier
                if isinstance(node.quantifier, str | int)
                else self.visit(node.quantifier)
            ),
            "string_set": self.visit(node.string_set),
        }

    def visit_meta(self, node: Meta) -> dict:
        return {"type": "Meta", "key": node.key, "value": node.value}

    def visit_comment(self, node) -> dict:
        return {"type": "Comment", "text": node.text}

    def visit_comment_group(self, node) -> dict:
        return {"type": "CommentGroup", "lines": node.lines}

    def visit_defined_expression(self, node) -> dict:
        return {"type": "DefinedExpression", "expression": self.visit(node.expression)}

    def visit_dictionary_access(self, node) -> dict:
        return {
            "type": "DictionaryAccess",
            "object": self.visit(node.object),
            "key": node.key,
        }

    def visit_extern_import(self, node) -> dict:
        return {"type": "ExternImport", "module": node.module}

    def visit_extern_namespace(self, node) -> dict:
        return {"type": "ExternNamespace", "name": node.name}

    def visit_extern_rule(self, node) -> dict:
        return {"type": "ExternRule", "name": node.name}

    def visit_extern_rule_reference(self, node) -> dict:
        return {"type": "ExternRuleReference", "name": node.name}

    def visit_hex_nibble(self, node) -> dict:
        return {"type": "HexNibble", "high": node.high, "value": node.value}

    def visit_in_rule_pragma(self, node) -> dict:
        return {"type": "InRulePragma", "directive": node.directive}

    def visit_module_reference(self, node) -> dict:
        return {"type": "ModuleReference", "module": node.module}

    def visit_pragma(self, node) -> dict:
        return {"type": "Pragma", "directive": node.directive}

    def visit_pragma_block(self, node) -> dict:
        return {"type": "PragmaBlock", "pragmas": [self.visit(p) for p in node.pragmas]}

    def visit_regex_literal(self, node) -> dict:
        return {
            "type": "RegexLiteral",
            "pattern": node.pattern,
            "modifiers": node.modifiers,
        }

    def visit_string_operator_expression(self, node) -> dict:
        return {
            "type": "StringOperatorExpression",
            "left": self.visit(node.left),
            "operator": node.operator,
            "right": self.visit(node.right),
        }


class ASTTreeBuilder(ASTVisitor[Tree]):
    """Build Rich tree visualization of AST."""

    def visit(self, node) -> Tree:
        """Generic visit method with fallback."""
        if node is None:
            return Tree("None")

        # Try specific visit methods first
        method_name = f"visit_{type(node).__name__.lower()}"
        if hasattr(self, method_name):
            return getattr(self, method_name)(node)

        # Fallback for unknown node types
        return Tree(f"{type(node).__name__}: {str(node)[:50]}")

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
            modifier_strs = []
            for mod in node.modifiers:
                if isinstance(mod, str):
                    modifier_strs.append(mod)
                else:
                    modifier_strs.append(str(mod))
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
        if isinstance(meta, dict):
            self._add_dict_meta_to_tree(meta_tree, meta, escape)
        elif isinstance(meta, list):
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
            return 1000  # Very long for many hashes
        if hash_count > 5:
            return 700  # Much more space for several hashes
        if is_hash_heavy:
            return 400  # More space for hash conditions
        return 200  # Normal conditions

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


class ConditionStringFormatter:
    """Helper class to format condition strings with reduced complexity."""

    ELLIPSIS_PARENTHESES = "(...)"

    def format_condition(self, condition, depth=0) -> str:
        """Main entry point for condition formatting."""
        if depth > 3:
            return "..."

        if not hasattr(condition, "__class__"):
            return "true"

        class_name = condition.__class__.__name__

        # Use dispatch table for different node types
        formatters = {
            "BooleanLiteral": self._format_boolean_literal,
            "OfExpression": self._format_of_expression,
            "BinaryExpression": lambda c, d: self._format_binary_expression(c, d),
            "Identifier": self._format_identifier,
            "StringIdentifier": self._format_string_identifier,
            "StringCount": self._format_string_count,
            "StringOffset": self._format_string_offset,
            "StringLength": self._format_string_length,
            "FunctionCall": lambda c, d: self._format_function_call(c, d),
            "ParenthesesExpression": lambda c, d: self._format_parentheses(c, d),
            "IntegerLiteral": self._format_integer_literal,
            "StringLiteral": self._format_string_literal,
            "MemberAccess": lambda c, d: self._format_member_access(c, d),
            "ArrayAccess": lambda c, d: self._format_array_access(c, d),
            "ForExpression": self._format_for_expression,
            "ForOfExpression": lambda c, d: "for ... of ...",
        }

        formatter = formatters.get(class_name, lambda c, d: f"<{class_name}>")
        return formatter(condition, depth)

    def _format_boolean_literal(self, condition, _depth):
        return str(condition.value).lower() if hasattr(condition, "value") else "true"

    def _format_of_expression(self, condition, _depth):
        quantifier = getattr(condition, "quantifier", "any")
        string_set = "them"
        if hasattr(condition, "string_set") and hasattr(condition.string_set, "name"):
            string_set = condition.string_set.name
        return f"{quantifier} of {string_set}"

    def _format_binary_expression(self, condition, depth):
        op = getattr(condition, "operator", "and")

        if depth == 0:
            return self._format_top_level_binary(condition, op, depth)
        return self._format_nested_binary(condition, op, depth)

    def _format_top_level_binary(self, condition, op, depth):
        if op in ["and", "or"]:
            return self._format_logical_expression(condition, op)
        return self._format_simple_binary(condition, op, depth)

    def _format_logical_expression(self, condition, op):
        parts = []
        self._collect_binary_parts(condition, op, parts, 0)
        parts = [p for p in parts if p and p != "..."]

        if not parts:
            return self._format_simple_binary(condition, op, 0)

        return self._format_parts_list(parts, op)

    def _format_parts_list(self, parts, op):
        """Format a list of expression parts."""
        hash_prefix = "hash."
        is_hash_condition = any(hash_prefix in p and "==" in p for p in parts[:3] if p)

        if is_hash_condition:
            return self._format_hash_condition(parts, op)
        if len(parts) > 8:
            return self._format_long_condition(parts, op)
        return f" {op} ".join(parts)

    def _format_hash_condition(self, parts, op):
        """Format hash comparison conditions."""
        if len(parts) <= 15:
            return f" {op} ".join(parts)
        if len(parts) <= 25:
            return f" {op} ".join(parts[:10]) + f" {op} ..."
        return f" {op} ".join(parts[:8]) + f" {op} ... {op} " + f" {op} ".join(parts[-2:])

    def _format_long_condition(self, parts, op):
        """Format very long conditions."""
        return f" {op} ".join(parts[:5]) + f" {op} ... {op} " + f" {op} ".join(parts[-2:])

    def _format_simple_binary(self, condition, op, _depth):
        left = self._expr_to_str(condition.left, 0) if hasattr(condition, "left") else "?"
        right = self._expr_to_str(condition.right, 0) if hasattr(condition, "right") else "?"
        return f"{left} {op} {right}"

    def _format_nested_binary(self, condition, op, depth):
        left_str = (
            self.format_condition(condition.left, depth + 1)
            if hasattr(condition, "left")
            else "..."
        )
        right_str = (
            self.format_condition(condition.right, depth + 1)
            if hasattr(condition, "right")
            else "..."
        )
        return f"{left_str} {op} {right_str}"

    def _format_identifier(self, condition, _depth):
        return getattr(condition, "name", "identifier")

    def _format_string_identifier(self, condition, _depth):
        return getattr(condition, "name", "$string")

    def _format_string_count(self, condition, _depth):
        name = getattr(condition, "name", "string")
        return f"#{name}"

    def _format_string_offset(self, condition, _depth):
        name = getattr(condition, "name", "string")
        return f"@{name}"

    def _format_string_length(self, condition, _depth):
        name = getattr(condition, "name", "string")
        return f"!{name}"

    def _format_function_call(self, condition, depth):
        func = getattr(condition, "function", "func")
        args = self._format_function_args(condition, depth)
        return f"{func}({args})"

    def _format_function_args(self, condition, depth):
        if not (hasattr(condition, "arguments") and condition.arguments):
            return ""

        arg_strs = []
        for arg in condition.arguments[:2]:
            arg_strs.append(self.format_condition(arg, depth + 1))
        args = ", ".join(arg_strs)

        if len(condition.arguments) > 2:
            args += ", ..."
        return args

    def _format_parentheses(self, condition, depth):
        if hasattr(condition, "expression"):
            inner = self.format_condition(condition.expression, depth + 1)
            return f"({inner})"
        return self.ELLIPSIS_PARENTHESES

    def _format_integer_literal(self, condition, _depth):
        val = getattr(condition, "value", 0)
        if isinstance(val, int) and val > 255:
            return f"0x{val:X}"
        return str(val)

    def _format_string_literal(self, condition, _depth):
        val = getattr(condition, "value", "")
        if len(val) > 20:
            val = val[:20] + "..."
        return f'"{val}"'

    def _format_member_access(self, condition, depth):
        obj = (
            self.format_condition(condition.object, depth + 1)
            if hasattr(condition, "object")
            else "obj"
        )
        member = getattr(condition, "member", "member")
        return f"{obj}.{member}"

    def _format_array_access(self, condition, depth):
        arr = (
            self.format_condition(condition.array, depth + 1)
            if hasattr(condition, "array")
            else "arr"
        )
        idx = (
            self.format_condition(condition.index, depth + 1)
            if hasattr(condition, "index")
            else "0"
        )
        return f"{arr}[{idx}]"

    def _format_for_expression(self, condition, _depth):
        var = getattr(condition, "identifier", "i")
        return f"for {var} of ..."

    def _collect_binary_parts(self, expr, target_op, parts, depth):
        """Collect parts of a binary expression with the same operator."""
        if depth > 500:
            parts.append("...")
            return

        if not hasattr(expr, "__class__"):
            parts.append("...")
            return

        class_name = expr.__class__.__name__
        if (
            class_name == "BinaryExpression"
            and hasattr(expr, "operator")
            and expr.operator == target_op
        ):
            if hasattr(expr, "left"):
                self._collect_binary_parts(expr.left, target_op, parts, depth + 1)
            if hasattr(expr, "right"):
                self._collect_binary_parts(expr.right, target_op, parts, depth + 1)
        else:
            expr_str = self._expr_to_str(expr, 0)
            parts.append(expr_str)

    def _expr_to_str(self, expr, depth=0) -> str:
        """Convert expression to string with fresh depth counter."""
        formatter = ExpressionStringFormatter()
        return formatter.format_expression(expr, depth)


class ExpressionStringFormatter:
    """Helper class to format expression strings with reduced complexity."""

    def format_expression(self, expr, depth=0) -> str:
        """Format an expression to string representation."""
        if depth > 5:
            return "..."

        if not expr or not hasattr(expr, "__class__"):
            return "..."

        class_name = expr.__class__.__name__

        # Use dispatch table for different expression types
        formatters = {
            "BinaryExpression": self._format_binary_expression,
            "ParenthesesExpression": self._format_parentheses_expression,
            "FunctionCall": self._format_function_call,
            "StringIdentifier": self._format_string_identifier,
            "Identifier": self._format_identifier,
            "IntegerLiteral": self._format_integer_literal,
            "StringLiteral": self._format_string_literal,
            "OfExpression": self._format_of_expression,
            "StringCount": self._format_string_count,
            "StringOffset": self._format_string_offset,
            "ForExpression": self._format_for_expression,
            "MemberAccess": self._format_member_access,
            "RangeExpression": self._format_range_expression,
        }

        formatter = formatters.get(class_name, lambda e, d: f"<{class_name[:10]}>")
        return formatter(expr, depth)

    def _format_binary_expression(self, expr, depth):
        op = getattr(expr, "operator", "?")
        left = self.format_expression(expr.left, depth + 1) if hasattr(expr, "left") else "?"
        right = self.format_expression(expr.right, depth + 1) if hasattr(expr, "right") else "?"
        return f"{left} {op} {right}"

    def _format_parentheses_expression(self, expr, depth):
        inner = (
            self.format_expression(expr.expression, depth + 1)
            if hasattr(expr, "expression")
            else "..."
        )
        return f"({inner})"

    def _format_function_call(self, expr, depth):
        func = getattr(expr, "function", "func")
        args = self._format_function_args(expr, depth)
        return f"{func}({args})"

    def _format_function_args(self, expr, depth):
        if not (hasattr(expr, "arguments") and expr.arguments):
            return ""

        args = ", ".join(self.format_expression(arg, depth + 1) for arg in expr.arguments[:2])
        if len(expr.arguments) > 2:
            args += ", ..."
        return args

    def _format_string_identifier(self, expr, _depth):
        return getattr(expr, "name", "$?")

    def _format_identifier(self, expr, _depth):
        return getattr(expr, "name", "?")

    def _format_integer_literal(self, expr, _depth):
        val = getattr(expr, "value", 0)
        if isinstance(val, int) and val > 255:
            return f"0x{val:X}"
        return str(val)

    def _format_string_literal(self, expr, _depth):
        val = getattr(expr, "value", "")
        if len(val) > 30:
            val = val[:30] + "..."
        return f'"{val}"'

    def _is_hash_value(self, val):
        """Check if string looks like a hash value."""
        return len(val) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in val)

    def _format_of_expression(self, expr, depth):
        quantifier = getattr(expr, "quantifier", "any")
        string_set = self._format_string_set(expr, depth)
        return f"{quantifier} of {string_set}"

    def _format_string_set(self, expr, depth):
        """Format the string set part of an of expression."""
        if not hasattr(expr, "string_set"):
            return "them"

        string_set = expr.string_set
        if hasattr(string_set, "name"):
            return string_set.name

        if not hasattr(string_set, "__class__"):
            return "them"

        s_class = string_set.__class__.__name__
        if s_class == "SetExpression":
            return self._format_set_expression(string_set, depth)
        if s_class == "StringWildcard":
            return self._format_string_wildcard(string_set)
        return "them"

    def _format_set_expression(self, string_set, depth):
        """Format a set expression like ($a, $b, $c)."""
        if not hasattr(string_set, "elements"):
            return self.ELLIPSIS_PARENTHESES

        elements = []
        for el in string_set.elements[:5]:
            if hasattr(el, "name"):
                elements.append(el.name)
            else:
                elements.append(self.format_expression(el, depth + 1))

        if len(string_set.elements) > 5:
            elements.append("...")

        return "(" + ", ".join(elements) + ")"

    def _format_string_wildcard(self, string_set):
        """Format a string wildcard like $a*."""
        if hasattr(string_set, "prefix"):
            return f"(${string_set.prefix}*)"
        return "($*)"

    def _format_string_count(self, expr, _depth):
        return f"#{getattr(expr, 'string_id', '?')}"

    def _format_string_offset(self, expr, depth):
        sid = getattr(expr, "string_id", "?")
        if hasattr(expr, "index") and expr.index is not None:
            idx = self.format_expression(expr.index, depth + 1)
            return f"@{sid}[{idx}]"
        return f"@{sid}"

    def _format_for_expression(self, expr, depth):
        quantifier = getattr(expr, "quantifier", "any")
        variable = getattr(expr, "variable", "i")
        iterable = (
            self.format_expression(expr.iterable, depth + 1) if hasattr(expr, "iterable") else "..."
        )
        body = self.format_expression(expr.body, depth + 1) if hasattr(expr, "body") else "..."
        return f"for {quantifier} {variable} in {iterable} : ({body})"

    def _format_member_access(self, expr, depth):
        obj = self.format_expression(expr.object, depth + 1) if hasattr(expr, "object") else "?"
        member = getattr(expr, "member", "?")
        return f"{obj}.{member}"

    def _format_range_expression(self, expr, depth):
        low = self.format_expression(expr.low, depth + 1) if hasattr(expr, "low") else "0"
        high = self.format_expression(expr.high, depth + 1) if hasattr(expr, "high") else "..."
        return f"({low}..{high})"


class DetailedNodeStringFormatter:
    """Helper class to format detailed node strings."""

    def format_node(self, node, depth=0) -> str:
        """Format a node to detailed string representation."""
        if not node or depth > 2:
            return "..."

        class_name = node.__class__.__name__

        formatters = {
            "StringIdentifier": self._format_string_identifier,
            "IntegerLiteral": self._format_integer_literal,
            "BooleanLiteral": self._format_boolean_literal,
            "StringLiteral": self._format_string_literal,
            "FunctionCall": lambda n, d: self._format_function_call(n, d),
            "BinaryExpression": lambda n, d: self._format_binary_expression(n, d),
            "ParenthesesExpression": lambda n, d: self._format_parentheses(n, d),
            "Identifier": self._format_identifier,
            "MemberAccess": lambda n, d: self._format_member_access(n, d),
        }

        formatter = formatters.get(class_name, lambda n, d: "...")
        return formatter(node, depth)

    def _format_string_identifier(self, node, _depth):
        return getattr(node, "name", "$...")

    def _format_integer_literal(self, node, _depth):
        return str(getattr(node, "value", 0))

    def _format_boolean_literal(self, node, _depth):
        value = getattr(node, "value", True)
        return str(value).lower()

    def _format_string_literal(self, node, _depth):
        val = getattr(node, "value", "")
        if len(val) > 15:
            val = val[:15] + "..."
        return f'"{val}"'

    def _format_function_call(self, node, depth):
        func = getattr(node, "function", "func")
        args = self._format_function_args(node, depth)
        return f"{func}({args})"

    def _format_function_args(self, node, depth):
        if not (hasattr(node, "arguments") and node.arguments):
            return ""
        return self.format_node(node.arguments[0], depth + 1)

    def _format_binary_expression(self, node, depth):
        if depth >= 2:
            return self.ELLIPSIS_PARENTHESES
        # Use the condition formatter for consistency
        formatter = ConditionStringFormatter()
        return formatter.format_condition(node, depth)

    def _format_parentheses(self, node, depth):
        if hasattr(node, "expression"):
            inner = self.format_node(node.expression, depth + 1)
            return f"({inner})"
        return self.ELLIPSIS_PARENTHESES

    def _format_identifier(self, node, _depth):
        return getattr(node, "name", "id")

    def _format_member_access(self, node, depth):
        obj = self.format_node(node.object, depth + 1) if hasattr(node, "object") else "obj"
        member = getattr(node, "member", "member")
        return f"{obj}.{member}"

    def _get_detailed_node_str(self, node, depth=0) -> str:
        """Get detailed string representation of a node."""
        formatter = DetailedNodeStringFormatter()
        return formatter.format_node(node, depth)

    def _get_simple_node_str(self, node: Any) -> str:
        """Get simple string representation of a node."""
        formatter = DetailedNodeStringFormatter()
        return formatter.format_node(node, 2)  # Use depth 2 to get simple version

    # Minimal implementations for other visit methods
    def visit_import(self, _node: Any) -> Tree:
        return Tree("")

    def visit_include(self, _node: Any) -> Tree:
        return Tree("")

    def visit_tag(self, _node: Any) -> Tree:
        return Tree("")

    def visit_string_definition(self, _node: Any) -> Tree:
        return Tree("")

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

    def visit_string_modifier(self, _node: Any) -> Tree:
        return Tree("")

    def visit_hex_token(self, _node: Any) -> Tree:
        return Tree("")

    def visit_hex_byte(self, _node: Any) -> Tree:
        return Tree("")

    def visit_hex_wildcard(self, _node: Any) -> Tree:
        return Tree("")

    def visit_hex_jump(self, _node: Any) -> Tree:
        return Tree("")

    def visit_hex_alternative(self, _node: Any) -> Tree:
        return Tree("")

    def visit_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_identifier(self, _node: Any) -> Tree:
        return Tree("")

    def visit_string_identifier(self, _node: Any) -> Tree:
        return Tree("")

    def visit_string_count(self, _node: Any) -> Tree:
        return Tree("")

    def visit_string_offset(self, _node: Any) -> Tree:
        return Tree("")

    def visit_string_length(self, _node: Any) -> Tree:
        return Tree("")

    def visit_integer_literal(self, _node: Any) -> Tree:
        return Tree("")

    def visit_double_literal(self, _node: Any) -> Tree:
        return Tree("")

    def visit_string_literal(self, _node: Any) -> Tree:
        return Tree("")

    def visit_boolean_literal(self, _node: Any) -> Tree:
        return Tree("")

    def visit_binary_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_unary_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_parentheses_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_set_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_range_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_function_call(self, _node: Any) -> Tree:
        return Tree("")

    def visit_array_access(self, _node: Any) -> Tree:
        return Tree("")

    def visit_member_access(self, _node: Any) -> Tree:
        return Tree("")

    def visit_condition(self, _node: Any) -> Tree:
        return Tree("")

    def visit_for_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_for_of_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_at_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_in_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_of_expression(self, _node: Any) -> Tree:
        return Tree("")

    def visit_meta(self, _node: Any) -> Tree:
        return Tree("")

    # Add missing abstract methods
    def visit_comment(self, node: Any) -> Tree:
        return Tree(f"💬 {node.text if hasattr(node, 'text') else ''}")

    def visit_comment_group(self, node: Any) -> Tree:
        return Tree("💬 Comments")

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


@click.group()
@click.version_option(version="0.1.0", prog_name="yaraast")
def cli() -> None:
    """YARA AST - Parse and manipulate YARA rules."""


# Add commands to CLI
cli.add_command(workspace)
cli.add_command(validate)
cli.add_command(analyze)
cli.add_command(serialize)
cli.add_command(metrics)
cli.add_command(optimize_cmd)
cli.add_command(performance)
cli.add_command(performance_check_cmd)
cli.add_command(semantic)
cli.add_command(fluent)
cli.add_command(roundtrip)
cli.add_command(yaral)
cli.add_command(yarax)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output file (default: stdout)")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["yara", "json", "yaml", "tree"]),
    default="yara",
    help="Output format",
)
@click.option(
    "--dialect",
    type=click.Choice(["auto", "yara", "yara-x", "yara-l"]),
    default="auto",
    help="YARA dialect to use (auto-detect by default)",
)
def parse(input_file: str, output: str | None, format: str, dialect: str) -> None:
    """Parse a YARA file and output in various formats. Supports YARA, YARA-X, and YARA-L."""
    try:
        content = _read_input_file(input_file)
        ast, lexer_errors, parser_errors = _parse_content_by_dialect(content, dialect)
        _report_parsing_errors(lexer_errors, parser_errors, ast)
        _generate_output_by_format(ast, format, output)

    except Exception as e:
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


def _read_input_file(input_file: str) -> str:
    """Read content from input file."""
    with Path(input_file).open() as f:
        return f.read()


def _parse_content_by_dialect(content: str, dialect: str) -> tuple:
    """Parse content based on specified dialect."""
    lexer_errors = []
    parser_errors = []

    if dialect == "auto":
        ast, lexer_errors, parser_errors = _parse_auto_detect_dialect(content)
    elif dialect == "yara-l":
        ast = _parse_yara_l_dialect(content)
    else:
        ast, lexer_errors, parser_errors = _parse_standard_yara_dialect(content)

    return ast, lexer_errors, parser_errors


def _parse_auto_detect_dialect(content: str) -> tuple:
    """Parse with auto-detected dialect."""
    unified_parser = UnifiedParser(content)
    detected_dialect = unified_parser.get_dialect()
    console.print(f"[green]Detected dialect: {detected_dialect.name}[/green]")

    if detected_dialect == YaraDialect.YARA_L:
        ast = unified_parser.parse()
        return ast, [], []
    return _parse_with_error_tolerant_parser(content)


def _parse_yara_l_dialect(content: str):
    """Parse using YARA-L parser."""
    console.print("[green]Using YARA-L parser[/green]")
    from yaraast.yaral.parser import YaraLParser

    parser = YaraLParser(content)
    return parser.parse()


def _parse_standard_yara_dialect(content: str) -> tuple:
    """Parse using standard YARA parser."""
    return _parse_with_error_tolerant_parser(content)


def _parse_with_error_tolerant_parser(content: str) -> tuple:
    """Parse using error-tolerant parser."""
    from yaraast.parser.error_tolerant_parser import ErrorTolerantParser

    error_parser = ErrorTolerantParser()
    return error_parser.parse_with_errors(content)


def _report_parsing_errors(lexer_errors: list, parser_errors: list, ast) -> None:
    """Report lexer and parser errors."""
    total_errors = len(lexer_errors) + len(parser_errors)

    if lexer_errors or parser_errors:
        console.print(f"\\n[yellow]⚠️  Found {total_errors} issue(s) in the file:[/yellow]")

        if lexer_errors:
            _display_lexer_errors(lexer_errors)

        if parser_errors:
            _display_parser_errors(parser_errors)

        if not ast:
            console.print("\\n[red]❌ Could not parse file due to critical errors[/red]")
            raise click.Abort from None

        console.print("\\n[green]✅ Partial parse successful despite errors[/green]\\n")


def _display_lexer_errors(lexer_errors: list) -> None:
    """Display lexer errors."""
    console.print(f"\\n[yellow]Lexer Issues ({len(lexer_errors)}):[/yellow]")
    for error in lexer_errors[:5]:
        console.print(error.format_error())

    if len(lexer_errors) > 5:
        console.print(f"\\n[dim]... and {len(lexer_errors) - 5} more lexer issues[/dim]")


def _display_parser_errors(parser_errors: list) -> None:
    """Display parser errors."""
    console.print(f"\\n[yellow]Parser Issues ({len(parser_errors)}):[/yellow]")
    for error in parser_errors[:5]:
        console.print(error.format_error())

    if len(parser_errors) > 5:
        console.print(f"\\n[dim]... and {len(parser_errors) - 5} more parser issues[/dim]")


def _generate_output_by_format(ast, format: str, output: str | None) -> None:
    """Generate output based on specified format."""
    if format == "yara":
        _generate_yara_output(ast, output)
    elif format == "json":
        _generate_json_output(ast, output)
    elif format == "yaml":
        _generate_yaml_output(ast, output)
    elif format == "tree":
        _generate_tree_output(ast, output)


def _generate_yara_output(ast, output: str | None) -> None:
    """Generate YARA code output."""
    generator = CodeGenerator()
    result = generator.generate(ast)

    if output:
        with Path(output).open("w") as f:
            f.write(result)
        console.print(f"✅ Generated YARA code written to {output}")
    else:
        syntax = Syntax(result, "yara", theme="monokai", line_numbers=True)
        console.print(syntax)


def _generate_json_output(ast, output: str | None) -> None:
    """Generate JSON AST output."""
    dumper = ASTDumper()
    result = dumper.visit(ast)
    json_str = json.dumps(result, indent=2)

    if output:
        with Path(output).open("w") as f:
            f.write(json_str)
        console.print(f"✅ AST JSON written to {output}")
    else:
        syntax = Syntax(json_str, "json", theme="monokai")
        console.print(syntax)


def _generate_yaml_output(ast, output: str | None) -> None:
    """Generate YAML AST output."""
    try:
        import yaml
    except ImportError:
        console.print(
            "[red]❌ Error: PyYAML is not installed. Install it with: pip install pyyaml[/red]"
        )
        raise click.Abort from None

    dumper = ASTDumper()
    result = dumper.visit(ast)
    yaml_str = yaml.dump(
        result,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )

    if output:
        with Path(output).open("w") as f:
            f.write(yaml_str)
        console.print(f"✅ AST YAML written to {output}")
    else:
        syntax = Syntax(yaml_str, "yaml", theme="monokai")
        console.print(syntax)


def _generate_tree_output(ast, output: str | None) -> None:
    """Generate tree visualization output."""
    builder = ASTTreeBuilder()
    tree = builder.visit(ast)

    if output:
        from rich.console import Console

        with open(output, "w") as f:
            file_console = Console(file=f, width=80, legacy_windows=False)
            file_console.print(tree)
        console.print(f"✅ AST tree written to {output}")
    else:
        console.print(tree)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
def validate(input_file: str) -> None:
    """Validate a YARA file for syntax errors."""
    try:
        with Path(input_file).open() as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Count rules
        rule_count = len(ast.rules)
        import_count = len(ast.imports)

        console.print(
            Panel(
                f"[green]✅ Valid YARA file[/green]\n\n"
                f"📊 Statistics:\n"
                f"  • Rules: {rule_count}\n"
                f"  • Imports: {import_count}",
                title=f"Validation Result: {Path(input_file).name}",
                border_style="green",
            ),
        )

    except Exception as e:
        console.print(
            Panel(
                f"[red]❌ Invalid YARA file[/red]\n\nError: {e}",
                title=f"Validation Result: {Path(input_file).name}",
                border_style="red",
            ),
        )
        raise click.Abort from None


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
def format(input_file: str, output_file: str) -> None:
    """Format a YARA file with consistent style."""
    try:
        with Path(input_file).open() as f:
            content = f.read()

        # Parse and regenerate
        parser = Parser()
        ast = parser.parse(content)

        generator = CodeGenerator()
        formatted = generator.generate(ast)

        with Path(output_file).open("w") as f:
            f.write(formatted)

        console.print(f"✅ Formatted YARA file written to {output_file}")

    except Exception as e:
        # Escape the error message to avoid markup interpretation
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


@cli.group()
def libyara() -> None:
    """LibYARA integration commands for compilation and scanning."""


@libyara.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output compiled rules file")
@click.option("--optimize", is_flag=True, help="Enable AST optimizations")
@click.option("--debug", is_flag=True, help="Enable debug mode with source generation")
@click.option("--stats", is_flag=True, help="Show compilation statistics")
def _print_optimization_stats(result) -> None:
    """Print optimization statistics."""
    console.print("[blue]🔧 Optimizations applied:[/blue]")
    if result.optimization_stats:
        opt_stats = result.optimization_stats
        console.print(f"  • Rules optimized: {opt_stats.rules_optimized}")
        console.print(f"  • Strings optimized: {opt_stats.strings_optimized}")
        console.print(f"  • Conditions simplified: {opt_stats.conditions_simplified}")
        console.print(f"  • Constants folded: {opt_stats.constant_folded}")


def _print_compilation_stats(result, compiler) -> None:
    """Print compilation statistics."""
    console.print("[blue]📊 Compilation Stats:[/blue]")
    console.print(f"  • Compilation time: {result.compilation_time:.3f}s")
    console.print(f"  • AST nodes: {result.ast_node_count}")

    comp_stats = compiler.get_compilation_stats()
    console.print(f"  • Total compilations: {comp_stats['total_compilations']}")
    console.print(
        f"  • Success rate: {comp_stats['successful_compilations']}/{comp_stats['total_compilations']}",
    )


def compile(
    input_file: str,
    output: str | None,
    optimize: bool,
    debug: bool,
    stats: bool,
) -> None:
    """Compile YARA file using direct AST compilation."""
    try:
        from yaraast.libyara import YARA_AVAILABLE, DirectASTCompiler

        if not YARA_AVAILABLE:
            console.print("[red]❌ yara-python is not installed[/red]")
            console.print("Install with: pip install yara-python")
            raise click.Abort from None

        # Parse YARA file
        with Path(input_file).open() as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Create direct compiler
        compiler = DirectASTCompiler(enable_optimization=optimize, debug_mode=debug)

        # Compile AST
        result = compiler.compile_ast(ast)

        if not result.success:
            console.print("[red]❌ Compilation failed[/red]")
            for error in result.errors:
                console.print(f"[red]  • {error}[/red]")
            raise click.Abort from None

        console.print("[green]✅ Compilation successful[/green]")

        if result.optimized:
            _print_optimization_stats(result)

        if stats:
            _print_compilation_stats(result, compiler)

        # Save compiled rules if output specified
        if output and result.compiled_rules:
            result.compiled_rules.save(output)
            console.print(f"[green]💾 Compiled rules saved to {output}[/green]")

        if debug and result.generated_source:
            console.print("[dim]🔍 Generated source (first 200 chars):[/dim]")
            console.print(f"[dim]{result.generated_source[:200]}...[/dim]")

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort from None
    except Exception as e:
        # Escape the error message to avoid markup interpretation
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


@libyara.command()
@click.argument("rules_file", type=click.Path(exists=True))
@click.argument("target", type=click.Path(exists=True))
@click.option("--optimize", is_flag=True, help="Use optimized AST compilation")
@click.option("--timeout", type=int, help="Scan timeout in seconds")
@click.option("--fast", is_flag=True, help="Fast mode (stop on first match)")
@click.option("--stats", is_flag=True, help="Show scan statistics")
def scan(
    rules_file: str,
    target: str,
    optimize: bool,
    timeout: int | None,
    fast: bool,
    stats: bool,
) -> None:
    """Scan file using optimized AST-based matcher."""
    try:
        from yaraast.libyara import YARA_AVAILABLE, DirectASTCompiler, OptimizedMatcher

        if not YARA_AVAILABLE:
            console.print("[red]❌ yara-python is not installed[/red]")
            console.print("Install with: pip install yara-python")
            raise click.Abort from None

        # Parse and compile rules
        with Path(rules_file).open() as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Compile with optimization if requested
        compiler = DirectASTCompiler(enable_optimization=optimize)
        compile_result = compiler.compile_ast(ast)

        if not compile_result.success:
            console.print("[red]❌ Rule compilation failed[/red]")
            for error in compile_result.errors:
                console.print(f"[red]  • {error}[/red]")
            raise click.Abort from None

        # Create optimized matcher
        matcher = OptimizedMatcher(compile_result.compiled_rules, ast)

        # Perform scan
        scan_result = matcher.scan(Path(target), timeout=timeout, fast_mode=fast)

        if scan_result["success"]:
            matches = scan_result["matches"]
            console.print("[green]✅ Scan completed[/green]")
            console.print("[blue]📊 Results:[/blue]")
            console.print(f"  • Matches found: {len(matches)}")
            console.print(f"  • Scan time: {scan_result['scan_time']:.3f}s")
            console.print(f"  • Data size: {scan_result['data_size']} bytes")

            if scan_result.get("ast_enhanced"):
                console.print("  • AST-enhanced: ✅")
                console.print(f"  • Rule count: {scan_result['rule_count']}")

            # Show matches
            if matches:
                console.print("\n[yellow]🔍 Matches:[/yellow]")
                for match in matches:
                    console.print(f"  🎯 [bold]{match['rule']}[/bold]")
                    if match.get("tags"):
                        console.print(f"     Tags: {', '.join(match['tags'])}")
                    if match.get("strings"):
                        console.print(f"     Strings: {len(match['strings'])} found")

                    # Show AST context if available
                    if match.get("ast_context"):
                        ctx = match["ast_context"]
                        console.print(
                            f"     Complexity: {ctx.get('condition_complexity', 'N/A')}",
                        )

            # Show optimization hints
            if scan_result.get("optimization_hints"):
                console.print("\n[dim]💡 Optimization Hints:[/dim]")
                for hint in scan_result["optimization_hints"]:
                    console.print(f"[dim]  • {hint}[/dim]")

            if stats:
                matcher_stats = matcher.get_scan_stats()
                console.print("\n[blue]📈 Scan Statistics:[/blue]")
                console.print(f"  • Total scans: {matcher_stats['total_scans']}")
                console.print(f"  • Success rate: {matcher_stats['success_rate']:.1%}")
                console.print(
                    f"  • Average scan time: {matcher_stats['average_scan_time']:.3f}s",
                )

        else:
            console.print(
                f"[red]❌ Scan failed: {scan_result.get('error', 'Unknown error')}[/red]",
            )
            raise click.Abort from None

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort from None
    except Exception as e:
        # Escape the error message to avoid markup interpretation
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


@libyara.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--show-optimizations", is_flag=True, help="Show applied optimizations")
def optimize(input_file: str, show_optimizations: bool) -> None:
    """Optimize YARA rules using AST analysis."""
    try:
        from yaraast.libyara import ASTOptimizer

        # Parse YARA file
        with Path(input_file).open() as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Create optimizer
        optimizer = ASTOptimizer()
        optimized_ast = optimizer.optimize(ast)

        # Generate optimized code
        generator = CodeGenerator()
        optimized_code = generator.generate(optimized_ast)

        console.print("[green]✅ Optimization completed[/green]")
        console.print("[blue]📊 Optimization Stats:[/blue]")
        console.print(f"  • Rules optimized: {optimizer.stats.rules_optimized}")
        console.print(f"  • Strings optimized: {optimizer.stats.strings_optimized}")
        console.print(
            f"  • Conditions simplified: {optimizer.stats.conditions_simplified}",
        )
        console.print(f"  • Constants folded: {optimizer.stats.constant_folded}")

        if show_optimizations and optimizer.optimizations_applied:
            console.print("\n[yellow]🔧 Applied Optimizations:[/yellow]")
            for opt in optimizer.optimizations_applied:
                console.print(f"  • {opt}")

        console.print("\n[dim]📝 Optimized YARA code:[/dim]")
        syntax = Syntax(optimized_code, "yara", theme="monokai", line_numbers=True)
        console.print(syntax)

    except Exception as e:
        # Escape the error message to avoid markup interpretation
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


def _handle_format_check(formatter, input_path) -> None:
    """Handle format checking mode."""
    needs_format, issues = formatter.check_format(input_path)

    if needs_format:
        console.print(f"[yellow]📝 {input_path.name} needs formatting[/yellow]")
        if issues:
            for issue in issues[:5]:  # Show first 5 issues
                console.print(f"[dim]  • {issue}[/dim]")
            if len(issues) > 5:
                console.print(f"[dim]  • ... and {len(issues) - 5} more issues[/dim]")
        raise click.Abort from None
    console.print(f"[green]✅ {input_path.name} is already formatted[/green]")


def _show_format_diff(formatter, input_path, style) -> None:
    """Show formatting diff."""
    with Path(input_path).open() as f:
        original = f.read()

    success, formatted = formatter.format_file(input_path, None, style)
    if not success:
        console.print(f"[red]❌ {formatted}[/red]")
        raise click.Abort from None

    if original.strip() == formatted.strip():
        console.print("[green]✅ No formatting changes needed[/green]")
        return

    console.print(f"[blue]📋 Formatting changes for {input_path.name}:[/blue]")

    diff_lines = unified_diff(
        original.splitlines(keepends=True),
        formatted.splitlines(keepends=True),
        fromfile=f"{input_path.name} (original)",
        tofile=f"{input_path.name} (formatted)",
        lineterm="",
    )

    _print_diff_lines(diff_lines)


def _print_diff_lines(diff_lines) -> None:
    """Print diff lines with colors."""
    for line in diff_lines:
        if line.startswith(("+++", "---")):
            console.print(f"[bold]{line.rstrip()}[/bold]")
        elif line.startswith("@@"):
            console.print(f"[cyan]{line.rstrip()}[/cyan]")
        elif line.startswith("+"):
            console.print(f"[green]{line.rstrip()}[/green]")
        elif line.startswith("-"):
            console.print(f"[red]{line.rstrip()}[/red]")
        else:
            console.print(f"[dim]{line.rstrip()}[/dim]")


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output file (default: overwrite input)",
)
@click.option(
    "--style",
    type=click.Choice(["default", "compact", "pretty", "verbose"]),
    default="default",
    help="Formatting style",
)
@click.option(
    "--check",
    is_flag=True,
    help="Check if file needs formatting (don't modify)",
)
@click.option("--diff", is_flag=True, help="Show formatting changes as diff")
def fmt(
    input_file: str,
    output: str | None,
    style: str,
    check: bool,
    diff: bool,
) -> None:
    """Format YARA file using AST-based formatting (like black for Python)."""
    try:
        from yaraast.cli.ast_tools import ASTFormatter

        input_path = Path(input_file)
        output_path = Path(output) if output else input_path
        formatter = ASTFormatter()

        if check:
            _handle_format_check(formatter, input_path)
            return

        if diff:
            _show_format_diff(formatter, input_path, style)
            return

        # Format file
        success, result = formatter.format_file(input_path, output_path, style)
        if not success:
            console.print(f"[red]❌ {result}[/red]")
            raise click.Abort from None

        if output_path == input_path:
            console.print(
                f"[green]✅ Formatted {input_path.name} ({style} style)[/green]",
            )
        else:
            console.print(f"[green]✅ Formatted file written to {output_path}[/green]")

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort from None
    except Exception as e:
        # Escape the error message to avoid markup interpretation
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


@cli.command()
@click.argument("file1", type=click.Path(exists=True))
@click.argument("file2", type=click.Path(exists=True))
@click.option(
    "--logical-only",
    is_flag=True,
    help="Show only logical changes (ignore style)",
)
@click.option("--summary", is_flag=True, help="Show summary of changes only")
@click.option("--no-style", is_flag=True, help="Don't analyze style changes")
def _show_diff_summary(result) -> None:
    """Show diff summary."""
    console.print("[yellow]📋 Change Summary:[/yellow]")
    for change_type, count in result.change_summary.items():
        if count > 0:
            console.print(f"  • {change_type.replace('_', ' ').title()}: {count}")


def _show_rule_changes(result) -> None:
    """Show rule additions, removals and modifications."""
    if result.added_rules:
        console.print(f"\n[green]+ Added Rules ({len(result.added_rules)}):[/green]")
        for rule in result.added_rules:
            console.print(f"  + {rule}")

    if result.removed_rules:
        console.print(f"\n[red]- Removed Rules ({len(result.removed_rules)}):[/red]")
        for rule in result.removed_rules:
            console.print(f"  - {rule}")

    if result.modified_rules:
        console.print(
            f"\n[yellow]🔄 Modified Rules ({len(result.modified_rules)}):[/yellow]",
        )
        for rule in result.modified_rules:
            console.print(f"  ~ {rule}")


def _show_change_details(result, logical_only, no_style) -> None:
    """Show detailed change information."""
    if result.logical_changes:
        console.print(
            f"\n[red]🧠 Logical Changes ({len(result.logical_changes)}):[/red]",
        )
        for change in result.logical_changes:
            console.print(f"  • {change}")

    if result.structural_changes:
        console.print(
            f"\n[blue]🏗️  Structural Changes ({len(result.structural_changes)}):[/blue]",
        )
        for change in result.structural_changes:
            console.print(f"  • {change}")

    if not logical_only and not no_style and result.style_only_changes:
        console.print(
            f"\n[dim]🎨 Style-Only Changes ({len(result.style_only_changes)}):[/dim]",
        )
        for change in result.style_only_changes[:10]:
            console.print(f"[dim]  • {change}[/dim]")
        if len(result.style_only_changes) > 10:
            console.print(
                f"[dim]  • ... and {len(result.style_only_changes) - 10} more style changes[/dim]",
            )


def _show_change_significance(result) -> None:
    """Show significance of changes."""
    total_logical = (
        len(result.logical_changes) + len(result.added_rules) + len(result.removed_rules)
    )
    total_style = len(result.style_only_changes)

    if total_logical > 0:
        console.print(
            f"\n[yellow]⚠️  This diff contains {total_logical} logical changes that affect rule behavior[/yellow]",
        )
    elif total_style > 0:
        console.print(
            f"\n[green]✨ This diff contains only {total_style} style changes (no logic changes)[/green]",
        )


def diff(
    file1: str,
    file2: str,
    logical_only: bool,
    summary: bool,
    no_style: bool,
) -> None:
    """Show AST-based diff highlighting logical vs stylistic changes."""
    try:
        from yaraast.cli.simple_differ import SimpleASTDiffer

        file1_path = Path(file1)
        file2_path = Path(file2)

        differ = SimpleASTDiffer()
        result = differ.diff_files(file1_path, file2_path)

        if not result.has_changes:
            console.print(
                f"[green]✅ No differences found between {file1_path.name} and {file2_path.name}[/green]",
            )
            return

        console.print(
            f"[blue]📊 AST Diff: {file1_path.name} → {file2_path.name}[/blue]",
        )
        console.print("=" * 60)

        if summary:
            _show_diff_summary(result)
            return

        _show_rule_changes(result)
        _show_change_details(result, logical_only, no_style)
        _show_change_significance(result)

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort from None
    except Exception as e:
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True), required=True)
@click.option(
    "--operations",
    type=click.Choice(["parse", "codegen", "roundtrip", "all"]),
    default="all",
    help="Operations to benchmark",
)
@click.option(
    "--iterations",
    type=int,
    default=10,
    help="Number of iterations per test",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output benchmark results to JSON file",
)
@click.option("--compare", is_flag=True, help="Compare performance across files")
def bench(
    files: tuple[str],
    operations: str,
    iterations: int,
    output: str | None,
    compare: bool,
) -> None:
    """Performance benchmarks for AST operations."""
    try:
        from yaraast.cli.ast_tools import ASTBenchmarker

        file_paths = [Path(f) for f in files]
        benchmarker = ASTBenchmarker()

        _print_benchmark_header(file_paths, iterations)
        all_results = _run_benchmarks_for_all_files(benchmarker, file_paths, operations, iterations)
        summary = _display_benchmark_summary(benchmarker)

        if compare and len(file_paths) > 1:
            _display_performance_comparison(all_results)

        if output:
            _save_benchmark_results(output, iterations, operations, all_results, summary)

        console.print("\n✅ Benchmarking completed!")

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort from None
    except Exception as e:
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


def _print_benchmark_header(file_paths, iterations):
    """Print benchmark header information."""
    console.print("[blue]🏃 Running AST Performance Benchmarks[/blue]")
    console.print(f"Files: {len(file_paths)}, Iterations: {iterations}")
    console.print("=" * 60)


def _run_benchmarks_for_all_files(benchmarker, file_paths, operations, iterations):
    """Run benchmarks for all files and return results."""
    all_results = []

    for file_path in file_paths:
        console.print(f"\n[yellow]📁 Benchmarking {file_path.name}...[/yellow]")
        file_results = _run_benchmarks_for_single_file(
            benchmarker, file_path, operations, iterations
        )

        all_results.append(
            {
                "file": str(file_path),
                "file_name": file_path.name,
                "results": file_results,
            }
        )

    return all_results


def _run_benchmarks_for_single_file(benchmarker, file_path, operations, iterations):
    """Run benchmarks for a single file."""
    ops_to_run = _determine_operations_to_run(operations)
    file_results = {}

    for op in ops_to_run:
        result = _run_single_operation(benchmarker, file_path, op, iterations)
        if result:
            _display_operation_result(op, result)
            if result.success:
                file_results[op] = result

    return file_results


def _determine_operations_to_run(operations):
    """Determine which operations to run based on input."""
    if operations == "all":
        return ["parse", "codegen", "roundtrip"]
    if operations == "roundtrip":
        return ["roundtrip"]
    return [operations]


def _run_single_operation(benchmarker, file_path, op, iterations):
    """Run a single benchmark operation."""
    if op == "parse":
        return benchmarker.benchmark_parsing(file_path, iterations)
    if op == "codegen":
        return benchmarker.benchmark_codegen(file_path, iterations)
    if op == "roundtrip":
        results = benchmarker.benchmark_roundtrip(file_path, iterations)
        return results[0] if results else None
    return None


def _display_operation_result(op, result):
    """Display result of a single operation."""
    if result and result.success:
        console.print(
            f"  ✅ {op:10s}: {result.execution_time * 1000:6.2f}ms "
            f"({result.rules_count} rules, {result.ast_nodes} nodes)",
        )
    elif result:
        console.print(f"  ❌ {op:10s}: {result.error}")


def _display_benchmark_summary(benchmarker):
    """Display benchmark summary and return summary data."""
    summary = benchmarker.get_benchmark_summary()

    console.print("\n[green]📊 Benchmark Summary:[/green]")
    console.print("=" * 60)

    for operation, stats in summary.items():
        console.print(f"\n[bold]{operation.upper()}:[/bold]")
        console.print(f"  • Average time: {stats['avg_time'] * 1000:.2f}ms")
        console.print(f"  • Min time: {stats['min_time'] * 1000:.2f}ms")
        console.print(f"  • Max time: {stats['max_time'] * 1000:.2f}ms")
        console.print(f"  • Files processed: {stats['total_files_processed']}")
        console.print(f"  • Rules processed: {stats['total_rules_processed']}")
        console.print(f"  • Rules/second: {stats['avg_rules_per_second']:.1f}")

    return summary


def _display_performance_comparison(all_results):
    """Display performance comparison between files."""
    console.print("\n[blue]🔍 Performance Comparison:[/blue]")
    console.print("=" * 60)

    parse_results = [
        (r["file_name"], r["results"].get("parse")) for r in all_results if "parse" in r["results"]
    ]

    if parse_results:
        _display_parsing_comparison(parse_results)


def _display_parsing_comparison(parse_results):
    """Display parsing performance comparison."""
    parse_results.sort(
        key=lambda x: x[1].execution_time if x[1] else float("inf"),
    )
    console.print(
        "\n[yellow]Parsing Performance (fastest to slowest):[/yellow]",
    )

    for i, (filename, result) in enumerate(parse_results):
        if result:
            throughput = (
                result.rules_count / result.execution_time if result.execution_time > 0 else 0
            )
            console.print(
                f"  {i + 1:2d}. {filename:20s} "
                f"{result.execution_time * 1000:6.2f}ms "
                f"({throughput:.1f} rules/sec)",
            )


def _save_benchmark_results(output, iterations, operations, all_results, summary):
    """Save benchmark results to JSON file."""
    import json

    benchmark_data = {
        "timestamp": time.time(),
        "iterations": iterations,
        "operations": operations,
        "files": all_results,
        "summary": summary,
    }

    with Path(output).open("w") as f:
        json.dump(benchmark_data, f, indent=2, default=str)

    console.print(f"\n[green]💾 Benchmark results saved to {output}[/green]")


if __name__ == "__main__":
    cli()
