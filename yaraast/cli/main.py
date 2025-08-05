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
            if isinstance(node.modifiers, (list, tuple)):
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
            if isinstance(node.modifiers, (list, tuple)):
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
            if isinstance(node.modifiers, (list, tuple)):
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
            if isinstance(node.modifiers, (list, tuple)):
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
        name_with_modifiers = node.name
        if node.modifiers:
            # Convert modifiers to strings safely
            modifier_strs = []
            for mod in node.modifiers:
                if isinstance(mod, str):
                    modifier_strs.append(mod)
                else:
                    modifier_strs.append(str(mod))
            name_with_modifiers = f"[{'|'.join(modifier_strs)}] {name_with_modifiers}"

        rule_tree = Tree(f"Rule: {name_with_modifiers}")

        if node.tags:
            tags_tree = rule_tree.add("Tags")
            for tag in node.tags:
                if isinstance(tag, str):
                    tags_tree.add(tag)
                else:
                    tags_tree.add(tag.name)

        if node.meta:
            from rich.markup import escape

            meta_tree = rule_tree.add("Meta")
            # Handle meta as dict or list
            if isinstance(node.meta, dict):
                for key, value in node.meta.items():
                    if isinstance(value, str):
                        # Escape value to avoid markup interpretation
                        meta_tree.add(f'{escape(key)} = "{escape(value)}"')
                    else:
                        meta_tree.add(f"{escape(key)} = {value}")
            elif isinstance(node.meta, list):
                for m in node.meta:
                    if hasattr(m, "key") and hasattr(m, "value"):
                        if isinstance(m.value, str):
                            meta_tree.add(f'{escape(m.key)} = "{escape(m.value)}"')
                        else:
                            meta_tree.add(f"{escape(m.key)} = {m.value}")

        if node.strings:
            from rich.markup import escape

            strings_tree = rule_tree.add("Strings")
            for string in node.strings:
                string_type = string.__class__.__name__
                value_preview = ""
                if isinstance(string, PlainString):
                    # Escape the value to avoid markup interpretation
                    escaped_val = escape(string.value[:30]) if string.value else ""
                    value_preview = f' = "{escaped_val}{"..." if len(string.value) > 30 else ""}"'
                elif isinstance(string, RegexString):
                    escaped_regex = escape(string.regex[:30]) if string.regex else ""
                    value_preview = f" = /{escaped_regex}{'...' if len(string.regex) > 30 else ''}/"
                strings_tree.add(f"{string.identifier}{value_preview} [{string_type}]")

        if node.condition:
            condition_tree = rule_tree.add("Condition")
            try:
                # Try to generate condition string
                from yaraast.codegen.generator import CodeGenerator

                condition_str = CodeGenerator().generate(node.condition).strip()
                if not condition_str:
                    # If generator returns empty, use fallback
                    condition_str = self._condition_to_string(node.condition)
            except Exception:
                # Fallback to simple representation
                condition_str = self._condition_to_string(node.condition)

            # Improved condition display - try to show more meaningful content
            # Check if this is a hash-heavy condition
            is_hash_heavy = "hash." in condition_str and condition_str.count("==") > 2

            # Allow even more space for conditions with many hashes
            hash_count = condition_str.count("hash.")
            if hash_count > 10:
                max_length = 1000  # Very long for many hashes (10+ hashes)
            elif hash_count > 5:
                max_length = 700  # Much more space for several hashes
            elif is_hash_heavy:
                max_length = 400  # More space for hash conditions
            else:
                max_length = 200  # Normal conditions

            if len(condition_str) > max_length:
                # Try to break at logical boundaries like ' and ' or ' or '
                for boundary in [" or ", " and ", ", "]:
                    if boundary in condition_str[:max_length]:
                        cut_point = condition_str[:max_length].rfind(boundary)
                        condition_str = condition_str[: cut_point + len(boundary)] + "..."
                        break
                else:
                    condition_str = condition_str[:max_length] + "..."
            # Always add something, even if it's a placeholder
            if condition_str:
                condition_tree.add(condition_str)
            else:
                condition_tree.add("<complex condition>")

        return rule_tree

    def _condition_to_string(self, condition, depth=0) -> str:
        """Convert condition to string representation."""
        if depth > 3:  # Increase recursion depth limit
            return "..."

        if hasattr(condition, "__class__"):
            class_name = condition.__class__.__name__
            if class_name == "BooleanLiteral":
                return str(condition.value).lower()
            if class_name == "OfExpression":
                quantifier = condition.quantifier if hasattr(condition, "quantifier") else "any"
                string_set = "them"
                if hasattr(condition, "string_set") and hasattr(condition.string_set, "name"):
                    string_set = condition.string_set.name
                return f"{quantifier} of {string_set}"
            if class_name == "BinaryExpression":
                op = condition.operator if hasattr(condition, "operator") else "and"
                # For top-level binary expressions, show more detail
                if depth == 0:
                    if op in ["and", "or"]:
                        # Collect all parts of the expression
                        parts = []
                        self._collect_binary_parts(condition, op, parts, 0)
                        # Filter out empty parts
                        parts = [p for p in parts if p and p != "..."]
                        if not parts:
                            # Fallback to simple representation
                            left = (
                                self._expr_to_str(condition.left, 0)
                                if hasattr(condition, "left")
                                else "?"
                            )
                            right = (
                                self._expr_to_str(condition.right, 0)
                                if hasattr(condition, "right")
                                else "?"
                            )
                            return f"{left} {op} {right}"

                        # Check if these are hash comparisons (they tend to be longer)
                        is_hash_condition = any("hash." in p and "==" in p for p in parts[:3] if p)

                        if is_hash_condition:
                            # For hash conditions, show ALL hashes if reasonable, otherwise abbreviate
                            if len(parts) <= 15:
                                # Show ALL if 15 or fewer - no abbreviation for manageable lists
                                result = f" {op} ".join(parts)
                            elif len(parts) <= 25:
                                # Show first 10 and "..." for up to 25
                                result = f" {op} ".join(parts[:10]) + f" {op} ..."
                            else:
                                # Show first 8, ellipsis, and last 2 for very long lists
                                result = (
                                    f" {op} ".join(parts[:8])
                                    + f" {op} ... {op} "
                                    + f" {op} ".join(parts[-2:])
                                )
                        elif len(parts) > 8:
                            # For very long conditions, show first 5 and last 2
                            result = (
                                f" {op} ".join(parts[:5])
                                + f" {op} ... {op} "
                                + f" {op} ".join(parts[-2:])
                            )
                        else:
                            result = f" {op} ".join(parts)
                        return result
                    # Other operators at top level
                    left = (
                        self._expr_to_str(condition.left, 0) if hasattr(condition, "left") else "?"
                    )
                    right = (
                        self._expr_to_str(condition.right, 0)
                        if hasattr(condition, "right")
                        else "?"
                    )
                    return f"{left} {op} {right}"
                # Not top level, use simple representation
                left_str = (
                    self._condition_to_string(condition.left, depth + 1)
                    if hasattr(condition, "left")
                    else "..."
                )
                right_str = (
                    self._condition_to_string(condition.right, depth + 1)
                    if hasattr(condition, "right")
                    else "..."
                )
                return f"{left_str} {op} {right_str}"
            if class_name == "Identifier":
                return condition.name if hasattr(condition, "name") else "identifier"
            if class_name == "StringIdentifier":
                return condition.name if hasattr(condition, "name") else "$string"
            if class_name == "StringCount":
                return f"#{condition.name}" if hasattr(condition, "name") else "#string"
            if class_name == "StringOffset":
                return f"@{condition.name}" if hasattr(condition, "name") else "@string"
            if class_name == "StringLength":
                return f"!{condition.name}" if hasattr(condition, "name") else "!string"
            if class_name == "FunctionCall":
                func = condition.function if hasattr(condition, "function") else "func"
                args = ""
                if hasattr(condition, "arguments") and condition.arguments:
                    arg_strs = []
                    for _i, arg in enumerate(condition.arguments[:2]):
                        arg_strs.append(self._condition_to_string(arg, depth + 1))
                    args = ", ".join(arg_strs)
                    if len(condition.arguments) > 2:
                        args += ", ..."
                return f"{func}({args})"
            if class_name == "ParenthesesExpression":
                if hasattr(condition, "expression"):
                    inner = self._condition_to_string(condition.expression, depth + 1)
                    return f"({inner})"
                return "(...)"
            if class_name == "IntegerLiteral":
                val = condition.value if hasattr(condition, "value") else 0
                # Format hex values nicely
                if isinstance(val, int) and val > 255:
                    return f"0x{val:X}"
                return str(val)
            if class_name == "StringLiteral":
                val = condition.value if hasattr(condition, "value") else ""
                if len(val) > 20:
                    val = val[:20] + "..."
                return f'"{val}"'
            if class_name == "MemberAccess":
                obj = (
                    self._condition_to_string(condition.object, depth + 1)
                    if hasattr(condition, "object")
                    else "obj"
                )
                member = condition.member if hasattr(condition, "member") else "member"
                return f"{obj}.{member}"
            if class_name == "ArrayAccess":
                arr = (
                    self._condition_to_string(condition.array, depth + 1)
                    if hasattr(condition, "array")
                    else "arr"
                )
                idx = (
                    self._condition_to_string(condition.index, depth + 1)
                    if hasattr(condition, "index")
                    else "0"
                )
                return f"{arr}[{idx}]"
            if class_name == "ForExpression":
                var = condition.identifier if hasattr(condition, "identifier") else "i"
                return f"for {var} of ..."
            if class_name == "ForOfExpression":
                return "for ... of ..."
            return f"<{class_name}>"
        return "true"

    def _collect_binary_parts(
        self, expr: Any, target_op: str, parts: list[str], depth: int
    ) -> None:
        """Collect parts of a binary expression with the same operator."""
        if depth > 500:  # Very high limit for extremely deeply nested hash conditions
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
            # Same operator, continue collecting
            if hasattr(expr, "left"):
                self._collect_binary_parts(expr.left, target_op, parts, depth + 1)
            if hasattr(expr, "right"):
                self._collect_binary_parts(expr.right, target_op, parts, depth + 1)
        else:
            # Different operator or leaf node - generate string for this node
            # Use a fresh depth counter to get full representation of this sub-expression
            expr_str = self._expr_to_str(expr, 0)
            parts.append(expr_str)

    def _expr_to_str(self, expr, depth=0) -> str:
        """Convert expression to string with fresh depth counter."""
        if depth > 5:  # Increased depth limit for complex conditions
            return "..."

        if not expr or not hasattr(expr, "__class__"):
            return "..."

        class_name = expr.__class__.__name__

        if class_name == "BinaryExpression":
            op = expr.operator if hasattr(expr, "operator") else "?"
            left = self._expr_to_str(expr.left, depth + 1) if hasattr(expr, "left") else "?"
            right = self._expr_to_str(expr.right, depth + 1) if hasattr(expr, "right") else "?"
            return f"{left} {op} {right}"
        if class_name == "ParenthesesExpression":
            inner = (
                self._expr_to_str(expr.expression, depth + 1)
                if hasattr(expr, "expression")
                else "..."
            )
            return f"({inner})"
        if class_name == "FunctionCall":
            func = expr.function if hasattr(expr, "function") else "func"
            if hasattr(expr, "arguments") and expr.arguments:
                args = ", ".join(self._expr_to_str(arg, depth + 1) for arg in expr.arguments[:2])
                if len(expr.arguments) > 2:
                    args += ", ..."
            else:
                args = ""
            return f"{func}({args})"
        if class_name == "StringIdentifier":
            return expr.name if hasattr(expr, "name") else "$?"
        if class_name == "Identifier":
            return expr.name if hasattr(expr, "name") else "?"
        if class_name == "IntegerLiteral":
            val = expr.value if hasattr(expr, "value") else 0
            if isinstance(val, int) and val > 255:
                return f"0x{val:X}"
            return str(val)
        if class_name == "StringLiteral":
            val = expr.value if hasattr(expr, "value") else ""
            # Don't truncate hash values (32 chars for MD5, 40 for SHA1, 64 for SHA256)
            if len(val) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in val):
                # It's likely a hash, show it complete
                return f'"{val}"'
            if len(val) > 30:  # Increased limit for other strings
                val = val[:30] + "..."
            return f'"{val}"'
        if class_name == "OfExpression":
            q = expr.quantifier if hasattr(expr, "quantifier") else "any"
            if hasattr(expr, "string_set"):
                if hasattr(expr.string_set, "name"):
                    s = expr.string_set.name
                elif hasattr(expr.string_set, "__class__"):
                    # Handle complex string sets like ($a*)
                    s_class = expr.string_set.__class__.__name__
                    if s_class == "SetExpression":
                        # Try to show the set elements
                        if hasattr(expr.string_set, "elements"):
                            elements = []
                            for el in expr.string_set.elements[:5]:  # Show more elements
                                if hasattr(el, "name"):
                                    elements.append(el.name)
                                else:
                                    # Handle other types
                                    elements.append(self._expr_to_str(el, depth + 1))
                            if len(expr.string_set.elements) > 5:
                                elements.append("...")
                            s = "(" + ", ".join(elements) + ")"
                        else:
                            s = "(...)"
                    elif s_class == "StringWildcard":
                        if hasattr(expr.string_set, "prefix"):
                            s = f"(${expr.string_set.prefix}*)"
                        else:
                            s = "($*)"
                    else:
                        s = "them"
                else:
                    s = "them"
            else:
                s = "them"
            return f"{q} of {s}"
        if class_name == "StringCount":
            return f"#{expr.string_id}" if hasattr(expr, "string_id") else "#?"
        if class_name == "StringOffset":
            sid = expr.string_id if hasattr(expr, "string_id") else "?"
            if hasattr(expr, "index") and expr.index is not None:
                idx = self._expr_to_str(expr.index, depth + 1)
                return f"@{sid}[{idx}]"
            return f"@{sid}"
        if class_name == "ForExpression":
            q = expr.quantifier if hasattr(expr, "quantifier") else "any"
            v = expr.variable if hasattr(expr, "variable") else "i"
            it = self._expr_to_str(expr.iterable, depth + 1) if hasattr(expr, "iterable") else "..."
            body = self._expr_to_str(expr.body, depth + 1) if hasattr(expr, "body") else "..."
            return f"for {q} {v} in {it} : ({body})"
        if class_name == "MemberAccess":
            obj = self._expr_to_str(expr.object, depth + 1) if hasattr(expr, "object") else "?"
            member = expr.member if hasattr(expr, "member") else "?"
            return f"{obj}.{member}"
        if class_name == "RangeExpression":
            low = self._expr_to_str(expr.low, depth + 1) if hasattr(expr, "low") else "0"
            high = self._expr_to_str(expr.high, depth + 1) if hasattr(expr, "high") else "..."
            return f"({low}..{high})"
        return f"<{class_name[:10]}>"

    def _get_detailed_node_str(self, node, depth=0) -> str:
        """Get detailed string representation of a node."""
        if not node or depth > 2:
            return "..."
        class_name = node.__class__.__name__
        if class_name == "StringIdentifier":
            return node.name if hasattr(node, "name") else "$..."
        if class_name == "IntegerLiteral":
            return str(node.value) if hasattr(node, "value") else "0"
        if class_name == "BooleanLiteral":
            return str(node.value).lower() if hasattr(node, "value") else "true"
        if class_name == "StringLiteral":
            val = node.value if hasattr(node, "value") else ""
            if len(val) > 15:
                val = val[:15] + "..."
            return f'"{val}"'
        if class_name == "FunctionCall":
            func = node.function if hasattr(node, "function") else "func"
            if hasattr(node, "arguments") and node.arguments:
                args = (
                    self._get_detailed_node_str(node.arguments[0], depth + 1)
                    if node.arguments
                    else ""
                )
            else:
                args = ""
            return f"{func}({args})"
        if class_name == "BinaryExpression":
            if depth >= 2:
                return "(...)"
            return self._condition_to_string(node, depth)
        if class_name == "ParenthesesExpression":
            if hasattr(node, "expression"):
                return f"({self._get_detailed_node_str(node.expression, depth + 1)})"
            return "(...)"
        if class_name == "Identifier":
            return node.name if hasattr(node, "name") else "id"
        if class_name == "MemberAccess":
            obj = (
                self._get_detailed_node_str(node.object, depth + 1)
                if hasattr(node, "object")
                else "obj"
            )
            member = node.member if hasattr(node, "member") else "member"
            return f"{obj}.{member}"
        return "..."

    def _get_simple_node_str(self, node: Any) -> str:
        """Get simple string representation of a node."""
        return self._get_detailed_node_str(node, 2)  # Use depth 2 to get simple version

    # Minimal implementations for other visit methods
    def visit_import(self, node: Any) -> Tree:
        return Tree("")

    def visit_include(self, node: Any) -> Tree:
        return Tree("")

    def visit_tag(self, node: Any) -> Tree:
        return Tree("")

    def visit_string_definition(self, node: Any) -> Tree:
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

    def visit_string_modifier(self, node: Any) -> Tree:
        return Tree("")

    def visit_hex_token(self, node: Any) -> Tree:
        return Tree("")

    def visit_hex_byte(self, node: Any) -> Tree:
        return Tree("")

    def visit_hex_wildcard(self, node: Any) -> Tree:
        return Tree("")

    def visit_hex_jump(self, node: Any) -> Tree:
        return Tree("")

    def visit_hex_alternative(self, node: Any) -> Tree:
        return Tree("")

    def visit_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_identifier(self, node: Any) -> Tree:
        return Tree("")

    def visit_string_identifier(self, node: Any) -> Tree:
        return Tree("")

    def visit_string_count(self, node: Any) -> Tree:
        return Tree("")

    def visit_string_offset(self, node: Any) -> Tree:
        return Tree("")

    def visit_string_length(self, node: Any) -> Tree:
        return Tree("")

    def visit_integer_literal(self, node: Any) -> Tree:
        return Tree("")

    def visit_double_literal(self, node: Any) -> Tree:
        return Tree("")

    def visit_string_literal(self, node: Any) -> Tree:
        return Tree("")

    def visit_boolean_literal(self, node: Any) -> Tree:
        return Tree("")

    def visit_binary_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_unary_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_parentheses_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_set_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_range_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_function_call(self, node: Any) -> Tree:
        return Tree("")

    def visit_array_access(self, node: Any) -> Tree:
        return Tree("")

    def visit_member_access(self, node: Any) -> Tree:
        return Tree("")

    def visit_condition(self, node: Any) -> Tree:
        return Tree("")

    def visit_for_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_for_of_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_at_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_in_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_of_expression(self, node: Any) -> Tree:
        return Tree("")

    def visit_meta(self, node: Any) -> Tree:
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
def parse(input_file: str, output: str | None, format: str) -> None:
    """Parse a YARA file and output in various formats."""
    try:
        # Read input file
        with Path(input_file).open() as f:
            content = f.read()

        # Try with error-tolerant parser
        from yaraast.parser.error_tolerant_parser import ErrorTolerantParser

        # Parse with error collection
        error_parser = ErrorTolerantParser()
        ast, lexer_errors, parser_errors = error_parser.parse_with_errors(content)

        # Report any errors found
        total_errors = len(lexer_errors) + len(parser_errors)

        if lexer_errors or parser_errors:
            console.print(f"\n[yellow]⚠️  Found {total_errors} issue(s) in the file:[/yellow]")

            # Show lexer errors
            if lexer_errors:
                console.print(f"\n[yellow]Lexer Issues ({len(lexer_errors)}):[/yellow]")
                for error in lexer_errors[:5]:  # Show first 5
                    console.print(error.format_error())

                if len(lexer_errors) > 5:
                    console.print(f"\n[dim]... and {len(lexer_errors) - 5} more lexer issues[/dim]")

            # Show parser errors
            if parser_errors:
                console.print(f"\n[yellow]Parser Issues ({len(parser_errors)}):[/yellow]")
                for error in parser_errors[:5]:  # Show first 5
                    console.print(error.format_error())

                if len(parser_errors) > 5:
                    console.print(
                        f"\n[dim]... and {len(parser_errors) - 5} more parser issues[/dim]"
                    )

            # If we couldn't parse anything, exit
            if not ast:
                console.print("\n[red]❌ Could not parse file due to critical errors[/red]")
                raise click.Abort from None

            console.print("\n[green]✅ Partial parse successful despite errors[/green]\n")

        # Generate output based on format
        if format == "yara":
            generator = CodeGenerator()
            result = generator.generate(ast)
            if output:
                with Path(output).open("w") as f:
                    f.write(result)
                console.print(f"✅ Generated YARA code written to {output}")
            else:
                syntax = Syntax(result, "yara", theme="monokai", line_numbers=True)
                console.print(syntax)

        elif format == "json":
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

        elif format == "yaml":
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
                result, default_flow_style=False, allow_unicode=True, sort_keys=False
            )
            if output:
                with Path(output).open("w") as f:
                    f.write(yaml_str)
                console.print(f"✅ AST YAML written to {output}")
            else:
                syntax = Syntax(yaml_str, "yaml", theme="monokai")
                console.print(syntax)

        elif format == "tree":
            builder = ASTTreeBuilder()
            tree = builder.visit(ast)
            if output:
                # For file output, use rich console to capture output
                from rich.console import Console

                with open(output, "w") as f:
                    file_console = Console(file=f, width=80, legacy_windows=False)
                    file_console.print(tree)
                console.print(f"✅ AST tree written to {output}")
            else:
                # For console output, print directly
                console.print(tree)

    except Exception as e:
        # Escape the error message to avoid markup interpretation
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


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
            )
        )

    except Exception as e:
        console.print(
            Panel(
                f"[red]❌ Invalid YARA file[/red]\n\nError: {e}",
                title=f"Validation Result: {Path(input_file).name}",
                border_style="red",
            )
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
def _print_optimization_stats(result):
    """Print optimization statistics."""
    console.print("[blue]🔧 Optimizations applied:[/blue]")
    if result.optimization_stats:
        opt_stats = result.optimization_stats
        console.print(f"  • Rules optimized: {opt_stats.rules_optimized}")
        console.print(f"  • Strings optimized: {opt_stats.strings_optimized}")
        console.print(f"  • Conditions simplified: {opt_stats.conditions_simplified}")
        console.print(f"  • Constants folded: {opt_stats.constant_folded}")


def _print_compilation_stats(result, compiler):
    """Print compilation statistics."""
    console.print("[blue]📊 Compilation Stats:[/blue]")
    console.print(f"  • Compilation time: {result.compilation_time:.3f}s")
    console.print(f"  • AST nodes: {result.ast_node_count}")

    comp_stats = compiler.get_compilation_stats()
    console.print(f"  • Total compilations: {comp_stats['total_compilations']}")
    console.print(
        f"  • Success rate: {comp_stats['successful_compilations']}/{comp_stats['total_compilations']}"
    )


def compile(input_file: str, output: str | None, optimize: bool, debug: bool, stats: bool):
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
):
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
                        console.print(f"     Complexity: {ctx.get('condition_complexity', 'N/A')}")

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
                console.print(f"  • Average scan time: {matcher_stats['average_scan_time']:.3f}s")

        else:
            console.print(f"[red]❌ Scan failed: {scan_result.get('error', 'Unknown error')}[/red]")
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
        console.print(f"  • Conditions simplified: {optimizer.stats.conditions_simplified}")
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


def _handle_format_check(formatter, input_path):
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


def _show_format_diff(formatter, input_path, style):
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


def _print_diff_lines(diff_lines):
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
@click.option("-o", "--output", type=click.Path(), help="Output file (default: overwrite input)")
@click.option(
    "--style",
    type=click.Choice(["default", "compact", "pretty", "verbose"]),
    default="default",
    help="Formatting style",
)
@click.option("--check", is_flag=True, help="Check if file needs formatting (don't modify)")
@click.option("--diff", is_flag=True, help="Show formatting changes as diff")
def fmt(input_file: str, output: str | None, style: str, check: bool, diff: bool) -> None:
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
            console.print(f"[green]✅ Formatted {input_path.name} ({style} style)[/green]")
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
@click.option("--logical-only", is_flag=True, help="Show only logical changes (ignore style)")
@click.option("--summary", is_flag=True, help="Show summary of changes only")
@click.option("--no-style", is_flag=True, help="Don't analyze style changes")
def _show_diff_summary(result):
    """Show diff summary."""
    console.print("[yellow]📋 Change Summary:[/yellow]")
    for change_type, count in result.change_summary.items():
        if count > 0:
            console.print(f"  • {change_type.replace('_', ' ').title()}: {count}")


def _show_rule_changes(result):
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
        console.print(f"\n[yellow]🔄 Modified Rules ({len(result.modified_rules)}):[/yellow]")
        for rule in result.modified_rules:
            console.print(f"  ~ {rule}")


def _show_change_details(result, logical_only, no_style):
    """Show detailed change information."""
    if result.logical_changes:
        console.print(f"\n[red]🧠 Logical Changes ({len(result.logical_changes)}):[/red]")
        for change in result.logical_changes:
            console.print(f"  • {change}")

    if result.structural_changes:
        console.print(f"\n[blue]🏗️  Structural Changes ({len(result.structural_changes)}):[/blue]")
        for change in result.structural_changes:
            console.print(f"  • {change}")

    if not logical_only and not no_style and result.style_only_changes:
        console.print(f"\n[dim]🎨 Style-Only Changes ({len(result.style_only_changes)}):[/dim]")
        for change in result.style_only_changes[:10]:
            console.print(f"[dim]  • {change}[/dim]")
        if len(result.style_only_changes) > 10:
            console.print(
                f"[dim]  • ... and {len(result.style_only_changes) - 10} more style changes[/dim]"
            )


def _show_change_significance(result):
    """Show significance of changes."""
    total_logical = (
        len(result.logical_changes) + len(result.added_rules) + len(result.removed_rules)
    )
    total_style = len(result.style_only_changes)

    if total_logical > 0:
        console.print(
            f"\n[yellow]⚠️  This diff contains {total_logical} logical changes that affect rule behavior[/yellow]"
        )
    elif total_style > 0:
        console.print(
            f"\n[green]✨ This diff contains only {total_style} style changes (no logic changes)[/green]"
        )


def diff(file1: str, file2: str, logical_only: bool, summary: bool, no_style: bool) -> None:
    """Show AST-based diff highlighting logical vs stylistic changes."""
    try:
        from yaraast.cli.simple_differ import SimpleASTDiffer

        file1_path = Path(file1)
        file2_path = Path(file2)

        differ = SimpleASTDiffer()
        result = differ.diff_files(file1_path, file2_path)

        if not result.has_changes:
            console.print(
                f"[green]✅ No differences found between {file1_path.name} and {file2_path.name}[/green]"
            )
            return

        console.print(f"[blue]📊 AST Diff: {file1_path.name} → {file2_path.name}[/blue]")
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
@click.option("--iterations", type=int, default=10, help="Number of iterations per test")
@click.option("--output", type=click.Path(), help="Output benchmark results to JSON file")
@click.option("--compare", is_flag=True, help="Compare performance across files")
def bench(
    files: tuple[str],
    operations: str,
    iterations: int,
    output: str | None,
    compare: bool,
):
    """Performance benchmarks for AST operations."""
    try:
        import json

        from yaraast.cli.ast_tools import ASTBenchmarker

        file_paths = [Path(f) for f in files]
        benchmarker = ASTBenchmarker()

        console.print("[blue]🏃 Running AST Performance Benchmarks[/blue]")
        console.print(f"Files: {len(file_paths)}, Iterations: {iterations}")
        console.print("=" * 60)

        all_results = []

        for file_path in file_paths:
            console.print(f"\n[yellow]📁 Benchmarking {file_path.name}...[/yellow]")

            # Determine operations to run
            ops_to_run = []
            if operations == "all":
                ops_to_run = ["parse", "codegen", "roundtrip"]
            elif operations == "roundtrip":
                ops_to_run = ["roundtrip"]
            else:
                ops_to_run = [operations]

            file_results = {}

            for op in ops_to_run:
                if op == "parse":
                    result = benchmarker.benchmark_parsing(file_path, iterations)
                elif op == "codegen":
                    result = benchmarker.benchmark_codegen(file_path, iterations)
                elif op == "roundtrip":
                    results = benchmarker.benchmark_roundtrip(file_path, iterations)
                    result = results[0] if results else None

                if result and result.success:
                    file_results[op] = result
                    console.print(
                        f"  ✅ {op:10s}: {result.execution_time * 1000:6.2f}ms "
                        f"({result.rules_count} rules, {result.ast_nodes} nodes)"
                    )
                elif result:
                    console.print(f"  ❌ {op:10s}: {result.error}")

            all_results.append(
                {
                    "file": str(file_path),
                    "file_name": file_path.name,
                    "results": file_results,
                }
            )

        # Show summary
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

        if compare and len(file_paths) > 1:
            console.print("\n[blue]🔍 Performance Comparison:[/blue]")
            console.print("=" * 60)

            # Compare parsing times
            parse_results = [
                (r["file_name"], r["results"].get("parse"))
                for r in all_results
                if "parse" in r["results"]
            ]

            if parse_results:
                parse_results.sort(key=lambda x: x[1].execution_time if x[1] else float("inf"))
                console.print("\n[yellow]Parsing Performance (fastest to slowest):[/yellow]")

                for i, (filename, result) in enumerate(parse_results):
                    if result:
                        throughput = (
                            result.rules_count / result.execution_time
                            if result.execution_time > 0
                            else 0
                        )
                        console.print(
                            f"  {i + 1:2d}. {filename:20s} "
                            f"{result.execution_time * 1000:6.2f}ms "
                            f"({throughput:.1f} rules/sec)"
                        )

        # Save results if requested
        if output:
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

        console.print("\n✅ Benchmarking completed!")

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort from None
    except Exception as e:
        # Escape the error message to avoid markup interpretation
        from rich.markup import escape

        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise click.Abort from None


if __name__ == "__main__":
    cli()
