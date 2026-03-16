"""AST hashing helpers for diffing."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile


class AstHasher(ASTVisitor[str]):
    """Creates structural hashes of AST nodes."""

    def __init__(self) -> None:
        self._node_hashes: dict[str, str] = {}

    def hash_ast(self, ast: YaraFile) -> str:
        """Create a hash of the entire AST."""
        ast_repr = self.visit(ast)
        return hashlib.sha256(ast_repr.encode()).hexdigest()[:16]

    def hash_node(self, node: ASTNode, path: str = "") -> str:
        """Create a hash of a specific node."""
        node_repr = self.visit(node)
        node_hash = hashlib.sha256(f"{path}:{node_repr}".encode()).hexdigest()[:12]
        self._node_hashes[path] = node_hash
        return node_hash

    def visit_yara_file(self, node: YaraFile) -> str:
        """Hash YaraFile node."""
        imports_hash = "|".join(self.visit(imp) for imp in node.imports)
        includes_hash = "|".join(self.visit(inc) for inc in node.includes)
        rules_hash = "|".join(self.visit(rule) for rule in node.rules)
        return f"YaraFile({imports_hash}|{includes_hash}|{rules_hash})"

    def visit_import(self, node) -> str:
        """Hash Import node."""
        alias = getattr(node, "alias", None)
        return f"Import({node.module},{alias})"

    def visit_include(self, node) -> str:
        """Hash Include node."""
        return f"Include({node.path})"

    def visit_rule(self, node) -> str:
        """Hash Rule node."""
        modifiers = "|".join(sorted(node.modifiers))
        tags = "|".join(self.visit(tag) for tag in node.tags)
        meta = "|".join(f"{k}:{v}" for k, v in sorted(node.meta.items()))
        strings = "|".join(self.visit(s) for s in node.strings)
        condition = self.visit(node.condition) if node.condition else ""
        return f"Rule({node.name},{modifiers},{tags},{meta},{strings},{condition})"

    def visit_tag(self, node) -> str:
        """Hash Tag node."""
        return f"Tag({node.name})"

    def visit_plain_string(self, node) -> str:
        """Hash PlainString node."""
        modifiers = "|".join(self.visit(mod) for mod in node.modifiers)
        return f"PlainString({node.identifier},{node.value},{modifiers})"

    def visit_hex_string(self, node) -> str:
        """Hash HexString node."""
        tokens = "|".join(self.visit(token) for token in node.tokens)
        modifiers = "|".join(self.visit(mod) for mod in node.modifiers)
        return f"HexString({node.identifier},{tokens},{modifiers})"

    def visit_regex_string(self, node) -> str:
        """Hash RegexString node."""
        modifiers = "|".join(self.visit(mod) for mod in node.modifiers)
        return f"RegexString({node.identifier},{node.regex},{modifiers})"

    def visit_string_modifier(self, node) -> str:
        """Hash StringModifier node."""
        return f"Mod({node.name},{node.value})"

    def visit_hex_byte(self, node) -> str:
        """Hash HexByte node."""
        return f"Byte({node.value})"

    def visit_hex_wildcard(self, node) -> str:
        """Hash HexWildcard node."""
        return "Wildcard()"

    def visit_hex_jump(self, node) -> str:
        """Hash HexJump node."""
        return f"Jump({node.min_jump},{node.max_jump})"

    def visit_binary_expression(self, node) -> str:
        """Hash BinaryExpression node."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        return f"Binary({left},{node.operator},{right})"

    def visit_identifier(self, node) -> str:
        """Hash Identifier node."""
        return f"Id({node.name})"

    def visit_string_identifier(self, node) -> str:
        """Hash StringIdentifier node."""
        return f"StrId({node.name})"

    def visit_string_wildcard(self, node) -> str:
        """Visit StringWildcard node."""
        return node.pattern

    def visit_integer_literal(self, node) -> str:
        """Hash IntegerLiteral node."""
        return f"Int({node.value})"

    def visit_boolean_literal(self, node) -> str:
        """Hash BooleanLiteral node."""
        return f"Bool({node.value})"

    def visit_string_definition(self, node) -> str:
        return f"StringDef({node.identifier})"

    def visit_hex_token(self, node) -> str:
        return "Token()"

    def visit_hex_alternative(self, node) -> str:
        return "Alt()"

    def visit_hex_nibble(self, node) -> str:
        return f"Nibble({node.high},{node.value})"

    def visit_expression(self, node) -> str:
        return "Expr()"

    def visit_string_count(self, node) -> str:
        return f"Count({node.string_id})"

    def visit_string_offset(self, node) -> str:
        return f"Offset({node.string_id})"

    def visit_string_length(self, node) -> str:
        return f"Length({node.string_id})"

    def visit_double_literal(self, node) -> str:
        return f"Double({node.value})"

    def visit_string_literal(self, node) -> str:
        return f"Str({node.value})"

    def visit_regex_literal(self, node) -> str:
        return f"Regex({node.pattern},{node.modifiers})"

    def visit_unary_expression(self, node) -> str:
        return f"Unary({node.operator},{self.visit(node.operand)})"

    def visit_parentheses_expression(self, node) -> str:
        return f"Parens({self.visit(node.expression)})"

    def visit_set_expression(self, node) -> str:
        elements = "|".join(self.visit(elem) for elem in node.elements)
        return f"Set({elements})"

    def visit_range_expression(self, node) -> str:
        return f"Range({self.visit(node.low)},{self.visit(node.high)})"

    def visit_function_call(self, node) -> str:
        args = "|".join(self.visit(arg) for arg in node.arguments)
        return f"Call({node.function},{args})"

    def visit_array_access(self, node) -> str:
        return f"Array({self.visit(node.array)},{self.visit(node.index)})"

    def visit_member_access(self, node) -> str:
        return f"Member({self.visit(node.object)},{node.member})"

    def visit_condition(self, node) -> str:
        return "Condition()"

    def visit_for_expression(self, node) -> str:
        return f"For({node.quantifier},{node.variable},{self.visit(node.iterable)},{self.visit(node.body)})"

    def visit_for_of_expression(self, node) -> str:
        cond = self.visit(node.condition) if node.condition else ""
        return f"ForOf({node.quantifier},{self.visit(node.string_set)},{cond})"

    def visit_at_expression(self, node) -> str:
        return f"At({node.string_id},{self.visit(node.offset)})"

    def visit_in_expression(self, node) -> str:
        return f"In({node.string_id},{self.visit(node.range)})"

    def visit_of_expression(self, node) -> str:
        quant = (
            self.visit(node.quantifier)
            if hasattr(node.quantifier, "accept")
            else str(node.quantifier)
        )
        string_set = (
            self.visit(node.string_set)
            if hasattr(node.string_set, "accept")
            else str(node.string_set)
        )
        return f"Of({quant},{string_set})"

    def visit_meta(self, node) -> str:
        return f"Meta({node.key},{node.value})"

    def visit_module_reference(self, node) -> str:
        return f"ModRef({node.module})"

    def visit_dictionary_access(self, node) -> str:
        return f"Dict({self.visit(node.object)},{node.key})"

    def visit_comment(self, node) -> str:
        return f"Comment({node.text},{node.is_multiline})"

    def visit_comment_group(self, node) -> str:
        comments = "|".join(self.visit(c) for c in node.comments)
        return f"CommentGroup({comments})"

    def visit_defined_expression(self, node) -> str:
        return f"Defined({self.visit(node.expression)})"

    def visit_string_operator_expression(self, node) -> str:
        return f"StrOp({self.visit(node.left)},{node.operator},{self.visit(node.right)})"

    def visit_extern_import(self, node) -> str:
        return f"ExternImport({node.module if hasattr(node, 'module') else ''})"

    def visit_extern_namespace(self, node) -> str:
        return f"ExternNamespace({node.name if hasattr(node, 'name') else ''})"

    def visit_extern_rule(self, node) -> str:
        return f"ExternRule({node.name if hasattr(node, 'name') else ''})"

    def visit_extern_rule_reference(self, node) -> str:
        return f"ExternRuleRef({node.name if hasattr(node, 'name') else ''})"

    def visit_in_rule_pragma(self, node) -> str:
        return f"InRulePragma({node.pragma if hasattr(node, 'pragma') else ''})"

    def visit_pragma(self, node) -> str:
        return f"Pragma({node.directive if hasattr(node, 'directive') else ''})"

    def visit_pragma_block(self, node) -> str:
        pragmas = (
            ",".join([self.visit(p) for p in node.pragmas]) if hasattr(node, "pragmas") else ""
        )
        return f"PragmaBlock({pragmas})"
