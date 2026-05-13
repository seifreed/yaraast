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
        extern_rules_hash = "|".join(self.visit(rule) for rule in node.extern_rules)
        extern_imports_hash = "|".join(self.visit(imp) for imp in node.extern_imports)
        pragmas_hash = "|".join(self.visit(pragma) for pragma in node.pragmas)
        namespaces_hash = "|".join(self.visit(namespace) for namespace in node.namespaces)
        return (
            f"YaraFile({imports_hash}|{includes_hash}|{rules_hash}|"
            f"{extern_rules_hash}|{extern_imports_hash}|{pragmas_hash}|{namespaces_hash})"
        )

    def visit_import(self, node) -> str:
        """Hash Import node."""
        alias = getattr(node, "alias", None)
        return f"Import({node.module},{alias})"

    def visit_include(self, node) -> str:
        """Hash Include node."""
        return f"Include({node.path})"

    def visit_rule(self, node) -> str:
        """Hash Rule node."""
        modifiers = "|".join(sorted(str(m) for m in node.modifiers))
        tags = "|".join(self.visit(tag) for tag in node.tags)
        meta = "|".join(
            f"{getattr(m, 'key', '')}:"
            f"{getattr(m, 'value', '')}:"
            f"{getattr(getattr(m, 'scope', None), 'value', '')}"
            for m in node.meta
        )
        strings = "|".join(self.visit(s) for s in node.strings)
        condition = self.visit(node.condition) if node.condition else ""
        pragmas = "|".join(self.visit(pragma) for pragma in node.pragmas)
        return f"Rule({node.name},{modifiers},{tags},{meta},{strings},{condition},{pragmas})"

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

    def visit_hex_negated_byte(self, node) -> str:
        """Hash HexNegatedByte node."""
        return f"NegatedByte({node.value})"

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
        quantifier = self._hash_value(node.quantifier)
        return (
            f"For({quantifier},{node.variable},{self.visit(node.iterable)},{self.visit(node.body)})"
        )

    def visit_for_of_expression(self, node) -> str:
        cond = self.visit(node.condition) if node.condition else ""
        return (
            f"ForOf({self._hash_value(node.quantifier)},{self._hash_value(node.string_set)},{cond})"
        )

    def visit_at_expression(self, node) -> str:
        return f"At({node.string_id},{self.visit(node.offset)})"

    def visit_in_expression(self, node) -> str:
        subject = getattr(node, "subject", getattr(node, "string_id", None))
        return f"In({self._hash_value(subject)},{self.visit(node.range)})"

    def visit_of_expression(self, node) -> str:
        return f"Of({self._hash_value(node.quantifier)},{self._hash_value(node.string_set)})"

    def _hash_value(self, value) -> str:
        """Hash AST values while preserving scalar/list values."""
        if hasattr(value, "accept"):
            return self.visit(value)
        if isinstance(value, list):
            return "[" + "|".join(self._hash_value(item) for item in value) + "]"
        return "" if value is None else str(value)

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
        module_path = getattr(node, "module", getattr(node, "module_path", ""))
        alias = getattr(node, "alias", None)
        rules = "|".join(getattr(node, "rules", []))
        return f"ExternImport({module_path},{alias},{rules})"

    def visit_extern_namespace(self, node) -> str:
        rules = "|".join(self.visit(rule) for rule in getattr(node, "extern_rules", []))
        return f"ExternNamespace({getattr(node, 'name', '')},{rules})"

    def visit_extern_rule(self, node) -> str:
        modifiers = "|".join(sorted(str(mod) for mod in getattr(node, "modifiers", [])))
        namespace = getattr(node, "namespace", None)
        return f"ExternRule({getattr(node, 'name', '')},{modifiers},{namespace})"

    def visit_extern_rule_reference(self, node) -> str:
        rule_name = getattr(node, "name", getattr(node, "rule_name", ""))
        namespace = getattr(node, "namespace", None)
        return f"ExternRuleRef({rule_name},{namespace})"

    def visit_in_rule_pragma(self, node) -> str:
        pragma = getattr(node, "pragma", "")
        pragma_hash = self._hash_value(pragma)
        position = getattr(node, "position", None)
        if position is None:
            return f"InRulePragma({pragma_hash})"
        return f"InRulePragma({pragma_hash},{position})"

    def visit_pragma(self, node) -> str:
        if not hasattr(node, "pragma_type"):
            return f"Pragma({getattr(node, 'directive', '')})"
        args = "|".join(getattr(node, "arguments", []))
        extra_parts = []
        for field_name in ("macro_name", "macro_value", "condition"):
            if hasattr(node, field_name):
                extra_parts.append(f"{field_name}={getattr(node, field_name)}")
        if hasattr(node, "parameters"):
            parameters = ",".join(
                f"{key}={value}" for key, value in sorted(node.parameters.items())
            )
            extra_parts.append(f"parameters={parameters}")
        extra = "|".join(extra_parts)
        return f"Pragma({node.pragma_type.value},{node.name},{args}," f"{node.scope.value},{extra})"

    def visit_pragma_block(self, node) -> str:
        pragmas = (
            ",".join([self.visit(p) for p in node.pragmas]) if hasattr(node, "pragmas") else ""
        )
        scope = getattr(getattr(node, "scope", None), "value", None)
        return f"PragmaBlock({pragmas},{scope})"
