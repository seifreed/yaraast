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
        imports_hash = "|".join(sorted(self.visit(imp) for imp in node.imports))
        includes_hash = "|".join(sorted(self.visit(inc) for inc in node.includes))
        rules_hash = "|".join(sorted(self.visit(rule) for rule in node.rules))
        extern_rules_hash = "|".join(sorted(self.visit(rule) for rule in node.extern_rules))
        extern_imports_hash = "|".join(sorted(self.visit(imp) for imp in node.extern_imports))
        pragmas_hash = self._hash_pragma_sequence(node.pragmas)
        namespaces_hash = "|".join(sorted(self.visit(namespace) for namespace in node.namespaces))
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
        tags = "|".join(sorted(self.visit(tag) for tag in node.tags))
        meta = "|".join(
            sorted(
                f"{getattr(m, 'key', '')}:"
                f"{getattr(m, 'value', '')}:"
                f"{getattr(getattr(m, 'scope', None), 'value', '')}"
                for m in node.meta
            )
        )
        strings = "|".join(sorted(self.visit(s) for s in node.strings))
        condition = self.visit(node.condition) if node.condition else ""
        pragmas = self._hash_in_rule_pragmas(node.pragmas)
        return f"Rule({node.name},{modifiers},{tags},{meta},{strings},{condition},{pragmas})"

    def visit_tag(self, node) -> str:
        """Hash Tag node."""
        return f"Tag({node.name})"

    def visit_plain_string(self, node) -> str:
        """Hash PlainString node."""
        modifiers = self._hash_modifiers(node)
        return f"PlainString({node.identifier},{node.value},{modifiers})"

    def visit_hex_string(self, node) -> str:
        """Hash HexString node."""
        tokens = "|".join(self.visit(token) for token in node.tokens)
        modifiers = self._hash_modifiers(node)
        return f"HexString({node.identifier},{tokens},{modifiers})"

    def visit_regex_string(self, node) -> str:
        """Hash RegexString node."""
        modifiers = self._hash_modifiers(node)
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
        alternatives = []
        for alternative in getattr(node, "alternatives", []):
            if isinstance(alternative, list):
                alternatives.append(" ".join(self._hash_value(token) for token in alternative))
            else:
                alternatives.append(self._hash_value(alternative))
        if not alternatives:
            return "Alt()"
        return f"Alt({'|'.join(sorted(alternatives))})"

    def visit_hex_nibble(self, node) -> str:
        return f"Nibble({node.high},{node.value})"

    def visit_expression(self, node) -> str:
        return "Expr()"

    def visit_string_count(self, node) -> str:
        return f"Count({node.string_id})"

    def visit_string_offset(self, node) -> str:
        index = self._hash_value(getattr(node, "index", None))
        if index:
            return f"Offset({node.string_id},{index})"
        return f"Offset({node.string_id})"

    def visit_string_length(self, node) -> str:
        index = self._hash_value(getattr(node, "index", None))
        if index:
            return f"Length({node.string_id},{index})"
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
        elements = "|".join(sorted(self.visit(elem) for elem in node.elements))
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
            f"ForOf({self._hash_value(node.quantifier)},"
            f"{self._hash_string_set(node.string_set)},{cond})"
        )

    def visit_at_expression(self, node) -> str:
        return f"At({node.string_id},{self.visit(node.offset)})"

    def visit_in_expression(self, node) -> str:
        subject = getattr(node, "subject", getattr(node, "string_id", None))
        return f"In({self._hash_value(subject)},{self.visit(node.range)})"

    def visit_of_expression(self, node) -> str:
        return f"Of({self._hash_value(node.quantifier)},{self._hash_string_set(node.string_set)})"

    def visit_with_statement(self, node) -> str:
        declarations = "|".join(self.visit(declaration) for declaration in node.declarations)
        return f"With({declarations},{self.visit(node.body)})"

    def visit_with_declaration(self, node) -> str:
        return f"WithDecl({node.identifier},{self.visit(node.value)})"

    def visit_array_comprehension(self, node) -> str:
        return (
            f"ArrayComp({self._hash_value(node.expression)},{node.variable},"
            f"{self._hash_value(node.iterable)},{self._hash_value(node.condition)})"
        )

    def visit_dict_comprehension(self, node) -> str:
        return (
            f"DictComp({self._hash_value(node.key_expression)},"
            f"{self._hash_value(node.value_expression)},{node.key_variable},"
            f"{node.value_variable},{self._hash_value(node.iterable)},"
            f"{self._hash_value(node.condition)})"
        )

    def visit_tuple_expression(self, node) -> str:
        elements = "|".join(self.visit(element) for element in node.elements)
        return f"Tuple({elements})"

    def visit_tuple_indexing(self, node) -> str:
        return f"TupleIndex({self.visit(node.tuple_expr)},{self.visit(node.index)})"

    def visit_list_expression(self, node) -> str:
        elements = "|".join(self.visit(element) for element in node.elements)
        return f"List({elements})"

    def visit_dict_expression(self, node) -> str:
        items = "|".join(self.visit(item) for item in node.items)
        return f"DictExpr({items})"

    def visit_dict_item(self, node) -> str:
        return f"DictItem({self.visit(node.key)},{self.visit(node.value)})"

    def visit_slice_expression(self, node) -> str:
        return (
            f"Slice({self.visit(node.target)},{self._hash_value(node.start)},"
            f"{self._hash_value(node.stop)},{self._hash_value(node.step)})"
        )

    def visit_lambda_expression(self, node) -> str:
        parameters = "|".join(node.parameters)
        return f"Lambda({parameters},{self.visit(node.body)})"

    def visit_pattern_match(self, node) -> str:
        cases = "|".join(self.visit(case) for case in node.cases)
        return f"Match({self.visit(node.value)},{cases},{self._hash_value(node.default)})"

    def visit_match_case(self, node) -> str:
        return f"Case({self.visit(node.pattern)},{self.visit(node.result)})"

    def visit_spread_operator(self, node) -> str:
        return f"Spread({self.visit(node.expression)},{node.is_dict})"

    def _hash_value(self, value) -> str:
        """Hash AST values while preserving scalar/list values."""
        if hasattr(value, "accept"):
            return self.visit(value)
        if isinstance(value, list):
            return "[" + "|".join(self._hash_value(item) for item in value) + "]"
        return "" if value is None else str(value)

    def _hash_modifiers(self, node) -> str:
        """Hash string modifiers as an order-insensitive set."""
        return "|".join(sorted(self._hash_value(mod) for mod in getattr(node, "modifiers", [])))

    def _hash_string_set(self, value) -> str:
        """Hash raw string-set lists as order-insensitive collections."""
        if isinstance(value, list):
            return "[" + "|".join(sorted(self._hash_value(item) for item in value)) + "]"
        return self._hash_value(value)

    def _hash_in_rule_pragmas(self, pragmas) -> str:
        """Hash rule pragmas by position while preserving sequential directives."""
        grouped: dict[str, list] = {}
        for pragma in pragmas:
            position = str(getattr(pragma, "position", ""))
            grouped.setdefault(position, []).append(pragma)
        return "|".join(
            f"{position}:{self._hash_pragma_sequence(grouped[position])}"
            for position in sorted(grouped)
        )

    def _hash_pragma_sequence(self, pragmas) -> str:
        """Hash pragma sequences, sorting only contiguous order-insensitive runs."""
        parts: list[str] = []
        unordered_run: list[str] = []

        def flush_unordered_run() -> None:
            if unordered_run:
                parts.append("Set(" + "|".join(sorted(unordered_run)) + ")")
                unordered_run.clear()

        for pragma in pragmas:
            pragma_hash = self.visit(pragma)
            if self._is_order_insensitive_pragma(pragma):
                unordered_run.append(pragma_hash)
            else:
                flush_unordered_run()
                parts.append(pragma_hash)

        flush_unordered_run()
        return "|".join(parts)

    @staticmethod
    def _is_order_insensitive_pragma(node) -> bool:
        pragma = getattr(node, "pragma", node)
        pragma_type = getattr(getattr(pragma, "pragma_type", None), "value", None)
        return pragma_type in {"custom", "include_once"}

    def visit_meta(self, node) -> str:
        return f"Meta({node.key},{node.value})"

    def visit_module_reference(self, node) -> str:
        return f"ModRef({node.module})"

    def visit_dictionary_access(self, node) -> str:
        return f"Dict({self.visit(node.object)},{self._hash_value(node.key)})"

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
        rules = "|".join(sorted(getattr(node, "rules", [])))
        return f"ExternImport({module_path},{alias},{rules})"

    def visit_extern_namespace(self, node) -> str:
        rules = "|".join(sorted(self.visit(rule) for rule in getattr(node, "extern_rules", [])))
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
