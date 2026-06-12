"""AST hashing helpers for diffing."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from yaraast.ast.expressions import Expression
from yaraast.ast.strings import HexAlternative, HexByte, HexToken
from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile


def _meta_value_repr(value: Any) -> str:
    """Encode a meta value with its type so that equal string forms of
    distinct types (e.g. the integer ``42`` and the string ``"42"``) hash
    differently."""
    if isinstance(value, bool):
        return f"bool:{value}"
    if isinstance(value, int):
        return f"int:{value}"
    if isinstance(value, float):
        return f"float:{value}"
    if isinstance(value, str):
        return f"str:{value}"
    return f"{type(value).__name__}:{value}"


def _validate_real_hex_token(node: Any) -> None:
    if isinstance(node, HexToken):
        validate_structure = getattr(node, "validate_structure", None)
        if callable(validate_structure):
            validate_structure()


def _validate_real_expression(node: Any) -> None:
    if isinstance(node, Expression):
        validate_structure = getattr(node, "validate_structure", None)
        if callable(validate_structure):
            validate_structure()


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
        from yaraast.ast.base import YaraFile

        if isinstance(node, YaraFile):
            node.validate_structure(deep=False)
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
        module = _required_string_attr(node, "module", "Import module")
        alias = _optional_string_attr(node, "alias", "Import alias")
        return f"Import({module},{alias})"

    def visit_include(self, node) -> str:
        """Hash Include node."""
        path = _required_string_attr(node, "path", "Include path")
        return f"Include({path})"

    def visit_rule(self, node) -> str:
        """Hash Rule node."""
        from yaraast.ast.rules import Rule

        if isinstance(node, Rule):
            node.validate_structure()
        name = _required_string_attr(node, "name", "Rule name")
        modifiers = "|".join(sorted(str(m) for m in node.modifiers))
        tags = "|".join(sorted(self.visit(tag) for tag in node.tags))
        meta = "|".join(
            sorted(
                f"{getattr(m, 'key', '')}:"
                f"{_meta_value_repr(getattr(m, 'value', ''))}:"
                f"{getattr(getattr(m, 'scope', None), 'value', '')}"
                for m in node.meta
            )
        )
        strings = "|".join(sorted(self.visit(s) for s in node.strings))
        condition = self.visit(node.condition) if node.condition is not None else ""
        pragmas = self._hash_in_rule_pragmas(node.pragmas)
        return f"Rule({name},{modifiers},{tags},{meta},{strings},{condition},{pragmas})"

    def visit_tag(self, node) -> str:
        """Hash Tag node."""
        name = _required_string_attr(node, "name", "Tag name")
        return f"Tag({name})"

    def visit_plain_string(self, node) -> str:
        """Hash PlainString node."""
        from yaraast.ast.strings import PlainString

        if isinstance(node, PlainString):
            node.validate_structure()
        modifiers = self._hash_modifiers(node)
        return (
            f"PlainString({node.identifier},{node.value},"
            f"{getattr(node, 'is_anonymous', False)},{modifiers})"
        )

    def visit_hex_string(self, node) -> str:
        """Hash HexString node."""
        from yaraast.ast.strings import HexString

        if isinstance(node, HexString):
            node.validate_structure()
        tokens = "|".join(self.visit(token) for token in node.tokens)
        modifiers = self._hash_modifiers(node)
        return (
            f"HexString({node.identifier},{tokens},"
            f"{getattr(node, 'is_anonymous', False)},{modifiers})"
        )

    def visit_regex_string(self, node) -> str:
        """Hash RegexString node."""
        from yaraast.ast.strings import RegexString

        if isinstance(node, RegexString):
            node.validate_structure()
        modifiers = self._hash_modifiers(node)
        return (
            f"RegexString({node.identifier},{node.regex},"
            f"{getattr(node, 'is_anonymous', False)},{modifiers})"
        )

    def visit_string_modifier(self, node) -> str:
        """Hash StringModifier node."""
        from yaraast.ast.modifiers import StringModifier

        if isinstance(node, StringModifier):
            node.validate_structure()
        return f"Mod({node.name},{node.value})"

    def visit_hex_byte(self, node) -> str:
        """Hash HexByte node."""
        _validate_real_hex_token(node)
        return f"Byte({node.value})"

    def visit_hex_negated_byte(self, node) -> str:
        """Hash HexNegatedByte node."""
        _validate_real_hex_token(node)
        return f"NegatedByte({node.value})"

    def visit_hex_wildcard(self, node) -> str:
        """Hash HexWildcard node."""
        _validate_real_hex_token(node)
        return "Wildcard()"

    def visit_hex_jump(self, node) -> str:
        """Hash HexJump node."""
        _validate_real_hex_token(node)
        return f"Jump({node.min_jump},{node.max_jump})"

    def visit_binary_expression(self, node) -> str:
        """Hash BinaryExpression node."""
        _validate_real_expression(node)
        left = self.visit(node.left)
        right = self.visit(node.right)
        return f"Binary({left},{node.operator},{right})"

    def visit_identifier(self, node) -> str:
        """Hash Identifier node."""
        _validate_real_expression(node)
        return f"Id({node.name})"

    def visit_string_identifier(self, node) -> str:
        """Hash StringIdentifier node."""
        _validate_real_expression(node)
        return f"StrId({node.name})"

    def visit_string_wildcard(self, node) -> str:
        """Visit StringWildcard node."""
        _validate_real_expression(node)
        return node.pattern

    def visit_integer_literal(self, node) -> str:
        """Hash IntegerLiteral node."""
        _validate_real_expression(node)
        return f"Int({node.value})"

    def visit_boolean_literal(self, node) -> str:
        """Hash BooleanLiteral node."""
        _validate_real_expression(node)
        return f"Bool({node.value})"

    def visit_string_definition(self, node) -> str:
        return f"StringDef({node.identifier},{getattr(node, 'is_anonymous', False)})"

    def visit_hex_token(self, node) -> str:
        _validate_real_hex_token(node)
        return "Token()"

    def visit_hex_alternative(self, node) -> str:
        if isinstance(node, HexAlternative):
            node.validate_structure()
        alternatives = []
        for alternative in getattr(node, "alternatives", []):
            alternatives.append(self._hash_hex_alternative_branch(alternative))
        if not alternatives:
            return "Alt()"
        return f"Alt({'|'.join(sorted(alternatives))})"

    def _hash_hex_alternative_branch(self, alternative) -> str:
        if isinstance(alternative, list):
            return " ".join(self._hash_hex_alternative_token(token) for token in alternative)
        return self._hash_hex_alternative_token(alternative)

    def _hash_hex_alternative_token(self, token) -> str:
        if isinstance(token, HexToken):
            _validate_real_hex_token(token)
            return self._hash_value(token)
        return self._hash_value(HexByte(token))

    def visit_hex_nibble(self, node) -> str:
        _validate_real_hex_token(node)
        return f"Nibble({node.high},{node.value})"

    def visit_expression(self, node) -> str:
        _validate_real_expression(node)
        return "Expr()"

    def visit_string_count(self, node) -> str:
        _validate_real_expression(node)
        return f"Count({node.string_id})"

    def visit_string_offset(self, node) -> str:
        _validate_real_expression(node)
        index = self._hash_value(getattr(node, "index", None))
        if index:
            return f"Offset({node.string_id},{index})"
        return f"Offset({node.string_id})"

    def visit_string_length(self, node) -> str:
        _validate_real_expression(node)
        index = self._hash_value(getattr(node, "index", None))
        if index:
            return f"Length({node.string_id},{index})"
        return f"Length({node.string_id})"

    def visit_double_literal(self, node) -> str:
        _validate_real_expression(node)
        return f"Double({node.value})"

    def visit_string_literal(self, node) -> str:
        _validate_real_expression(node)
        return f"Str({node.value})"

    def visit_regex_literal(self, node) -> str:
        _validate_real_expression(node)
        return f"Regex({node.pattern},{node.modifiers})"

    def visit_unary_expression(self, node) -> str:
        _validate_real_expression(node)
        return f"Unary({node.operator},{self.visit(node.operand)})"

    def visit_parentheses_expression(self, node) -> str:
        _validate_real_expression(node)
        return f"Parens({self.visit(node.expression)})"

    def visit_set_expression(self, node) -> str:
        _validate_real_expression(node)
        elements = "|".join(sorted(self.visit(elem) for elem in node.elements))
        return f"Set({elements})"

    def visit_range_expression(self, node) -> str:
        _validate_real_expression(node)
        return f"Range({self.visit(node.low)},{self.visit(node.high)})"

    def visit_function_call(self, node) -> str:
        _validate_real_expression(node)
        args = "|".join(self.visit(arg) for arg in node.arguments)
        receiver_node = getattr(node, "receiver", None)
        receiver = self.visit(receiver_node) if receiver_node is not None else ""
        return f"Call({receiver}:{node.function},{args})"

    def visit_array_access(self, node) -> str:
        _validate_real_expression(node)
        return f"Array({self.visit(node.array)},{self.visit(node.index)})"

    def visit_member_access(self, node) -> str:
        _validate_real_expression(node)
        return f"Member({self.visit(node.object)},{node.member})"

    def visit_condition(self, node) -> str:
        return "Condition()"

    def visit_for_expression(self, node) -> str:
        quantifier = self._hash_value(node.quantifier)
        return (
            f"For({quantifier},{node.variable},{self.visit(node.iterable)},{self.visit(node.body)})"
        )

    def visit_for_of_expression(self, node) -> str:
        cond = self.visit(node.condition) if node.condition is not None else ""
        return (
            f"ForOf({self._hash_value(node.quantifier)},"
            f"{self._hash_string_set(node.string_set)},{cond})"
        )

    def visit_at_expression(self, node) -> str:
        return f"At({self._hash_value(node.string_id)},{self.visit(node.offset)})"

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
        if isinstance(value, list | tuple):
            return "[" + "|".join(self._hash_value(item) for item in value) + "]"
        if isinstance(value, set | frozenset):
            return "[" + "|".join(self._hash_value(item) for item in sorted(value, key=str)) + "]"
        return "" if value is None else str(value)

    def _hash_modifiers(self, node) -> str:
        """Hash string modifiers as an order-insensitive set."""
        return "|".join(sorted(self._hash_value(mod) for mod in getattr(node, "modifiers", [])))

    def _hash_string_set(self, value) -> str:
        """Hash raw string-set lists as order-insensitive collections."""
        string_set_items = self._string_set_items(value)
        if string_set_items is not None:
            return "[" + "|".join(sorted(string_set_items)) + "]"
        if isinstance(value, list | tuple | set | frozenset):
            return "[" + "|".join(sorted(self._hash_value(item) for item in value)) + "]"
        return self._hash_value(value)

    def _string_set_items(self, value) -> list[str] | None:
        from yaraast.ast.expressions import ParenthesesExpression, SetExpression

        if isinstance(value, ParenthesesExpression):
            return self._string_set_items(value.expression)
        if isinstance(value, SetExpression):
            return self._string_set_container_items(value.elements)
        if isinstance(value, list | tuple | set | frozenset):
            return self._string_set_container_items(value)
        return None

    def _string_set_container_items(self, values) -> list[str] | None:
        items = []
        for value in values:
            item = self._string_set_item(value)
            if item is None:
                return None
            items.append(item)
        return items

    @staticmethod
    def _string_set_item(value) -> str | None:
        from yaraast.ast.expressions import StringIdentifier, StringLiteral, StringWildcard

        if isinstance(value, str):
            return value
        if isinstance(value, StringIdentifier):
            if not isinstance(value.name, str):
                msg = "String reference must be a string"
                raise TypeError(msg)
            return value.name
        if isinstance(value, StringWildcard):
            if not isinstance(value.pattern, str):
                msg = "String reference must be a string"
                raise TypeError(msg)
            return value.pattern
        if isinstance(value, StringLiteral):
            if not isinstance(value.value, str):
                msg = "String reference must be a string"
                raise TypeError(msg)
            if value.value.startswith("$"):
                return value.value
        return None

    def _hash_in_rule_pragmas(self, pragmas) -> str:
        """Hash rule pragmas by position while preserving sequential directives."""
        grouped: dict[str, list] = {}
        for pragma in pragmas:
            position = _string_attr_or_empty(pragma, "position", "InRulePragma position")
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
        return f"Meta({node.key},{_meta_value_repr(node.value)})"

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
        if hasattr(node, "module"):
            module_path = _string_attr_or_empty(node, "module", "ExternImport module")
        else:
            module_path = _string_attr_or_empty(
                node,
                "module_path",
                "ExternImport module path",
            )
        alias = _optional_string_attr(node, "alias", "ExternImport alias")
        rules = "|".join(sorted(getattr(node, "rules", [])))
        return f"ExternImport({module_path},{alias},{rules})"

    def visit_extern_namespace(self, node) -> str:
        rules = "|".join(sorted(self.visit(rule) for rule in getattr(node, "extern_rules", [])))
        name = _string_attr_or_empty(node, "name", "ExternNamespace name")
        return f"ExternNamespace({name},{rules})"

    def visit_extern_rule(self, node) -> str:
        modifiers = "|".join(sorted(str(mod) for mod in getattr(node, "modifiers", [])))
        name = _string_attr_or_empty(node, "name", "ExternRule name")
        namespace = _optional_string_attr(node, "namespace", "ExternRule namespace")
        return f"ExternRule({name},{modifiers},{namespace})"

    def visit_extern_rule_reference(self, node) -> str:
        if hasattr(node, "name"):
            rule_name = _string_attr_or_empty(node, "name", "ExternRuleReference name")
        else:
            rule_name = _string_attr_or_empty(
                node,
                "rule_name",
                "ExternRuleReference rule name",
            )
        namespace = _optional_string_attr(node, "namespace", "ExternRuleReference namespace")
        return f"ExternRuleRef({rule_name},{namespace})"

    def visit_in_rule_pragma(self, node) -> str:
        pragma = getattr(node, "pragma", "")
        pragma_hash = self._hash_value(pragma)
        position = _optional_string_attr(node, "position", "InRulePragma position")
        if position is None:
            return f"InRulePragma({pragma_hash})"
        return f"InRulePragma({pragma_hash},{position})"

    def visit_pragma(self, node) -> str:
        from yaraast.ast.pragmas import Pragma

        if not hasattr(node, "pragma_type"):
            return f"Pragma({getattr(node, 'directive', '')})"
        if isinstance(node, Pragma):
            node.validate_structure()
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


def _required_string_attr(node: Any, attr: str, field_name: str) -> str:
    value = getattr(node, attr)
    if not isinstance(value, str):
        msg = f"{field_name} must be a string"
        raise TypeError(msg)
    return value


def _optional_string_attr(node: Any, attr: str, field_name: str) -> str | None:
    value = getattr(node, attr, None)
    if value is None:
        return None
    if not isinstance(value, str):
        msg = f"{field_name} must be a string"
        raise TypeError(msg)
    return value


def _string_attr_or_empty(node: Any, attr: str, field_name: str) -> str:
    if not hasattr(node, attr):
        return ""
    return _required_string_attr(node, attr, field_name)
