"""Deserialization helpers for JSON serializer."""

from __future__ import annotations

from typing import Any

from yaraast.errors import SerializationError


def _deserialize_ast_value(self, data):
    if isinstance(data, dict):
        return self._deserialize_expression(data)
    return data


def _deser_binary_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import BinaryExpression

    left = self._deserialize_expression(data["left"])
    right = self._deserialize_expression(data["right"])
    return BinaryExpression(left=left, operator=data["operator"], right=right)


def _deser_unary_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import UnaryExpression

    operand = self._deserialize_expression(data["operand"])
    return UnaryExpression(operator=data["operator"], operand=operand)


def _deser_parentheses_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import ParenthesesExpression

    expression = self._deserialize_expression(data["expression"])
    return ParenthesesExpression(expression=expression)


def _deser_set_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import SetExpression

    elements = [self._deserialize_expression(e) for e in data.get("elements", [])]
    return SetExpression(elements=elements)


def _deser_range_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import RangeExpression

    low = self._deserialize_expression(data["low"])
    high = self._deserialize_expression(data["high"])
    return RangeExpression(low=low, high=high)


def _deser_function_call(self, data: dict[str, Any]):
    from yaraast.ast.expressions import FunctionCall

    args = [self._deserialize_expression(a) for a in data.get("arguments", [])]
    return FunctionCall(function=data["function"], arguments=args)


def _deser_array_access(self, data: dict[str, Any]):
    from yaraast.ast.expressions import ArrayAccess

    array = self._deserialize_expression(data["array"])
    index = self._deserialize_expression(data["index"])
    return ArrayAccess(array=array, index=index)


def _deser_member_access(self, data: dict[str, Any]):
    from yaraast.ast.expressions import MemberAccess

    obj = self._deserialize_expression(data["object"])
    return MemberAccess(object=obj, member=data["member"])


def _deser_identifier(self, data: dict[str, Any]):
    from yaraast.ast.expressions import Identifier

    return Identifier(name=data["name"])


def _deser_string_identifier(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringIdentifier

    return StringIdentifier(name=data["name"])


def _deser_string_wildcard(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringWildcard

    return StringWildcard(pattern=data["pattern"])


def _deser_string_count(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringCount

    return StringCount(string_id=data["string_id"])


def _deser_string_offset(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringOffset

    index = data.get("index")
    return StringOffset(
        string_id=data["string_id"],
        index=self._deserialize_expression(index) if index else None,
    )


def _deser_string_length(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringLength

    index = data.get("index")
    return StringLength(
        string_id=data["string_id"],
        index=self._deserialize_expression(index) if index else None,
    )


def _deser_integer_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import IntegerLiteral

    return IntegerLiteral(value=data["value"])


def _deser_double_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import DoubleLiteral

    return DoubleLiteral(value=data["value"])


def _deser_string_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringLiteral

    return StringLiteral(value=data["value"])


def _deser_regex_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import RegexLiteral

    return RegexLiteral(pattern=data["pattern"], modifiers=data.get("modifiers", ""))


def _deser_boolean_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import BooleanLiteral

    return BooleanLiteral(value=data["value"])


def _deser_for_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import ForExpression

    return ForExpression(
        quantifier=_deserialize_ast_value(self, data["quantifier"]),
        variable=data.get("variable", "i"),
        iterable=self._deserialize_expression(data["iterable"]),
        body=self._deserialize_expression(data["body"]),
    )


def _deser_for_of_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import ForOfExpression

    condition = data.get("condition")
    return ForOfExpression(
        quantifier=_deserialize_ast_value(self, data["quantifier"]),
        string_set=_deserialize_ast_value(self, data["string_set"]),
        condition=self._deserialize_expression(condition) if condition else None,
    )


def _deser_at_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import AtExpression

    return AtExpression(
        string_id=data["string_id"],
        offset=self._deserialize_expression(data["offset"]),
    )


def _deser_in_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import InExpression

    subject = data.get("subject")
    if subject is None and "string_id" in data:
        subject = data["string_id"]
    if isinstance(subject, dict):
        subject = self._deserialize_expression(subject)
    return InExpression(
        subject=subject,
        range=self._deserialize_expression(data["range"]),
    )


def _deser_of_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import OfExpression

    return OfExpression(
        quantifier=_deserialize_ast_value(self, data["quantifier"]),
        string_set=_deserialize_ast_value(self, data["string_set"]),
    )


def _deser_module_reference(self, data: dict[str, Any]):
    from yaraast.ast.modules import ModuleReference

    return ModuleReference(module=data["module"])


def _deser_dictionary_access(self, data: dict[str, Any]):
    from yaraast.ast.modules import DictionaryAccess

    obj = self._deserialize_expression(data["object"])
    key = data.get("key")
    if isinstance(key, dict):
        key = self._deserialize_expression(key)
    return DictionaryAccess(object=obj, key=key)


def _deser_defined_expression(self, data: dict[str, Any]):
    from yaraast.ast.operators import DefinedExpression

    expression = data.get("expression")
    if expression is None and "identifier" in data:
        expression = {"type": "Identifier", "name": data["identifier"]}
    return DefinedExpression(expression=self._deserialize_expression(expression))


def _deser_string_operator_expression(self, data: dict[str, Any]):
    from yaraast.ast.operators import StringOperatorExpression

    left = data.get("left")
    right = data.get("right")
    if left is None and "subject" in data:
        left = data.get("subject")
    if right is None and "pattern" in data:
        right = {"type": "StringLiteral", "value": data.get("pattern", "")}
    if left is None:
        left = {"type": "Identifier", "name": "true"}
    if right is None:
        right = {"type": "Identifier", "name": "true"}
    return StringOperatorExpression(
        left=self._deserialize_expression(left),
        operator=data["operator"],
        right=self._deserialize_expression(right),
    )


def _deser_extern_rule_reference(self, data: dict[str, Any]):
    from yaraast.ast.extern import ExternRuleReference

    rule_name = data.get("rule_name", data.get("name"))
    if rule_name is None:
        msg = "ExternRuleReference missing rule_name"
        raise SerializationError(msg)
    return ExternRuleReference(rule_name=rule_name, namespace=data.get("namespace"))


_EXPR_DESERIALIZERS: dict[str, Any] = {
    "BinaryExpression": _deser_binary_expression,
    "UnaryExpression": _deser_unary_expression,
    "ParenthesesExpression": _deser_parentheses_expression,
    "SetExpression": _deser_set_expression,
    "RangeExpression": _deser_range_expression,
    "FunctionCall": _deser_function_call,
    "ArrayAccess": _deser_array_access,
    "MemberAccess": _deser_member_access,
    "Identifier": _deser_identifier,
    "StringIdentifier": _deser_string_identifier,
    "StringWildcard": _deser_string_wildcard,
    "StringCount": _deser_string_count,
    "StringOffset": _deser_string_offset,
    "StringLength": _deser_string_length,
    "IntegerLiteral": _deser_integer_literal,
    "DoubleLiteral": _deser_double_literal,
    "StringLiteral": _deser_string_literal,
    "RegexLiteral": _deser_regex_literal,
    "BooleanLiteral": _deser_boolean_literal,
    "ForExpression": _deser_for_expression,
    "ForOfExpression": _deser_for_of_expression,
    "AtExpression": _deser_at_expression,
    "InExpression": _deser_in_expression,
    "OfExpression": _deser_of_expression,
    "ModuleReference": _deser_module_reference,
    "DictionaryAccess": _deser_dictionary_access,
    "DefinedExpression": _deser_defined_expression,
    "StringOperatorExpression": _deser_string_operator_expression,
    "ExternRuleReference": _deser_extern_rule_reference,
}


class JsonSerializerDeserializeMixin:
    """Mixin with JSON deserialization helpers."""

    def _deserialize_import(self, data: dict[str, Any]):
        from yaraast.ast.rules import Import

        return Import(module=data["module"], alias=data.get("alias"))

    def _deserialize_include(self, data: dict[str, Any]):
        from yaraast.ast.rules import Include

        return Include(path=data["path"])

    def _deserialize_rule(self, data: dict[str, Any]):
        from yaraast.ast.rules import Rule

        meta_data = data.get("meta", [])
        if isinstance(meta_data, dict):
            from yaraast.ast.meta import Meta

            meta = [Meta(key=k, value=v) for k, v in meta_data.items()]
        elif isinstance(meta_data, list):
            meta = [self._deserialize_meta(m) for m in meta_data]
        else:
            meta = []

        strings = [self._deserialize_string(s) for s in data.get("strings", [])]
        condition = (
            self._deserialize_expression(data["condition"]) if data.get("condition") else None
        )

        tags = [self._deserialize_tag(t) for t in data.get("tags", [])]
        pragmas = [self._deserialize_in_rule_pragma(p) for p in data.get("pragmas", [])]

        return Rule(
            name=data["name"],
            modifiers=data.get("modifiers", []),
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
            pragmas=pragmas,
        )

    def _deserialize_tag(self, data: dict[str, Any]):
        from yaraast.ast.rules import Tag

        return Tag(name=data["name"])

    def _deserialize_meta(self, data: dict[str, Any]):
        from yaraast.ast.modifiers import MetaEntry

        return MetaEntry.from_key_value(
            data["key"],
            data["value"],
            data.get("scope"),
        )

    def _deserialize_string(self, data: dict[str, Any]):
        string_type = data.get("type")
        modifiers = [self._deserialize_modifier(m) for m in data.get("modifiers", [])]

        if string_type == "PlainString":
            from yaraast.ast.strings import PlainString

            return PlainString(
                identifier=data["identifier"],
                value=data["value"],
                modifiers=modifiers,
            )
        if string_type == "HexString":
            from yaraast.ast.strings import HexString

            tokens = [self._deserialize_hex_token(t) for t in data.get("tokens", [])]
            return HexString(
                identifier=data["identifier"],
                tokens=tokens,
                modifiers=modifiers,
            )
        if string_type == "RegexString":
            from yaraast.ast.strings import RegexString

            return RegexString(
                identifier=data["identifier"],
                regex=data["regex"],
                modifiers=modifiers,
            )
        msg = f"Unknown string type: {string_type}"
        raise SerializationError(msg)

    def _deserialize_modifier_value(self, name: str, value: Any) -> Any:
        if name == "xor":
            if isinstance(value, list) and len(value) == 2:
                return (value[0], value[1])
            if isinstance(value, str) and "-" in value:
                low, high = value.split("-", maxsplit=1)
                if low.isdigit() and high.isdigit():
                    return (int(low), int(high))
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return value

    def _deserialize_modifier(self, data: dict[str, Any]):
        from yaraast.ast.modifiers import StringModifier

        name = data["name"]
        return StringModifier.from_name_value(
            name,
            self._deserialize_modifier_value(name, data.get("value")),
        )

    def _deserialize_hex_token(self, data: dict[str, Any]):
        hex_kind = data.get("type")

        if hex_kind == "HexByte":
            from yaraast.ast.strings import HexByte

            return HexByte(value=data["value"])
        if hex_kind == "HexWildcard":
            from yaraast.ast.strings import HexWildcard

            return HexWildcard()
        if hex_kind == "HexJump":
            from yaraast.ast.strings import HexJump

            return HexJump(min_jump=data.get("min_jump"), max_jump=data.get("max_jump"))
        if hex_kind == "HexNibble":
            from yaraast.ast.strings import HexNibble

            return HexNibble(high=data.get("high", True), value=data.get("value", 0))
        if hex_kind == "HexNegatedByte":
            from yaraast.ast.strings import HexNegatedByte

            return HexNegatedByte(value=data["value"])
        if hex_kind == "HexAlternative":
            from yaraast.ast.strings import HexAlternative

            alternatives = [
                [self._deserialize_hex_token(t) for t in alt]
                for alt in data.get("alternatives", [])
            ]
            return HexAlternative(alternatives=alternatives)
        msg = f"Unknown hex token type: {hex_kind}"
        raise SerializationError(msg)

    def _deserialize_extern_import(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternImport

        module_path = data.get("module_path", data.get("module"))
        if module_path is None:
            msg = "ExternImport missing module_path"
            raise SerializationError(msg)
        return ExternImport(
            module_path=module_path,
            alias=data.get("alias"),
            rules=list(data.get("rules", [])),
        )

    def _deserialize_extern_rule(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternRule
        from yaraast.ast.rules import Rule

        return ExternRule(
            name=data["name"],
            modifiers=Rule._normalize_modifiers(data.get("modifiers", [])),
            namespace=data.get("namespace"),
        )

    def _deserialize_extern_namespace(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternNamespace

        return ExternNamespace(
            name=data["name"],
            extern_rules=[
                self._deserialize_extern_rule(rule) for rule in data.get("extern_rules", [])
            ],
        )

    def _deserialize_pragma(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import (
            ConditionalDirective,
            CustomPragma,
            DefineDirective,
            IncludeOncePragma,
            Pragma,
            PragmaScope,
            PragmaType,
            UndefDirective,
        )

        pragma_type = PragmaType.from_string(
            str(data.get("pragma_type", data.get("name", PragmaType.CUSTOM.value)))
        )
        scope = PragmaScope(data.get("scope", PragmaScope.FILE.value))
        name = data.get("name", pragma_type.value)
        arguments = list(data.get("arguments", []))

        if pragma_type == PragmaType.INCLUDE_ONCE:
            pragma = IncludeOncePragma()
        elif pragma_type == PragmaType.DEFINE and "macro_name" in data:
            pragma = DefineDirective(
                macro_name=str(data["macro_name"]),
                macro_value=data.get("macro_value"),
            )
        elif pragma_type == PragmaType.UNDEF and "macro_name" in data:
            pragma = UndefDirective(macro_name=str(data["macro_name"]))
        elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF, PragmaType.ENDIF}:
            pragma = ConditionalDirective(pragma_type, condition=data.get("condition"))
        elif pragma_type == PragmaType.CUSTOM:
            pragma = CustomPragma(
                name=name,
                arguments=arguments,
                parameters=dict(data.get("parameters", {})),
                scope=scope,
            )
        else:
            pragma = Pragma(
                pragma_type=pragma_type,
                name=name,
                arguments=arguments,
                scope=scope,
            )
        pragma.scope = scope
        return pragma

    def _deserialize_in_rule_pragma(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import InRulePragma

        return InRulePragma(
            pragma=self._deserialize_pragma(data["pragma"]),
            position=data.get("position", "before_strings"),
        )

    def _deserialize_pragma_block(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import PragmaBlock, PragmaScope

        return PragmaBlock(
            pragmas=[self._deserialize_pragma(pragma) for pragma in data.get("pragmas", [])],
            scope=PragmaScope(data.get("scope", PragmaScope.FILE.value)),
        )

    def _deserialize_expression(self, data: dict[str, Any]):
        if not data:
            return None

        expr_type = data.get("type")
        factory = _EXPR_DESERIALIZERS.get(expr_type)
        if factory:
            return factory(self, data)

        msg = f"Unknown expression type: {expr_type}"
        raise SerializationError(msg)
