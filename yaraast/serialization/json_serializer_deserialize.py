"""Deserialization helpers for JSON serializer."""

from __future__ import annotations

from typing import Any


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
        else:
            meta = [self._deserialize_meta(m) for m in meta_data]

        strings = [self._deserialize_string(s) for s in data.get("strings", [])]
        condition = (
            self._deserialize_expression(data["condition"]) if data.get("condition") else None
        )

        tags = [self._deserialize_tag(t) for t in data.get("tags", [])]

        return Rule(
            name=data["name"],
            modifiers=data.get("modifiers", []),
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
        )

    def _deserialize_tag(self, data: dict[str, Any]):
        from yaraast.ast.rules import Tag

        return Tag(name=data["name"])

    def _deserialize_meta(self, data: dict[str, Any]):
        from yaraast.ast.meta import Meta

        return Meta(key=data["key"], value=data["value"])

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
        raise ValueError(msg)

    def _deserialize_modifier(self, data: dict[str, Any]):
        from yaraast.ast.modifiers import StringModifier

        return StringModifier.from_name_value(data["name"], data.get("value"))

    def _deserialize_hex_token(self, data: dict[str, Any]):
        token_type = data.get("type")

        if token_type == "HexByte":  # nosec B105
            from yaraast.ast.strings import HexByte

            return HexByte(value=data["value"])
        if token_type == "HexWildcard":  # nosec B105
            from yaraast.ast.strings import HexWildcard

            return HexWildcard()
        if token_type == "HexJump":  # nosec B105
            from yaraast.ast.strings import HexJump

            return HexJump(min_jump=data.get("min_jump"), max_jump=data.get("max_jump"))
        msg = f"Unknown hex token type: {token_type}"
        raise ValueError(msg)

    def _deserialize_expression(self, data: dict[str, Any]):
        if not data:
            return None

        expr_type = data.get("type")

        if expr_type == "BinaryExpression":
            from yaraast.ast.expressions import BinaryExpression

            left = self._deserialize_expression(data["left"])
            right = self._deserialize_expression(data["right"])
            return BinaryExpression(left=left, operator=data["operator"], right=right)
        if expr_type == "UnaryExpression":
            from yaraast.ast.expressions import UnaryExpression

            operand = self._deserialize_expression(data["operand"])
            return UnaryExpression(operator=data["operator"], operand=operand)
        if expr_type == "ParenthesesExpression":
            from yaraast.ast.expressions import ParenthesesExpression

            expression = self._deserialize_expression(data["expression"])
            return ParenthesesExpression(expression=expression)
        if expr_type == "SetExpression":
            from yaraast.ast.expressions import SetExpression

            elements = [self._deserialize_expression(e) for e in data.get("elements", [])]
            return SetExpression(elements=elements)
        if expr_type == "RangeExpression":
            from yaraast.ast.expressions import RangeExpression

            low = self._deserialize_expression(data["low"])
            high = self._deserialize_expression(data["high"])
            return RangeExpression(low=low, high=high)
        if expr_type == "FunctionCall":
            from yaraast.ast.expressions import FunctionCall

            args = [self._deserialize_expression(a) for a in data.get("arguments", [])]
            return FunctionCall(function=data["function"], arguments=args)
        if expr_type == "ArrayAccess":
            from yaraast.ast.expressions import ArrayAccess

            array = self._deserialize_expression(data["array"])
            index = self._deserialize_expression(data["index"])
            return ArrayAccess(array=array, index=index)
        if expr_type == "MemberAccess":
            from yaraast.ast.expressions import MemberAccess

            obj = self._deserialize_expression(data["object"])
            return MemberAccess(object=obj, member=data["member"])
        if expr_type == "Identifier":
            from yaraast.ast.expressions import Identifier

            return Identifier(name=data["name"])
        if expr_type == "StringIdentifier":
            from yaraast.ast.expressions import StringIdentifier

            return StringIdentifier(name=data["name"])
        if expr_type == "StringWildcard":
            from yaraast.ast.expressions import StringWildcard

            return StringWildcard(pattern=data["pattern"])
        if expr_type == "StringCount":
            from yaraast.ast.expressions import StringCount

            index = data.get("index")
            return StringCount(
                string_id=data["string_id"],
                index=self._deserialize_expression(index) if index else None,
            )
        if expr_type == "StringOffset":
            from yaraast.ast.expressions import StringOffset

            index = data.get("index")
            return StringOffset(
                string_id=data["string_id"],
                index=self._deserialize_expression(index) if index else None,
            )
        if expr_type == "StringLength":
            from yaraast.ast.expressions import StringLength

            index = data.get("index")
            return StringLength(
                string_id=data["string_id"],
                index=self._deserialize_expression(index) if index else None,
            )
        if expr_type == "IntegerLiteral":
            from yaraast.ast.expressions import IntegerLiteral

            return IntegerLiteral(value=data["value"])
        if expr_type == "DoubleLiteral":
            from yaraast.ast.expressions import DoubleLiteral

            return DoubleLiteral(value=data["value"])
        if expr_type == "StringLiteral":
            from yaraast.ast.expressions import StringLiteral

            return StringLiteral(value=data["value"])
        if expr_type == "RegexLiteral":
            from yaraast.ast.expressions import RegexLiteral

            return RegexLiteral(pattern=data["pattern"], modifiers=data.get("modifiers", ""))
        if expr_type == "BooleanLiteral":
            from yaraast.ast.expressions import BooleanLiteral

            return BooleanLiteral(value=data["value"])
        if expr_type == "ForExpression":
            from yaraast.ast.conditions import ForExpression

            return ForExpression(
                quantifier=data["quantifier"],
                variable=data.get("variable", "i"),
                iterable=self._deserialize_expression(data["iterable"]),
                body=self._deserialize_expression(data["body"]),
            )
        if expr_type == "ForOfExpression":
            from yaraast.ast.conditions import ForOfExpression

            condition = data.get("condition")
            return ForOfExpression(
                quantifier=data["quantifier"],
                string_set=self._deserialize_expression(data["string_set"]),
                condition=self._deserialize_expression(condition) if condition else None,
            )
        if expr_type == "AtExpression":
            from yaraast.ast.conditions import AtExpression

            return AtExpression(
                string_id=data["string_id"],
                offset=self._deserialize_expression(data["offset"]),
            )
        if expr_type == "InExpression":
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
        if expr_type == "OfExpression":
            from yaraast.ast.conditions import OfExpression

            return OfExpression(
                quantifier=self._deserialize_expression(data["quantifier"]),
                string_set=self._deserialize_expression(data["string_set"]),
            )
        if expr_type == "ModuleReference":
            from yaraast.ast.modules import ModuleReference

            return ModuleReference(module=data["module"])
        if expr_type == "DictionaryAccess":
            from yaraast.ast.modules import DictionaryAccess

            obj = self._deserialize_expression(data["object"])
            key = data.get("key")
            if isinstance(key, dict):
                key = self._deserialize_expression(key)
            return DictionaryAccess(object=obj, key=key)
        if expr_type == "DefinedExpression":
            from yaraast.ast.operators import DefinedExpression

            expression = data.get("expression")
            if expression is None and "identifier" in data:
                expression = {"type": "Identifier", "name": data["identifier"]}
            return DefinedExpression(expression=self._deserialize_expression(expression))
        if expr_type == "StringOperatorExpression":
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

        msg = f"Unknown expression type: {expr_type}"
        raise ValueError(msg)
