"""Conversion helpers between AST and protobuf representations."""

from __future__ import annotations

import time

from . import yara_ast_pb2


def ast_to_protobuf(ast, *, include_metadata: bool) -> yara_ast_pb2.YaraFile:
    """Convert an AST to its protobuf representation."""
    pb_file = yara_ast_pb2.YaraFile()

    for imp in ast.imports:
        pb_import = pb_file.imports.add()
        pb_import.module = imp.module
        if hasattr(imp, "alias") and imp.alias:
            pb_import.alias = imp.alias

    for inc in ast.includes:
        pb_include = pb_file.includes.add()
        pb_include.path = inc.path

    for rule in ast.rules:
        pb_rule = pb_file.rules.add()
        convert_rule_to_protobuf(rule, pb_rule)

    if include_metadata:
        pb_file.metadata.format = "yaraast-protobuf"
        pb_file.metadata.version = "1.0"
        pb_file.metadata.ast_type = "YaraFile"
        pb_file.metadata.rules_count = len(ast.rules)
        pb_file.metadata.imports_count = len(ast.imports)
        pb_file.metadata.includes_count = len(ast.includes)
        pb_file.metadata.timestamp = int(time.time())

    return pb_file


def convert_rule_to_protobuf(rule, pb_rule) -> None:
    """Convert a single rule AST node to protobuf."""
    pb_rule.name = rule.name
    pb_rule.modifiers.extend(str(m) for m in rule.modifiers)

    for tag in rule.tags:
        pb_tag = pb_rule.tags.add()
        pb_tag.name = tag.name

    for entry in rule.meta:
        key = getattr(entry, "key", "")
        value = getattr(entry, "value", "")
        meta_val = pb_rule.meta[key]
        if isinstance(value, str):
            meta_val.string_value = value
        elif isinstance(value, bool):
            meta_val.bool_value = value
        elif isinstance(value, int):
            meta_val.int_value = value
        elif isinstance(value, float):
            meta_val.double_value = value

    for string_def in rule.strings:
        pb_string = pb_rule.strings.add()
        pb_string.identifier = string_def.identifier
        convert_string_to_protobuf(string_def, pb_string)

    if rule.condition:
        convert_expression_to_protobuf(rule.condition, pb_rule.condition)


def convert_string_to_protobuf(string_def, pb_string) -> None:
    """Convert a string definition to protobuf."""
    from yaraast.ast.strings import HexString, PlainString, RegexString

    if isinstance(string_def, PlainString):
        pb_string.plain.value = string_def.value
        for mod in string_def.modifiers:
            pb_mod = pb_string.plain.modifiers.add()
            pb_mod.name = mod.name
            if mod.value:
                pb_mod.value = mod.value

    elif isinstance(string_def, HexString):
        for token in string_def.tokens:
            pb_token = pb_string.hex.tokens.add()
            convert_hex_token_to_protobuf(token, pb_token)

        for mod in string_def.modifiers:
            pb_mod = pb_string.hex.modifiers.add()
            pb_mod.name = mod.name
            if mod.value:
                pb_mod.value = mod.value

    elif isinstance(string_def, RegexString):
        pb_string.regex.regex = string_def.regex
        for mod in string_def.modifiers:
            pb_mod = pb_string.regex.modifiers.add()
            pb_mod.name = mod.name
            if mod.value:
                pb_mod.value = mod.value


def convert_hex_token_to_protobuf(token, pb_token) -> None:
    """Convert a hex token to protobuf."""
    from yaraast.ast.strings import HexByte, HexJump, HexNibble, HexWildcard

    if isinstance(token, HexByte):
        pb_token.byte.value = str(token.value)
    elif isinstance(token, HexWildcard):
        pb_token.wildcard.CopyFrom(yara_ast_pb2.HexWildcard())
    elif isinstance(token, HexJump):
        pb_token.jump.SetInParent()
        if token.min_jump is not None:
            pb_token.jump.min_jump = token.min_jump
        if token.max_jump is not None:
            pb_token.jump.max_jump = token.max_jump
    elif isinstance(token, HexNibble):
        pb_token.nibble.high = token.high
        pb_token.nibble.value = token.value


def _coerce_expression(value):
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        Expression,
        Identifier,
        IntegerLiteral,
        SetExpression,
        StringIdentifier,
    )

    if isinstance(value, Expression):
        return value
    if isinstance(value, bool):
        return BooleanLiteral(value=value)
    if isinstance(value, int):
        return IntegerLiteral(value=value)
    if isinstance(value, float):
        return DoubleLiteral(value=value)
    if isinstance(value, str):
        return StringIdentifier(value) if value.startswith("$") else Identifier(value)
    if isinstance(value, list):
        return SetExpression([_coerce_expression(item) for item in value])
    return None


def _coerce_quantifier_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int | float):
        return str(value)

    raw_value = getattr(value, "value", None)
    if raw_value is not None:
        return str(raw_value)

    name = getattr(value, "name", None)
    if name is not None:
        return str(name)

    return str(value)


def convert_expression_to_protobuf(expr, pb_expr) -> None:
    """Convert an AST expression to protobuf."""
    import warnings

    from yaraast.ast.conditions import (
        AtExpression,
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
        FunctionCall,
        Identifier,
        IntegerLiteral,
        MemberAccess,
        ParenthesesExpression,
        RangeExpression,
        RegexLiteral,
        SetExpression,
        StringCount,
        StringIdentifier,
        StringLength,
        StringLiteral,
        StringOffset,
        UnaryExpression,
    )
    from yaraast.ast.operators import DefinedExpression, StringOperatorExpression

    if isinstance(expr, Identifier):
        pb_expr.identifier.name = expr.name
    elif isinstance(expr, StringIdentifier):
        pb_expr.string_identifier.name = expr.name
    elif isinstance(expr, StringCount):
        pb_expr.string_count.string_id = expr.string_id
    elif isinstance(expr, StringOffset):
        pb_expr.string_offset.string_id = expr.string_id
        if expr.index is not None:
            convert_expression_to_protobuf(expr.index, pb_expr.string_offset.index)
    elif isinstance(expr, StringLength):
        pb_expr.string_length.string_id = expr.string_id
        if expr.index is not None:
            convert_expression_to_protobuf(expr.index, pb_expr.string_length.index)
    elif isinstance(expr, IntegerLiteral):
        pb_expr.integer_literal.value = expr.value
    elif isinstance(expr, DoubleLiteral):
        pb_expr.double_literal.value = expr.value
    elif isinstance(expr, StringLiteral):
        pb_expr.string_literal.value = expr.value
    elif isinstance(expr, RegexLiteral):
        pb_expr.regex_literal.pattern = expr.pattern
        pb_expr.regex_literal.modifiers = expr.modifiers
    elif isinstance(expr, BooleanLiteral):
        pb_expr.boolean_literal.value = expr.value
    elif isinstance(expr, BinaryExpression):
        pb_expr.binary_expression.operator = expr.operator
        convert_expression_to_protobuf(expr.left, pb_expr.binary_expression.left)
        convert_expression_to_protobuf(expr.right, pb_expr.binary_expression.right)
    elif isinstance(expr, UnaryExpression):
        pb_expr.unary_expression.operator = expr.operator
        convert_expression_to_protobuf(expr.operand, pb_expr.unary_expression.operand)
    elif isinstance(expr, ParenthesesExpression):
        convert_expression_to_protobuf(expr.expression, pb_expr.parentheses_expression.expression)
    elif isinstance(expr, SetExpression):
        for element in expr.elements:
            convert_expression_to_protobuf(element, pb_expr.set_expression.elements.add())
    elif isinstance(expr, RangeExpression):
        convert_expression_to_protobuf(expr.low, pb_expr.range_expression.low)
        convert_expression_to_protobuf(expr.high, pb_expr.range_expression.high)
    elif isinstance(expr, FunctionCall):
        pb_expr.function_call.function = expr.function
        for argument in expr.arguments:
            convert_expression_to_protobuf(argument, pb_expr.function_call.arguments.add())
    elif isinstance(expr, ArrayAccess):
        convert_expression_to_protobuf(expr.array, pb_expr.array_access.array)
        convert_expression_to_protobuf(expr.index, pb_expr.array_access.index)
    elif isinstance(expr, MemberAccess):
        convert_expression_to_protobuf(expr.object, pb_expr.member_access.object)
        pb_expr.member_access.member = expr.member
    elif isinstance(expr, ForExpression):
        pb_expr.for_expression.quantifier = _coerce_quantifier_text(expr.quantifier)
        pb_expr.for_expression.variable = expr.variable
        convert_expression_to_protobuf(expr.iterable, pb_expr.for_expression.iterable)
        convert_expression_to_protobuf(expr.body, pb_expr.for_expression.body)
    elif isinstance(expr, ForOfExpression):
        pb_expr.for_of_expression.quantifier = _coerce_quantifier_text(expr.quantifier)
        string_set = _coerce_expression(expr.string_set)
        if string_set is not None:
            convert_expression_to_protobuf(string_set, pb_expr.for_of_expression.string_set)
        if expr.condition is not None:
            convert_expression_to_protobuf(expr.condition, pb_expr.for_of_expression.condition)
    elif isinstance(expr, AtExpression):
        pb_expr.at_expression.string_id = expr.string_id
        convert_expression_to_protobuf(expr.offset, pb_expr.at_expression.offset)
    elif isinstance(expr, InExpression) and isinstance(expr.subject, str):
        pb_expr.in_expression.string_id = expr.subject
        convert_expression_to_protobuf(expr.range, pb_expr.in_expression.range)
    elif isinstance(expr, OfExpression):
        quantifier = _coerce_expression(expr.quantifier)
        string_set = _coerce_expression(expr.string_set)
        if quantifier is not None and string_set is not None:
            convert_expression_to_protobuf(quantifier, pb_expr.of_expression.quantifier)
            convert_expression_to_protobuf(string_set, pb_expr.of_expression.string_set)
    elif isinstance(expr, DefinedExpression):
        convert_expression_to_protobuf(expr.expression, pb_expr.defined_expression.expression)
    elif isinstance(expr, StringOperatorExpression):
        convert_expression_to_protobuf(expr.left, pb_expr.string_operator_expression.left)
        pb_expr.string_operator_expression.operator = expr.operator
        convert_expression_to_protobuf(expr.right, pb_expr.string_operator_expression.right)
    else:
        warnings.warn(
            f"Protobuf serialization: unsupported expression type {type(expr).__name__}, "
            "data will be lost",
            stacklevel=2,
        )


def protobuf_to_ast(pb_file: yara_ast_pb2.YaraFile):
    """Convert a protobuf message back to a basic AST."""
    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import BooleanLiteral
    from yaraast.ast.rules import Import, Include, Rule

    imports = []
    for pb_import in pb_file.imports:
        imports.append(
            Import(
                module=pb_import.module,
                alias=pb_import.alias if pb_import.alias else None,
            ),
        )

    includes = []
    for pb_include in pb_file.includes:
        includes.append(Include(path=pb_include.path))

    rules = []
    for pb_rule in pb_file.rules:
        tags = []
        for pb_tag in pb_rule.tags:
            from yaraast.ast.rules import Tag

            tags.append(Tag(name=pb_tag.name))

        meta = {}
        for key, meta_val in pb_rule.meta.items():
            if meta_val.HasField("string_value"):
                meta[key] = meta_val.string_value
            elif meta_val.HasField("bool_value"):
                meta[key] = meta_val.bool_value
            elif meta_val.HasField("int_value"):
                meta[key] = meta_val.int_value
            elif meta_val.HasField("double_value"):
                meta[key] = meta_val.double_value

        strings = []
        for pb_string in pb_rule.strings:
            string_def = protobuf_to_string(pb_string)
            if string_def is not None:
                strings.append(string_def)

        condition = (
            protobuf_to_expression(pb_rule.condition)
            if pb_rule.HasField("condition")
            else BooleanLiteral(value=True)
        )

        rules.append(
            Rule(
                name=pb_rule.name,
                modifiers=list(pb_rule.modifiers),
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition,
            )
        )

    return YaraFile(imports=imports, includes=includes, rules=rules)


def protobuf_to_string(pb_string):
    """Convert a protobuf string definition back to AST."""
    from yaraast.ast.modifiers import StringModifier
    from yaraast.ast.strings import (
        HexByte,
        HexJump,
        HexNibble,
        HexString,
        HexWildcard,
        PlainString,
        RegexString,
    )

    if pb_string.HasField("plain"):
        modifiers = [
            StringModifier.from_name_value(m.name, m.value if m.value else None)
            for m in pb_string.plain.modifiers
        ]
        s = PlainString(identifier=pb_string.identifier, value=pb_string.plain.value)
        s.modifiers = modifiers
        return s
    if pb_string.HasField("hex"):
        tokens = []
        for pb_token in pb_string.hex.tokens:
            if pb_token.HasField("byte"):
                tokens.append(HexByte(value=int(pb_token.byte.value)))
            elif pb_token.HasField("wildcard"):
                tokens.append(HexWildcard())
            elif pb_token.HasField("jump"):
                tokens.append(
                    HexJump(
                        min_jump=(
                            pb_token.jump.min_jump if pb_token.jump.HasField("min_jump") else None
                        ),
                        max_jump=(
                            pb_token.jump.max_jump if pb_token.jump.HasField("max_jump") else None
                        ),
                    )
                )
            elif pb_token.HasField("nibble"):
                tokens.append(HexNibble(high=pb_token.nibble.high, value=pb_token.nibble.value))
        modifiers = [
            StringModifier.from_name_value(m.name, m.value if m.value else None)
            for m in pb_string.hex.modifiers
        ]
        s = HexString(identifier=pb_string.identifier, tokens=tokens)
        s.modifiers = modifiers
        return s
    if pb_string.HasField("regex"):
        modifiers = [
            StringModifier.from_name_value(m.name, m.value if m.value else None)
            for m in pb_string.regex.modifiers
        ]
        s = RegexString(identifier=pb_string.identifier, regex=pb_string.regex.regex)
        s.modifiers = modifiers
        return s
    return None


def protobuf_to_expression(pb_expr):
    """Convert a protobuf expression back to AST."""
    from yaraast.ast.conditions import (
        AtExpression,
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
        FunctionCall,
        Identifier,
        IntegerLiteral,
        MemberAccess,
        ParenthesesExpression,
        RangeExpression,
        RegexLiteral,
        SetExpression,
        StringCount,
        StringIdentifier,
        StringLength,
        StringLiteral,
        StringOffset,
        UnaryExpression,
    )
    from yaraast.ast.operators import DefinedExpression, StringOperatorExpression

    if pb_expr.HasField("identifier"):
        return Identifier(name=pb_expr.identifier.name)
    if pb_expr.HasField("string_identifier"):
        return StringIdentifier(name=pb_expr.string_identifier.name)
    if pb_expr.HasField("string_count"):
        return StringCount(string_id=pb_expr.string_count.string_id)
    if pb_expr.HasField("string_offset"):
        return StringOffset(
            string_id=pb_expr.string_offset.string_id,
            index=(
                protobuf_to_expression(pb_expr.string_offset.index)
                if pb_expr.string_offset.HasField("index")
                else None
            ),
        )
    if pb_expr.HasField("string_length"):
        return StringLength(
            string_id=pb_expr.string_length.string_id,
            index=(
                protobuf_to_expression(pb_expr.string_length.index)
                if pb_expr.string_length.HasField("index")
                else None
            ),
        )
    if pb_expr.HasField("integer_literal"):
        return IntegerLiteral(value=pb_expr.integer_literal.value)
    if pb_expr.HasField("double_literal"):
        return DoubleLiteral(value=pb_expr.double_literal.value)
    if pb_expr.HasField("string_literal"):
        return StringLiteral(value=pb_expr.string_literal.value)
    if pb_expr.HasField("regex_literal"):
        return RegexLiteral(
            pattern=pb_expr.regex_literal.pattern,
            modifiers=pb_expr.regex_literal.modifiers,
        )
    if pb_expr.HasField("boolean_literal"):
        return BooleanLiteral(value=pb_expr.boolean_literal.value)
    if pb_expr.HasField("binary_expression"):
        return BinaryExpression(
            left=protobuf_to_expression(pb_expr.binary_expression.left),
            operator=pb_expr.binary_expression.operator,
            right=protobuf_to_expression(pb_expr.binary_expression.right),
        )
    if pb_expr.HasField("unary_expression"):
        return UnaryExpression(
            operator=pb_expr.unary_expression.operator,
            operand=protobuf_to_expression(pb_expr.unary_expression.operand),
        )
    if pb_expr.HasField("parentheses_expression"):
        return ParenthesesExpression(
            expression=protobuf_to_expression(pb_expr.parentheses_expression.expression)
        )
    if pb_expr.HasField("set_expression"):
        return SetExpression(
            elements=[
                protobuf_to_expression(element) for element in pb_expr.set_expression.elements
            ]
        )
    if pb_expr.HasField("range_expression"):
        return RangeExpression(
            low=protobuf_to_expression(pb_expr.range_expression.low),
            high=protobuf_to_expression(pb_expr.range_expression.high),
        )
    if pb_expr.HasField("function_call"):
        return FunctionCall(
            function=pb_expr.function_call.function,
            arguments=[
                protobuf_to_expression(argument) for argument in pb_expr.function_call.arguments
            ],
        )
    if pb_expr.HasField("array_access"):
        return ArrayAccess(
            array=protobuf_to_expression(pb_expr.array_access.array),
            index=protobuf_to_expression(pb_expr.array_access.index),
        )
    if pb_expr.HasField("member_access"):
        return MemberAccess(
            object=protobuf_to_expression(pb_expr.member_access.object),
            member=pb_expr.member_access.member,
        )
    if pb_expr.HasField("for_expression"):
        return ForExpression(
            quantifier=pb_expr.for_expression.quantifier,
            variable=pb_expr.for_expression.variable,
            iterable=protobuf_to_expression(pb_expr.for_expression.iterable),
            body=protobuf_to_expression(pb_expr.for_expression.body),
        )
    if pb_expr.HasField("for_of_expression"):
        return ForOfExpression(
            quantifier=pb_expr.for_of_expression.quantifier,
            string_set=protobuf_to_expression(pb_expr.for_of_expression.string_set),
            condition=(
                protobuf_to_expression(pb_expr.for_of_expression.condition)
                if pb_expr.for_of_expression.HasField("condition")
                else None
            ),
        )
    if pb_expr.HasField("at_expression"):
        return AtExpression(
            string_id=pb_expr.at_expression.string_id,
            offset=protobuf_to_expression(pb_expr.at_expression.offset),
        )
    if pb_expr.HasField("in_expression"):
        return InExpression(
            subject=pb_expr.in_expression.string_id,
            range=protobuf_to_expression(pb_expr.in_expression.range),
        )
    if pb_expr.HasField("of_expression"):
        return OfExpression(
            quantifier=protobuf_to_expression(pb_expr.of_expression.quantifier),
            string_set=protobuf_to_expression(pb_expr.of_expression.string_set),
        )
    if pb_expr.HasField("defined_expression"):
        return DefinedExpression(
            expression=protobuf_to_expression(pb_expr.defined_expression.expression)
        )
    if pb_expr.HasField("string_operator_expression"):
        return StringOperatorExpression(
            left=protobuf_to_expression(pb_expr.string_operator_expression.left),
            operator=pb_expr.string_operator_expression.operator,
            right=protobuf_to_expression(pb_expr.string_operator_expression.right),
        )
    import warnings

    warnings.warn(
        "Protobuf deserialization: unrecognized expression field, "
        "substituting BooleanLiteral(true) — data may have been lost during serialization",
        stacklevel=2,
    )
    return BooleanLiteral(value=True)
