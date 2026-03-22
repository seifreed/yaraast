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

    meta_items = (
        rule.meta.items()
        if isinstance(rule.meta, dict)
        else ((getattr(m, "key", ""), getattr(m, "value", "")) for m in rule.meta)
    )
    for key, value in meta_items:
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
        pb_token.jump.min_jump = token.min_jump or 0
        pb_token.jump.max_jump = token.max_jump or 0
    elif isinstance(token, HexNibble):
        pb_token.nibble.high = token.high
        pb_token.nibble.value = token.value


def convert_expression_to_protobuf(expr, pb_expr) -> None:
    """Convert an AST expression to protobuf."""
    import warnings

    from yaraast.ast.expressions import (
        BinaryExpression,
        BooleanLiteral,
        DoubleLiteral,
        Identifier,
        IntegerLiteral,
        StringCount,
        StringIdentifier,
        StringLiteral,
        UnaryExpression,
    )

    if isinstance(expr, Identifier):
        pb_expr.identifier.name = expr.name
    elif isinstance(expr, StringIdentifier):
        pb_expr.string_identifier.name = expr.name
    elif isinstance(expr, StringCount):
        pb_expr.string_count.string_id = expr.string_id
    elif isinstance(expr, IntegerLiteral):
        pb_expr.integer_literal.value = expr.value
    elif isinstance(expr, DoubleLiteral):
        pb_expr.double_literal.value = expr.value
    elif isinstance(expr, StringLiteral):
        pb_expr.string_literal.value = expr.value
    elif isinstance(expr, BooleanLiteral):
        pb_expr.boolean_literal.value = expr.value
    elif isinstance(expr, BinaryExpression):
        pb_expr.binary_expression.operator = expr.operator
        convert_expression_to_protobuf(expr.left, pb_expr.binary_expression.left)
        convert_expression_to_protobuf(expr.right, pb_expr.binary_expression.right)
    elif isinstance(expr, UnaryExpression):
        pb_expr.unary_expression.operator = expr.operator
        convert_expression_to_protobuf(expr.operand, pb_expr.unary_expression.operand)
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
                        min_jump=pb_token.jump.min_jump or None,
                        max_jump=pb_token.jump.max_jump or None,
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
    from yaraast.ast.expressions import (
        BinaryExpression,
        BooleanLiteral,
        DoubleLiteral,
        Identifier,
        IntegerLiteral,
        StringCount,
        StringIdentifier,
        StringLiteral,
        UnaryExpression,
    )

    if pb_expr.HasField("identifier"):
        return Identifier(name=pb_expr.identifier.name)
    if pb_expr.HasField("string_identifier"):
        return StringIdentifier(name=pb_expr.string_identifier.name)
    if pb_expr.HasField("string_count"):
        return StringCount(string_id=pb_expr.string_count.string_id)
    if pb_expr.HasField("integer_literal"):
        return IntegerLiteral(value=pb_expr.integer_literal.value)
    if pb_expr.HasField("double_literal"):
        return DoubleLiteral(value=pb_expr.double_literal.value)
    if pb_expr.HasField("string_literal"):
        return StringLiteral(value=pb_expr.string_literal.value)
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
    import warnings

    warnings.warn(
        "Protobuf deserialization: unrecognized expression field, "
        "substituting BooleanLiteral(true) — data may have been lost during serialization",
        stacklevel=2,
    )
    return BooleanLiteral(value=True)
