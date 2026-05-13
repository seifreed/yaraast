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

    for extern_rule in ast.extern_rules:
        convert_extern_rule_to_protobuf(extern_rule, pb_file.extern_rules.add())

    for extern_import in ast.extern_imports:
        convert_extern_import_to_protobuf(extern_import, pb_file.extern_imports.add())

    for pragma in ast.pragmas:
        convert_pragma_to_protobuf(pragma, pb_file.pragmas.add())

    for namespace in ast.namespaces:
        convert_extern_namespace_to_protobuf(namespace, pb_file.namespaces.add())

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
        scope = getattr(entry, "scope", None)
        meta_val = pb_rule.meta[key]
        if scope is not None:
            pb_rule.meta_scopes[key] = getattr(scope, "value", str(scope))
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

    for pragma in rule.pragmas:
        convert_in_rule_pragma_to_protobuf(pragma, pb_rule.pragmas.add())


def _copy_python_value_to_meta_value(value, pb_meta_value) -> None:
    if isinstance(value, str):
        pb_meta_value.string_value = value
    elif isinstance(value, bool):
        pb_meta_value.bool_value = value
    elif isinstance(value, int):
        pb_meta_value.int_value = value
    elif isinstance(value, float):
        pb_meta_value.double_value = value
    else:
        pb_meta_value.string_value = str(value)


def _meta_value_to_python(pb_meta_value):
    if pb_meta_value.HasField("string_value"):
        return pb_meta_value.string_value
    if pb_meta_value.HasField("bool_value"):
        return pb_meta_value.bool_value
    if pb_meta_value.HasField("int_value"):
        return pb_meta_value.int_value
    if pb_meta_value.HasField("double_value"):
        return pb_meta_value.double_value
    return ""


def convert_extern_rule_to_protobuf(extern_rule, pb_extern_rule) -> None:
    pb_extern_rule.name = extern_rule.name
    pb_extern_rule.modifiers.extend(str(modifier) for modifier in extern_rule.modifiers)
    if extern_rule.namespace:
        pb_extern_rule.namespace = extern_rule.namespace


def convert_extern_import_to_protobuf(extern_import, pb_extern_import) -> None:
    pb_extern_import.module_path = extern_import.module_path
    if extern_import.alias:
        pb_extern_import.alias = extern_import.alias
    pb_extern_import.rules.extend(extern_import.rules)


def convert_extern_namespace_to_protobuf(namespace, pb_namespace) -> None:
    pb_namespace.name = namespace.name
    for extern_rule in namespace.extern_rules:
        convert_extern_rule_to_protobuf(extern_rule, pb_namespace.extern_rules.add())


def convert_pragma_to_protobuf(pragma, pb_pragma) -> None:
    scope = getattr(pragma, "scope", None)
    pb_pragma.pragma_type = getattr(pragma.pragma_type, "value", str(pragma.pragma_type))
    pb_pragma.name = pragma.name
    pb_pragma.arguments.extend(pragma.arguments)
    pb_pragma.scope = getattr(scope, "value", str(scope)) if scope is not None else ""

    macro_name = getattr(pragma, "macro_name", "")
    if macro_name:
        pb_pragma.macro_name = macro_name
    macro_value = getattr(pragma, "macro_value", None)
    if macro_value is not None:
        pb_pragma.macro_value = macro_value
    condition = getattr(pragma, "condition", None)
    if condition is not None:
        pb_pragma.condition = condition

    for key, value in getattr(pragma, "parameters", {}).items():
        _copy_python_value_to_meta_value(value, pb_pragma.parameters[str(key)])


def convert_in_rule_pragma_to_protobuf(in_rule_pragma, pb_in_rule_pragma) -> None:
    convert_pragma_to_protobuf(in_rule_pragma.pragma, pb_in_rule_pragma.pragma)
    pb_in_rule_pragma.position = in_rule_pragma.position


def _modifier_value_text(value) -> str:
    if isinstance(value, tuple) and len(value) == 2:
        return f"{value[0]}-{value[1]}"
    return str(value)


def _copy_modifier_to_protobuf(mod, pb_mod) -> None:
    pb_mod.name = mod.name
    if mod.value is None:
        return

    pb_mod.value = _modifier_value_text(mod.value)
    if isinstance(mod.value, tuple) and len(mod.value) == 2:
        pb_mod.tuple_value.extend([int(mod.value[0]), int(mod.value[1])])
    elif isinstance(mod.value, bool):
        pb_mod.typed_value.bool_value = mod.value
    elif isinstance(mod.value, int):
        pb_mod.typed_value.int_value = mod.value
    elif isinstance(mod.value, float):
        pb_mod.typed_value.double_value = mod.value
    elif isinstance(mod.value, str):
        pb_mod.typed_value.string_value = mod.value


def convert_string_to_protobuf(string_def, pb_string) -> None:
    """Convert a string definition to protobuf."""
    from yaraast.ast.strings import HexString, PlainString, RegexString

    if isinstance(string_def, PlainString):
        pb_string.plain.value = string_def.value
        for mod in string_def.modifiers:
            pb_mod = pb_string.plain.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)

    elif isinstance(string_def, HexString):
        for token in string_def.tokens:
            pb_token = pb_string.hex.tokens.add()
            convert_hex_token_to_protobuf(token, pb_token)

        for mod in string_def.modifiers:
            pb_mod = pb_string.hex.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)

    elif isinstance(string_def, RegexString):
        pb_string.regex.regex = string_def.regex
        for mod in string_def.modifiers:
            pb_mod = pb_string.regex.modifiers.add()
            _copy_modifier_to_protobuf(mod, pb_mod)


def convert_hex_token_to_protobuf(token, pb_token) -> None:
    """Convert a hex token to protobuf."""
    from yaraast.ast.strings import (
        HexAlternative,
        HexByte,
        HexJump,
        HexNegatedByte,
        HexNibble,
        HexWildcard,
    )

    if isinstance(token, HexByte):
        pb_token.byte.value = str(token.value)
    elif isinstance(token, HexNegatedByte):
        pb_token.negated_byte.value = str(token.value)
    elif isinstance(token, HexWildcard):
        pb_token.wildcard.CopyFrom(yara_ast_pb2.HexWildcard())
    elif isinstance(token, HexJump):
        pb_token.jump.SetInParent()
        if token.min_jump is not None:
            pb_token.jump.min_jump = token.min_jump
        if token.max_jump is not None:
            pb_token.jump.max_jump = token.max_jump
    elif isinstance(token, HexAlternative):
        for alternative in token.alternatives:
            pb_alternative = pb_token.alternative.alternatives.add()
            for alternative_token in alternative:
                convert_hex_token_to_protobuf(alternative_token, pb_alternative.tokens.add())
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


def _coerce_quantifier_expression(value):
    from yaraast.ast.expressions import Expression

    return value if isinstance(value, Expression) else None


def _copy_string_set_to_protobuf(value, pb_owner) -> None:
    if isinstance(value, str):
        pb_owner.string_set_text = value
        return

    if isinstance(value, list):
        pb_owner.string_set_items.extend(str(item) for item in value)
        return

    string_set = _coerce_expression(value)
    if string_set is not None:
        convert_expression_to_protobuf(string_set, pb_owner.string_set)


def _restore_quantifier_text(value: str):
    lower_value = value.lower()
    if lower_value == "true":
        return True
    if lower_value == "false":
        return False
    if value.lstrip("-").isdigit() and value not in {"", "-"}:
        return int(value)
    try:
        if any(marker in value for marker in (".", "e", "E")):
            return float(value)
    except ValueError:
        pass
    return value


def _protobuf_string_set_to_ast(pb_owner):
    if pb_owner.HasField("string_set_text"):
        return pb_owner.string_set_text
    if pb_owner.string_set_items:
        return list(pb_owner.string_set_items)
    return protobuf_to_expression(pb_owner.string_set)


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
        Expression,
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
        StringWildcard,
        UnaryExpression,
    )
    from yaraast.ast.extern import ExternRuleReference
    from yaraast.ast.modules import DictionaryAccess, ModuleReference
    from yaraast.ast.operators import DefinedExpression, StringOperatorExpression

    if isinstance(expr, Identifier):
        pb_expr.identifier.name = expr.name
    elif isinstance(expr, StringIdentifier):
        pb_expr.string_identifier.name = expr.name
    elif isinstance(expr, StringWildcard):
        pb_expr.string_wildcard.pattern = expr.pattern
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
    elif isinstance(expr, ModuleReference):
        pb_expr.module_reference.module = expr.module
    elif isinstance(expr, DictionaryAccess):
        convert_expression_to_protobuf(expr.object, pb_expr.dictionary_access.object)
        if isinstance(expr.key, Expression):
            convert_expression_to_protobuf(expr.key, pb_expr.dictionary_access.key_expr)
        else:
            pb_expr.dictionary_access.key = str(expr.key)
    elif isinstance(expr, ExternRuleReference):
        pb_expr.extern_rule_reference.rule_name = expr.rule_name
        if expr.namespace:
            pb_expr.extern_rule_reference.namespace = expr.namespace
    elif isinstance(expr, ForExpression):
        pb_expr.for_expression.quantifier = _coerce_quantifier_text(expr.quantifier)
        quantifier = _coerce_quantifier_expression(expr.quantifier)
        if quantifier is not None:
            convert_expression_to_protobuf(quantifier, pb_expr.for_expression.quantifier_expr)
        pb_expr.for_expression.variable = expr.variable
        convert_expression_to_protobuf(expr.iterable, pb_expr.for_expression.iterable)
        convert_expression_to_protobuf(expr.body, pb_expr.for_expression.body)
    elif isinstance(expr, ForOfExpression):
        pb_expr.for_of_expression.quantifier = _coerce_quantifier_text(expr.quantifier)
        quantifier = _coerce_quantifier_expression(expr.quantifier)
        if quantifier is not None:
            convert_expression_to_protobuf(
                quantifier,
                pb_expr.for_of_expression.quantifier_expr,
            )
        _copy_string_set_to_protobuf(expr.string_set, pb_expr.for_of_expression)
        if expr.condition is not None:
            convert_expression_to_protobuf(expr.condition, pb_expr.for_of_expression.condition)
    elif isinstance(expr, AtExpression):
        pb_expr.at_expression.string_id = expr.string_id
        convert_expression_to_protobuf(expr.offset, pb_expr.at_expression.offset)
    elif isinstance(expr, InExpression):
        if isinstance(expr.subject, str):
            pb_expr.in_expression.string_id = expr.subject
        else:
            convert_expression_to_protobuf(expr.subject, pb_expr.in_expression.subject)
        convert_expression_to_protobuf(expr.range, pb_expr.in_expression.range)
    elif isinstance(expr, OfExpression):
        quantifier = _coerce_quantifier_expression(expr.quantifier)
        if quantifier is not None:
            convert_expression_to_protobuf(quantifier, pb_expr.of_expression.quantifier)
        else:
            pb_expr.of_expression.quantifier_text = _coerce_quantifier_text(expr.quantifier)
        _copy_string_set_to_protobuf(expr.string_set, pb_expr.of_expression)
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

    extern_rules = [protobuf_to_extern_rule(pb_rule) for pb_rule in pb_file.extern_rules]
    extern_imports = [protobuf_to_extern_import(pb_import) for pb_import in pb_file.extern_imports]
    pragmas = [protobuf_to_pragma(pb_pragma) for pb_pragma in pb_file.pragmas]
    namespaces = [protobuf_to_extern_namespace(pb_namespace) for pb_namespace in pb_file.namespaces]

    rules = []
    for pb_rule in pb_file.rules:
        tags = []
        for pb_tag in pb_rule.tags:
            from yaraast.ast.rules import Tag

            tags.append(Tag(name=pb_tag.name))

        meta_values = {}
        for key, meta_val in pb_rule.meta.items():
            if meta_val.HasField("string_value"):
                meta_values[key] = meta_val.string_value
            elif meta_val.HasField("bool_value"):
                meta_values[key] = meta_val.bool_value
            elif meta_val.HasField("int_value"):
                meta_values[key] = meta_val.int_value
            elif meta_val.HasField("double_value"):
                meta_values[key] = meta_val.double_value

        from yaraast.ast.modifiers import MetaEntry

        meta = [
            MetaEntry.from_key_value(key, value, pb_rule.meta_scopes.get(key) or None)
            for key, value in meta_values.items()
        ]

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
        pragmas_for_rule = [protobuf_to_in_rule_pragma(pb_pragma) for pb_pragma in pb_rule.pragmas]

        rules.append(
            Rule(
                name=pb_rule.name,
                modifiers=list(pb_rule.modifiers),
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition,
                pragmas=pragmas_for_rule,
            )
        )

    return YaraFile(
        imports=imports,
        includes=includes,
        rules=rules,
        extern_rules=extern_rules,
        extern_imports=extern_imports,
        pragmas=pragmas,
        namespaces=namespaces,
    )


def protobuf_to_extern_rule(pb_extern_rule):
    from yaraast.ast.extern import ExternRule
    from yaraast.ast.modifiers import RuleModifier
    from yaraast.errors import ValidationError

    modifiers = []
    for modifier in pb_extern_rule.modifiers:
        try:
            modifiers.append(RuleModifier.from_string(modifier))
        except (ValueError, ValidationError):
            modifiers.append(modifier)

    return ExternRule(
        name=pb_extern_rule.name,
        modifiers=modifiers,
        namespace=pb_extern_rule.namespace or None,
    )


def protobuf_to_extern_import(pb_extern_import):
    from yaraast.ast.extern import ExternImport

    return ExternImport(
        module_path=pb_extern_import.module_path,
        alias=pb_extern_import.alias or None,
        rules=list(pb_extern_import.rules),
    )


def protobuf_to_extern_namespace(pb_namespace):
    from yaraast.ast.extern import ExternNamespace

    return ExternNamespace(
        name=pb_namespace.name,
        extern_rules=[protobuf_to_extern_rule(pb_rule) for pb_rule in pb_namespace.extern_rules],
    )


def _protobuf_pragma_scope(scope_text):
    from yaraast.ast.pragmas import PragmaScope

    try:
        return PragmaScope(scope_text or PragmaScope.FILE.value)
    except ValueError:
        return PragmaScope.FILE


def protobuf_to_pragma(pb_pragma):
    from yaraast.ast.pragmas import (
        ConditionalDirective,
        CustomPragma,
        DefineDirective,
        IncludeOncePragma,
        Pragma,
        PragmaType,
        UndefDirective,
    )

    pragma_type = PragmaType.from_string(
        pb_pragma.pragma_type or pb_pragma.name or PragmaType.CUSTOM.value
    )
    scope = _protobuf_pragma_scope(pb_pragma.scope)
    parameters = {key: _meta_value_to_python(value) for key, value in pb_pragma.parameters.items()}

    if pragma_type == PragmaType.INCLUDE_ONCE:
        pragma = IncludeOncePragma()
    elif pragma_type == PragmaType.DEFINE and pb_pragma.macro_name:
        pragma = DefineDirective(
            macro_name=pb_pragma.macro_name,
            macro_value=pb_pragma.macro_value if pb_pragma.HasField("macro_value") else None,
        )
    elif pragma_type == PragmaType.UNDEF and pb_pragma.macro_name:
        pragma = UndefDirective(macro_name=pb_pragma.macro_name)
    elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF, PragmaType.ENDIF}:
        pragma = ConditionalDirective(
            pragma_type,
            condition=pb_pragma.condition if pb_pragma.HasField("condition") else None,
        )
    elif pragma_type == PragmaType.CUSTOM:
        pragma = CustomPragma(
            name=pb_pragma.name,
            arguments=list(pb_pragma.arguments),
            parameters=parameters,
            scope=scope,
        )
    else:
        pragma = Pragma(
            pragma_type=pragma_type,
            name=pb_pragma.name,
            arguments=list(pb_pragma.arguments),
            scope=scope,
        )
    pragma.scope = scope
    return pragma


def protobuf_to_in_rule_pragma(pb_in_rule_pragma):
    from yaraast.ast.pragmas import InRulePragma

    return InRulePragma(
        pragma=protobuf_to_pragma(pb_in_rule_pragma.pragma),
        position=pb_in_rule_pragma.position or "before_strings",
    )


def _protobuf_to_hex_token(pb_token):
    from yaraast.ast.strings import (
        HexAlternative,
        HexByte,
        HexJump,
        HexNegatedByte,
        HexNibble,
        HexWildcard,
    )

    if pb_token.HasField("byte"):
        return HexByte(value=int(pb_token.byte.value))
    if pb_token.HasField("negated_byte"):
        return HexNegatedByte(value=int(pb_token.negated_byte.value))
    if pb_token.HasField("wildcard"):
        return HexWildcard()
    if pb_token.HasField("jump"):
        return HexJump(
            min_jump=pb_token.jump.min_jump if pb_token.jump.HasField("min_jump") else None,
            max_jump=pb_token.jump.max_jump if pb_token.jump.HasField("max_jump") else None,
        )
    if pb_token.HasField("alternative"):
        alternatives = []
        for pb_alternative in pb_token.alternative.alternatives:
            alternative = []
            for nested_pb_token in pb_alternative.tokens:
                token = _protobuf_to_hex_token(nested_pb_token)
                if token is not None:
                    alternative.append(token)
            alternatives.append(alternative)
        return HexAlternative(alternatives=alternatives)
    if pb_token.HasField("nibble"):
        return HexNibble(high=pb_token.nibble.high, value=pb_token.nibble.value)
    return None


def _typed_modifier_value(pb_modifier):
    if pb_modifier.HasField("typed_value"):
        typed_value = pb_modifier.typed_value
        if typed_value.HasField("string_value"):
            return typed_value.string_value
        if typed_value.HasField("bool_value"):
            return typed_value.bool_value
        if typed_value.HasField("int_value"):
            return typed_value.int_value
        if typed_value.HasField("double_value"):
            return typed_value.double_value
    return None


def _legacy_modifier_value(name: str, value: str):
    if name == "xor":
        if "-" in value:
            low, high = value.split("-", maxsplit=1)
            if low.isdigit() and high.isdigit():
                return (int(low), int(high))
        if value.isdigit():
            return int(value)
    return value


def _protobuf_modifier_value(pb_modifier):
    if len(pb_modifier.tuple_value) == 2:
        return (pb_modifier.tuple_value[0], pb_modifier.tuple_value[1])

    typed_value = _typed_modifier_value(pb_modifier)
    if typed_value is not None:
        return typed_value

    if pb_modifier.value:
        return _legacy_modifier_value(pb_modifier.name, pb_modifier.value)
    return None


def _protobuf_modifiers_to_ast(pb_modifiers):
    from yaraast.ast.modifiers import StringModifier

    return [
        StringModifier.from_name_value(m.name, _protobuf_modifier_value(m)) for m in pb_modifiers
    ]


def protobuf_to_string(pb_string):
    """Convert a protobuf string definition back to AST."""
    from yaraast.ast.strings import HexString, PlainString, RegexString

    if pb_string.HasField("plain"):
        modifiers = _protobuf_modifiers_to_ast(pb_string.plain.modifiers)
        s = PlainString(identifier=pb_string.identifier, value=pb_string.plain.value)
        s.modifiers = modifiers
        return s
    if pb_string.HasField("hex"):
        tokens = []
        for pb_token in pb_string.hex.tokens:
            token = _protobuf_to_hex_token(pb_token)
            if token is not None:
                tokens.append(token)
        modifiers = _protobuf_modifiers_to_ast(pb_string.hex.modifiers)
        s = HexString(identifier=pb_string.identifier, tokens=tokens)
        s.modifiers = modifiers
        return s
    if pb_string.HasField("regex"):
        modifiers = _protobuf_modifiers_to_ast(pb_string.regex.modifiers)
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
        StringWildcard,
        UnaryExpression,
    )
    from yaraast.ast.extern import ExternRuleReference
    from yaraast.ast.modules import DictionaryAccess, ModuleReference
    from yaraast.ast.operators import DefinedExpression, StringOperatorExpression

    if pb_expr.HasField("identifier"):
        return Identifier(name=pb_expr.identifier.name)
    if pb_expr.HasField("string_identifier"):
        return StringIdentifier(name=pb_expr.string_identifier.name)
    if pb_expr.HasField("string_wildcard"):
        return StringWildcard(pattern=pb_expr.string_wildcard.pattern)
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
    if pb_expr.HasField("module_reference"):
        return ModuleReference(module=pb_expr.module_reference.module)
    if pb_expr.HasField("dictionary_access"):
        return DictionaryAccess(
            object=protobuf_to_expression(pb_expr.dictionary_access.object),
            key=(
                protobuf_to_expression(pb_expr.dictionary_access.key_expr)
                if pb_expr.dictionary_access.HasField("key_expr")
                else pb_expr.dictionary_access.key
            ),
        )
    if pb_expr.HasField("extern_rule_reference"):
        return ExternRuleReference(
            rule_name=pb_expr.extern_rule_reference.rule_name,
            namespace=pb_expr.extern_rule_reference.namespace or None,
        )
    if pb_expr.HasField("for_expression"):
        return ForExpression(
            quantifier=(
                protobuf_to_expression(pb_expr.for_expression.quantifier_expr)
                if pb_expr.for_expression.HasField("quantifier_expr")
                else _restore_quantifier_text(pb_expr.for_expression.quantifier)
            ),
            variable=pb_expr.for_expression.variable,
            iterable=protobuf_to_expression(pb_expr.for_expression.iterable),
            body=protobuf_to_expression(pb_expr.for_expression.body),
        )
    if pb_expr.HasField("for_of_expression"):
        return ForOfExpression(
            quantifier=(
                protobuf_to_expression(pb_expr.for_of_expression.quantifier_expr)
                if pb_expr.for_of_expression.HasField("quantifier_expr")
                else _restore_quantifier_text(pb_expr.for_of_expression.quantifier)
            ),
            string_set=_protobuf_string_set_to_ast(pb_expr.for_of_expression),
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
        subject = (
            protobuf_to_expression(pb_expr.in_expression.subject)
            if pb_expr.in_expression.HasField("subject")
            else pb_expr.in_expression.string_id
        )
        return InExpression(
            subject=subject,
            range=protobuf_to_expression(pb_expr.in_expression.range),
        )
    if pb_expr.HasField("of_expression"):
        return OfExpression(
            quantifier=(
                _restore_quantifier_text(pb_expr.of_expression.quantifier_text)
                if pb_expr.of_expression.HasField("quantifier_text")
                else protobuf_to_expression(pb_expr.of_expression.quantifier)
            ),
            string_set=_protobuf_string_set_to_ast(pb_expr.of_expression),
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
