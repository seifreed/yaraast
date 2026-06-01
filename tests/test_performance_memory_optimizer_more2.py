from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment
from yaraast.ast.conditions import ForOfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    RegexLiteral,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.modifiers import (
    MetaEntry,
    RuleModifier,
    RuleModifierType,
    StringModifier,
    StringModifierType,
)
from yaraast.ast.pragmas import CustomPragma
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.performance.memory_optimizer import MemoryOptimizer, MemoryOptimizerTransformer


def _fresh_text(value: str) -> str:
    return ("_" + value)[1:]


def test_memory_optimizer_rule_list_usage_and_batch_paths() -> None:
    optimizer = MemoryOptimizer(aggressive=True, gc_threshold=2)
    rule = Rule(
        name="dup",
        tags=[Tag("tag"), Tag("tag")],
        meta=[MetaEntry("author", "alice"), MetaEntry("author", "alice")],
        strings=[
            PlainString(identifier="$a", value="same"),
            RegexString(identifier="$r", regex="same"),
            HexString(identifier="$h", tokens=[HexByte(0x41)]),
        ],
        condition=BinaryExpression(
            left=Identifier("same"),
            operator="and",
            right=UnaryExpression("not", StringIdentifier("$a")),
        ),
    )

    optimized_rule = optimizer.optimize_rule(rule)
    assert optimized_rule is not rule  # optimizer returns a new copy

    optimized_rules = optimizer.optimize_rules([rule])
    assert optimized_rules == [rule]

    usage = optimizer.get_memory_usage()
    assert {"rss_mb", "vms_mb", "percent", "available_mb"} <= set(usage)

    batches = list(
        optimizer.batch_process_with_memory_limit(list(range(5)), lambda x: x + 1, batch_size=2)
    )
    assert batches == [[1, 2], [3, 4], [5]]

    with pytest.raises(ValueError, match="batch_size must be at least 1"):
        list(optimizer.batch_process_with_memory_limit([1], lambda x: x, batch_size=0))

    with pytest.raises(TypeError, match="batch_size must be an integer"):
        list(
            optimizer.batch_process_with_memory_limit([1], lambda x: x, batch_size=cast(Any, True))
        )


def test_memory_optimizer_optimize_rule_records_stats_and_resets_pool() -> None:
    optimizer = MemoryOptimizer()
    first_rule = Rule(
        name="first",
        tags=[Tag("large")],
        meta=[MetaEntry("owner", "alice")],
        strings=[
            PlainString(identifier="$first_a", value="alpha"),
            PlainString(identifier="$first_b", value="beta"),
            RegexString(identifier="$first_r", regex="gamma"),
        ],
        condition=StringIdentifier("$first_a"),
    )
    second_rule = Rule(
        name="second",
        strings=[PlainString(identifier="$second", value="delta")],
        condition=StringIdentifier("$second"),
    )

    optimizer.optimize_rule(first_rule)
    first_stats = optimizer.get_statistics()
    assert first_stats["nodes_processed"] > 0
    assert first_stats["strings_pooled"] > 0
    assert first_stats["string_pool_size"] > 0

    optimizer.optimize_rule(second_rule)
    second_stats = optimizer.get_statistics()
    assert second_stats["nodes_processed"] > first_stats["nodes_processed"]
    assert second_stats["strings_pooled"] > first_stats["strings_pooled"]
    assert second_stats["string_pool_size"] < first_stats["string_pool_size"]


def test_memory_optimizer_transformer_visits_real_nodes() -> None:
    pool: dict[str, str] = {}
    transformer = MemoryOptimizerTransformer(pool, aggressive=True)

    yara_file = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="common.yar")],
        extern_rules=[ExternRule("external_rule")],
        extern_imports=[ExternImport("external_rules", alias="ext", rules=["external_rule"])],
        pragmas=[CustomPragma("vendor", arguments=["enabled"])],
        namespaces=[ExternNamespace("corp", [ExternRule("nested_rule")])],
        rules=[
            Rule(
                name="dup",
                modifiers=[RuleModifier(RuleModifierType.PRIVATE)],
                tags=[Tag("dup")],
                meta=[MetaEntry("k", "dup")],
                strings=[
                    PlainString(
                        identifier="$a",
                        value="dup",
                        modifiers=[StringModifier(StringModifierType.NOCASE)],
                    ),
                    HexString(identifier="$h", tokens=[HexByte(0x41)]),
                    RegexString(identifier="$r", regex="dup"),
                ],
                condition=BinaryExpression(
                    left=StringLiteral("dup"),
                    operator="or",
                    right=Identifier("dup"),
                ),
            ),
        ],
    )
    yara_file.leading_comments = [Comment("file lead")]
    yara_file.trailing_comment = Comment("file tail")

    optimized = transformer.visit(yara_file)
    assert optimized is not yara_file  # returns a new copy
    assert transformer.nodes_processed >= 1
    assert optimized.rules[0].location is None
    assert optimized.rules[0].name == "dup"
    first_string = optimized.rules[0].strings[0]
    assert isinstance(first_string, PlainString)
    assert first_string.value == "dup"
    assert optimized.imports[0].module == "pe"
    assert optimized.extern_rules is not yara_file.extern_rules
    assert optimized.extern_rules[0] is not yara_file.extern_rules[0]
    assert optimized.extern_imports is not yara_file.extern_imports
    assert optimized.pragmas is not yara_file.pragmas
    assert optimized.namespaces is not yara_file.namespaces
    optimized.extern_rules.append(ExternRule("new_external"))
    assert len(yara_file.extern_rules) == 1
    assert optimized.leading_comments is not yara_file.leading_comments
    assert optimized.leading_comments[0] is not yara_file.leading_comments[0]
    optimized.leading_comments[0].text = "changed"
    assert yara_file.leading_comments[0].text == "file lead"
    assert optimized.trailing_comment is not None
    assert yara_file.trailing_comment is not None
    assert optimized.trailing_comment is not yara_file.trailing_comment
    optimized.trailing_comment.text = "changed"
    assert yara_file.trailing_comment.text == "file tail"

    optimized_rule = optimized.rules[0]
    original_rule = yara_file.rules[0]
    assert optimized_rule.modifiers is not original_rule.modifiers
    optimized_rule.modifiers.append(RuleModifier(RuleModifierType.GLOBAL))
    assert len(original_rule.modifiers) == 1

    optimized_plain = optimized_rule.strings[0]
    original_plain = original_rule.strings[0]
    assert isinstance(optimized_plain, PlainString)
    assert isinstance(original_plain, PlainString)
    assert optimized_plain.modifiers is not original_plain.modifiers
    assert optimized_plain.modifiers[0] is not original_plain.modifiers[0]
    optimized_plain.modifiers.append(StringModifier(StringModifierType.WIDE))
    assert len(original_plain.modifiers) == 1

    optimized_hex = optimized_rule.strings[1]
    original_hex = original_rule.strings[1]
    assert isinstance(optimized_hex, HexString)
    assert isinstance(original_hex, HexString)
    assert optimized_hex.tokens is not original_hex.tokens
    assert optimized_hex.tokens[0] is not original_hex.tokens[0]
    optimized_hex.tokens.append(HexByte(0x42))
    assert len(original_hex.tokens) == 1
    assert yara_file.includes[0].path == "common.yar"


def test_memory_optimizer_transformer_does_not_count_rejected_nodes() -> None:
    transformer = MemoryOptimizerTransformer({}, aggressive=False)

    with pytest.raises(TypeError, match="Visitor node must be an ASTNode"):
        transformer.visit(cast(Any, object()))

    assert transformer.nodes_processed == 0


def test_memory_optimizer_transformer_rejects_invalid_hex_tokens() -> None:
    transformer = MemoryOptimizerTransformer({}, aggressive=False)
    hex_string = HexString(identifier="$h", tokens=[cast(Any, object())])

    with pytest.raises(TypeError, match="Hex string tokens must contain AST nodes"):
        transformer.visit(hex_string)

    assert transformer.nodes_processed == 0


def test_memory_optimizer_transformer_leaf_visitors_are_passthrough_or_pool() -> None:
    pool: dict[str, str] = {}
    transformer = MemoryOptimizerTransformer(pool, aggressive=False)

    str_lit = StringLiteral("hello")
    ident = Identifier("hello")
    string_id = StringIdentifier("$a")
    wildcard = StringWildcard("$a*")
    binary = BinaryExpression(BooleanLiteral(True), "and", IntegerLiteral(1))
    unary = UnaryExpression("not", Identifier("x"))
    plain = PlainString(identifier="$p", value="hello")
    regex = RegexString(identifier="$r", regex="hello")
    hexs = HexString(identifier="$h", tokens=[HexByte(0x41)])

    result_str = transformer.visit_string_literal(str_lit)
    result_ident = transformer.visit_identifier(ident)
    result_sid = transformer.visit_string_identifier(string_id)
    result_wc = transformer.visit_string_wildcard(wildcard)
    result_bin = transformer.visit_binary_expression(binary)
    result_un = transformer.visit_unary_expression(unary)
    transformer.visit_hex_string(hexs)
    result_regex = transformer.visit_regex_string(regex)
    transformer.visit_plain_string(plain)
    assert transformer.visit_boolean_literal(BooleanLiteral(True)).value is True
    assert transformer.visit_integer_literal(IntegerLiteral(1)).value == 1
    assert transformer.visit_double_literal(DoubleLiteral(1.5)).value == 1.5

    assert pool["hello"] == "hello"
    assert result_ident.name == "hello"
    assert result_str.value == "hello"
    assert result_sid.name == "$a"
    assert result_wc.pattern == "$a*"
    assert result_bin.operator == "and"
    assert result_un.operator == "not"
    assert result_regex.regex == "hello"
    assert plain.identifier == "$p"
    assert hexs.identifier == "$h"


def test_memory_optimizer_copies_literal_metadata() -> None:
    transformer = MemoryOptimizerTransformer({}, aggressive=False)

    integer = IntegerLiteral(7)
    integer.leading_comments = [Comment("integer lead")]

    double = DoubleLiteral(1.5)
    double.leading_comments = [Comment("double lead")]

    boolean = BooleanLiteral(True)
    boolean.trailing_comment = Comment("boolean tail")

    optimized_integer = transformer.visit_integer_literal(integer)
    optimized_double = transformer.visit_double_literal(double)
    optimized_boolean = transformer.visit_boolean_literal(boolean)

    assert optimized_integer is not integer
    assert optimized_integer.leading_comments is not integer.leading_comments
    optimized_integer.leading_comments[0].text = "changed"
    assert integer.leading_comments[0].text == "integer lead"

    assert optimized_double is not double
    assert optimized_double.leading_comments is not double.leading_comments
    optimized_double.leading_comments[0].text = "changed"
    assert double.leading_comments[0].text == "double lead"

    assert optimized_boolean is not boolean
    assert optimized_boolean.trailing_comment is not None
    assert boolean.trailing_comment is not None
    assert optimized_boolean.trailing_comment is not boolean.trailing_comment
    optimized_boolean.trailing_comment.text = "changed"
    assert boolean.trailing_comment.text == "boolean tail"


def test_memory_optimizer_copies_nested_pragma_parameters() -> None:
    transformer = MemoryOptimizerTransformer({}, aggressive=False)
    pragma = CustomPragma(
        "vendor",
        parameters={
            "nested": ["same", StringLiteral("same")],
            "options": {"mode": "same"},
        },
    )

    optimized = transformer.visit_pragma(pragma)
    assert isinstance(optimized, CustomPragma)

    optimized_nested = optimized.parameters["nested"]
    original_nested = pragma.parameters["nested"]
    assert isinstance(optimized_nested, list)
    assert isinstance(original_nested, list)
    assert optimized_nested is not original_nested
    assert optimized_nested[1] is not original_nested[1]
    assert isinstance(optimized_nested[1], StringLiteral)
    optimized_nested[1].value = "changed"
    assert isinstance(original_nested[1], StringLiteral)
    assert original_nested[1].value == "same"

    optimized_options = optimized.parameters["options"]
    original_options = pragma.parameters["options"]
    assert isinstance(optimized_options, dict)
    assert isinstance(original_options, dict)
    assert optimized_options is not original_options
    optimized_options["mode"] = "changed"
    assert original_options["mode"] == "same"


def test_memory_optimizer_pools_generic_expression_strings() -> None:
    pool: dict[str, str] = {}
    transformer = MemoryOptimizerTransformer(pool, aggressive=False)

    function_name = _fresh_text("shared_value")
    regex_pattern = _fresh_text("shared_value")
    assert function_name == regex_pattern
    assert function_name is not regex_pattern

    optimized_call = transformer.visit_function_call(
        FunctionCall(function_name, [RegexLiteral(regex_pattern)])
    )
    optimized_regex = optimized_call.arguments[0]
    assert isinstance(optimized_regex, RegexLiteral)
    assert optimized_call.function is optimized_regex.pattern

    set_item = _fresh_text("$shared")
    identifier_name = _fresh_text("$shared")
    assert set_item == identifier_name
    assert set_item is not identifier_name

    optimized_for_of = transformer.visit_for_of_expression(
        ForOfExpression(
            quantifier="any",
            string_set=[set_item, StringIdentifier(identifier_name)],
        )
    )
    assert isinstance(optimized_for_of.string_set, list)
    optimized_identifier = optimized_for_of.string_set[1]
    assert isinstance(optimized_identifier, StringIdentifier)
    assert optimized_for_of.string_set[0] is optimized_identifier.name
