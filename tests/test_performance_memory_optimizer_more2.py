from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.modifiers import MetaEntry
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.performance.memory_optimizer import MemoryOptimizer, MemoryOptimizerTransformer


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


def test_memory_optimizer_transformer_visits_real_nodes() -> None:
    pool: dict[str, str] = {}
    transformer = MemoryOptimizerTransformer(pool, aggressive=True)

    yara_file = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="common.yar")],
        rules=[
            Rule(
                name="dup",
                tags=[Tag("dup")],
                meta=[MetaEntry("k", "dup")],
                strings=[
                    PlainString(identifier="$a", value="dup"),
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

    optimized = transformer.visit(yara_file)
    assert optimized is not yara_file  # returns a new copy
    assert transformer.nodes_processed >= 1
    assert optimized.rules[0].location is None
    assert optimized.rules[0].name == "dup"
    assert optimized.rules[0].strings[0].value == "dup"
    assert optimized.imports[0].module == "pe"
    assert yara_file.includes[0].path == "common.yar"


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
