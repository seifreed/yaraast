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
    assert optimized_rule is rule

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
    assert optimized is yara_file
    assert transformer.nodes_processed >= 1
    assert yara_file.rules[0].location is None
    assert yara_file.rules[0].name == "dup"
    assert yara_file.rules[0].strings[0].value == "dup"
    assert yara_file.imports[0].module == "pe"
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

    assert transformer.visit_string_literal(str_lit) is str_lit
    assert transformer.visit_identifier(ident) is ident
    assert transformer.visit_string_identifier(string_id) is string_id
    assert transformer.visit_string_wildcard(wildcard) is wildcard
    assert transformer.visit_binary_expression(binary) is binary
    assert transformer.visit_unary_expression(unary) is unary
    assert transformer.visit_hex_string(hexs) is hexs
    assert transformer.visit_regex_string(regex) is regex
    assert transformer.visit_plain_string(plain) is plain
    assert transformer.visit_boolean_literal(BooleanLiteral(True)).value is True
    assert transformer.visit_integer_literal(IntegerLiteral(1)).value == 1
    assert transformer.visit_double_literal(DoubleLiteral(1.5)).value == 1.5

    assert pool["hello"] == "hello"
    assert ident.name == "hello"
    assert str_lit.value == "hello"
    assert string_id.name == "$a"
    assert wildcard.pattern == "$a*"
    assert binary.operator == "and"
    assert unary.operator == "not"
    assert regex.regex == "hello"
    assert plain.identifier == "$p"
    assert hexs.identifier == "$h"
