"""Further branch coverage for CLI visitor formatters and tree builder."""

from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

from rich.console import Console

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import Identifier, IntegerLiteral, StringLiteral
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexString, PlainString
from yaraast.cli.visitors.formatters import (
    ConditionStringFormatter,
    DetailedNodeStringFormatter,
    ExpressionStringFormatter,
)
from yaraast.cli.visitors.tree_builder import ASTTreeBuilder


class _NoClassAttr:
    def __getattribute__(self, name: str):
        if name == "__class__":
            raise AttributeError("hidden")
        return super().__getattribute__(name)


class BinaryExpression:
    def __init__(self, operator: str, left, right) -> None:
        self.operator = operator
        self.left = left
        self.right = right


class _CustomMod:
    pass


class _MetaKV:
    def __init__(self, key: str, value) -> None:
        self.key = key
        self.value = value


def _render(tree) -> str:
    c = Console(file=StringIO(), record=True, force_terminal=False)
    c.print(tree)
    return c.export_text()


def test_condition_formatter_remaining_paths() -> None:
    fmt = ConditionStringFormatter()

    assert fmt.format_condition(_NoClassAttr()) == "true"

    # Empty parts after filtering ('...') forces fallback simple formatting path.
    expr = BinaryExpression("and", _NoClassAttr(), _NoClassAttr())
    assert fmt.format_condition(expr, depth=0) == "... and ..."

    # Force hash and long-condition branches in parts list formatting.
    hash_short = fmt._format_parts_list(["hash.md5 == 1", "hash.sha1 == 2"], "and")
    assert "hash.md5" in hash_short
    long_non_hash = fmt._format_parts_list([f"p{i}" for i in range(9)], "or")
    assert "..." in long_non_hash

    assert fmt._format_string_count(SimpleNamespace(), 0) == "#string"
    assert fmt._format_string_offset(SimpleNamespace(), 0) == "@string"
    assert fmt._format_string_length(SimpleNamespace(), 0) == "!string"
    assert fmt._format_string_identifier(SimpleNamespace(), 0) == "$string"
    assert fmt._format_parentheses(
        SimpleNamespace(expression=SimpleNamespace(name="x", __class__=type("Identifier", (), {}))),
        0,
    ).startswith("(")
    assert fmt._format_for_expression(SimpleNamespace(), 0) == "for i of ..."

    parts: list[str] = []
    left_only = BinaryExpression(
        "and", SimpleNamespace(name="x", __class__=type("Identifier", (), {})), _NoClassAttr()
    )
    delattr(left_only, "right")
    fmt._collect_binary_parts(left_only, "and", parts, 0)
    assert parts

    nested = BinaryExpression("==", Identifier("a"), IntegerLiteral(1))
    assert fmt._format_binary_expression(nested, 1) == "a == 1"

    many_args = SimpleNamespace(
        function="f", arguments=[Identifier("a"), Identifier("b"), Identifier("c")]
    )
    assert fmt._format_function_call(many_args, 0) == "f(a, b, ...)"

    left_only_top = BinaryExpression("and", Identifier("x"), Identifier("y"))
    delattr(left_only_top, "right")
    parts2: list[str] = []
    fmt._collect_binary_parts(left_only_top, "and", parts2, 0)
    assert parts2


def test_expression_and_detailed_remaining_paths() -> None:
    expr = ExpressionStringFormatter()
    det = DetailedNodeStringFormatter()

    # function args empty branch
    assert expr._format_function_args(SimpleNamespace(), 0) == ""

    # string set branches: no __class__, set expression, wildcard, fallback
    assert expr._format_string_set(SimpleNamespace(string_set=_NoClassAttr()), 0) == "them"

    # type name is inspected from actual class, so use a dynamic class instance.
    set_obj = type(
        "SetExpression",
        (),
        {"elements": [SimpleNamespace(name=f"$a{i}") for i in range(6)]},
    )()
    out_set = expr._format_string_set(SimpleNamespace(string_set=set_obj), 0)
    assert out_set.startswith("(") and "..." in out_set

    wildcard_obj = type("StringWildcard", (), {"prefix": "pref"})()
    assert expr._format_string_set(SimpleNamespace(string_set=wildcard_obj), 0) == "($pref*)"

    other_obj = type("Other", (), {})()
    assert expr._format_string_set(SimpleNamespace(string_set=other_obj), 0) == "them"

    mixed_set = type(
        "SetExpression",
        (),
        {"elements": [SimpleNamespace(name="$a"), IntegerLiteral(2)]},
    )()
    assert expr._format_string_set(SimpleNamespace(string_set=mixed_set), 0) == "($a, 2)"
    assert expr._format_string_set(SimpleNamespace(string_set=Identifier("$x")), 0) == "$x"

    long_literal = StringLiteral("x" * 60)
    assert expr._format_string_literal(long_literal, 0).startswith('"')
    assert "..." in expr._format_string_literal(long_literal, 0)

    fn_expr = SimpleNamespace(
        function="math.abs", arguments=[IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]
    )
    assert expr._format_function_call(fn_expr, 0) == "math.abs(1, 2, ...)"

    assert det._format_boolean_literal(SimpleNamespace(), 0) == "true"
    assert det._format_function_call(
        SimpleNamespace(function="f", arguments=[Identifier("x")]),
        0,
    ).startswith("f(")
    assert det._format_function_args(SimpleNamespace(arguments=[Identifier("z")]), 0) == "z"
    bin_expr = BinaryExpression("and", Identifier("a"), Identifier("b"))
    assert "and" in det._format_binary_expression(bin_expr, 0)


class _BuilderEmptyCondition(ASTTreeBuilder):
    def _get_condition_string(self, condition) -> str:
        return ""


class _BuilderGeneratedEmpty(ASTTreeBuilder):
    def _get_condition_string(self, condition) -> str:
        return super()._get_condition_string(condition)


def test_tree_builder_remaining_paths() -> None:
    builder = ASTTreeBuilder()

    yf = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="common.yar")],
        rules=[],
    )
    txt = _render(builder.visit_yara_file(yf))
    assert "Imports" in txt and "Includes" in txt

    # Non-list modifiers branch + fallback modifier str conversion.
    rule = Rule(name="r", modifiers=_CustomMod())
    rtxt = _render(builder.visit_rule(rule))
    assert "Rule:" in rtxt

    # Meta list branch.
    rule2 = Rule(
        name="r2", meta=[_MetaKV("k", "v"), _MetaKV("n", 1)], strings=[HexString(identifier="$h")]
    )
    r2 = _render(builder.visit_rule(rule2))
    assert "Meta" in r2 and "$h" in r2

    # Condition fallback path when empty string.
    empty_builder = _BuilderEmptyCondition()
    rule3 = Rule(name="r3", condition=SimpleNamespace())
    r3 = _render(empty_builder.visit_rule(rule3))
    assert "<complex condition>" in r3

    # Truncation thresholds and boundaries.
    assert builder._get_condition_max_length(11, False) == 1000
    assert builder._get_condition_max_length(6, False) == 700
    assert builder._get_condition_max_length(1, True) == 400

    long = "a and b and c and d and e"
    truncated = builder._truncate_condition_string(long * 30)
    assert truncated.endswith("...")

    assert "Comments" in _render(builder.visit_comment_group(SimpleNamespace()))
    assert "defined" in _render(builder.visit_defined_expression(SimpleNamespace()))
    assert "dict" in _render(builder.visit_dictionary_access(SimpleNamespace()))
    assert "extern import" in _render(builder.visit_extern_import(SimpleNamespace(module="x")))
    assert "extern namespace" in _render(builder.visit_extern_namespace(SimpleNamespace(name="ns")))
    assert "~" in _render(builder.visit_hex_nibble(SimpleNamespace()))
    assert "pragma" in _render(builder.visit_in_rule_pragma(SimpleNamespace()))
    assert "pragma" in _render(builder.visit_pragma(SimpleNamespace(name="once")))
    assert "block" in _render(builder.visit_pragma_block(SimpleNamespace()))
    assert "extern rule ref" in _render(builder.visit_extern_rule_reference(SimpleNamespace()))

    # Cover plain/regex string visitor modifier branches.
    plain = builder.visit_plain_string(
        PlainString(identifier="$a", value="x", modifiers=[Tag(name="t")])
    )
    assert "$a" in _render(plain)
