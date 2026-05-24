"""Additional direct coverage for BaseVisitor mixins."""

from __future__ import annotations

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    RangeExpression,
    SetExpression,
    StringIdentifier,
    StringWildcard,
)
from yaraast.ast.extern import ExternNamespace, ExternRule
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexAlternative, HexByte, HexNegatedByte, HexToken, StringDefinition
from yaraast.visitor.base import BaseVisitor


class _Visitor(BaseVisitor[None]):
    pass


class _RecordingVisitor(BaseVisitor[None]):
    def __init__(self) -> None:
        self.identifiers: list[str] = []

    def visit_identifier(self, node: Identifier) -> None:
        self.identifiers.append(node.name)

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        self.identifiers.append(node.name)

    def visit_string_wildcard(self, node: StringWildcard) -> None:
        self.identifiers.append(node.pattern)


class _StructuralRecordingVisitor(BaseVisitor[None]):
    def __init__(self) -> None:
        self.comments: list[str] = []
        self.extern_rules: list[str] = []
        self.meta_keys: list[str] = []

    def visit_comment(self, node: Comment) -> None:
        self.comments.append(node.text)

    def visit_extern_rule(self, node: ExternRule) -> None:
        self.extern_rules.append(node.name)

    def visit_meta(self, node: Meta) -> None:
        self.meta_keys.append(node.key)


class _HexRecordingVisitor(BaseVisitor[None]):
    def __init__(self) -> None:
        self.negated_values: list[int | str] = []
        self.byte_values: list[int | str] = []

    def visit_hex_byte(self, node: HexByte) -> None:
        self.byte_values.append(node.value)
        return super().visit_hex_byte(node)

    def visit_hex_negated_byte(self, node: HexNegatedByte) -> None:
        self.negated_values.append(node.value)
        return super().visit_hex_negated_byte(node)


def test_base_visitor_expression_and_condition_methods() -> None:
    visitor = _Visitor()
    condition = Condition()
    literal = BooleanLiteral(value=True)

    assert visitor.visit_expression(Expression()) is None
    assert visitor.visit_expression(literal) is None
    assert visitor.visit_condition(condition) is None


def test_base_visitor_string_definition_and_hex_token_methods() -> None:
    visitor = _Visitor()

    assert visitor.visit_string_definition(StringDefinition(identifier="$a")) is None
    assert visitor.visit_hex_token(HexToken()) is None


def test_base_visitor_supports_hex_negated_byte_super_path() -> None:
    visitor = _HexRecordingVisitor()

    visitor.visit(HexNegatedByte(value=0x4D))

    assert visitor.negated_values == [0x4D]


def test_base_visitor_traverses_scalar_hex_alternatives_as_bytes() -> None:
    visitor = _HexRecordingVisitor()

    visitor.visit(HexAlternative(alternatives=[0x90, "91"]))

    assert visitor.byte_values == [0x90, "91"]


def test_base_visitor_traverses_in_expression_subject_nodes() -> None:
    visitor = _RecordingVisitor()

    visitor.visit(
        InExpression(
            subject=Identifier("subject"),
            range=RangeExpression(low=Identifier("low"), high=Identifier("high")),
        )
    )

    assert visitor.identifiers == ["subject", "low", "high"]


def test_base_visitor_traverses_condition_quantifier_nodes() -> None:
    visitor = _RecordingVisitor()

    visitor.visit(
        ForExpression(
            quantifier=Identifier("limit"),
            variable="i",
            iterable=SetExpression([IntegerLiteral(1)]),
            body=Identifier("body"),
        )
    )
    visitor.visit(
        ForOfExpression(
            quantifier=Identifier("count"),
            string_set=Identifier("strings"),
            condition=Identifier("condition"),
        )
    )

    assert visitor.identifiers == ["limit", "body", "count", "strings", "condition"]


def test_base_visitor_traverses_raw_string_set_expression_items() -> None:
    visitor = _RecordingVisitor()

    visitor.visit(
        OfExpression(
            quantifier=Identifier("of_count"),
            string_set=[Identifier("of_string"), StringIdentifier("$a")],
        )
    )
    visitor.visit(
        ForOfExpression(
            quantifier=Identifier("for_count"),
            string_set=[Identifier("for_string"), StringWildcard("$api*")],
            condition=Identifier("for_condition"),
        )
    )

    assert visitor.identifiers == [
        "of_count",
        "of_string",
        "$a",
        "for_count",
        "for_string",
        "$api*",
        "for_condition",
    ]


def test_base_visitor_traverses_nested_structural_nodes() -> None:
    visitor = _StructuralRecordingVisitor()

    visitor.visit(Rule(name="with_meta", meta=[Meta(key="author", value="unit")]))
    visitor.visit(CommentGroup([Comment("one"), Comment("two")]))
    visitor.visit(ExternNamespace(name="ns", extern_rules=[ExternRule(name="Nested")]))

    assert visitor.meta_keys == ["author"]
    assert visitor.comments == ["one", "two"]
    assert visitor.extern_rules == ["Nested"]
