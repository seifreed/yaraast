from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
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
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import CustomPragma, InRulePragma, Pragma, PragmaBlock, PragmaType
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.visitor.transformer_impl import ASTTransformer


def test_transformer_impl_visits_remaining_node_types() -> None:
    t = ASTTransformer()

    assert t._transform_node("not-dataclass") == "not-dataclass"  # type: ignore[arg-type]

    assert isinstance(t.visit_import(Import("pe")), Import)
    assert isinstance(t.visit_include(Include("common.yar")), Include)
    assert isinstance(t.visit_rule(Rule(name="r")), Rule)
    assert isinstance(t.visit_tag(Tag("t")), Tag)

    assert isinstance(t.visit_string_definition(StringDefinition("$x")), StringDefinition)
    assert isinstance(t.visit_plain_string(PlainString("$a", value="v")), PlainString)
    assert isinstance(t.visit_hex_string(HexString("$h", tokens=[HexByte(0x4D)])), HexString)
    assert isinstance(t.visit_regex_string(RegexString("$re", regex="a.*")), RegexString)
    assert isinstance(
        t.visit_string_modifier(StringModifier.from_name_value("ascii")), StringModifier
    )
    assert isinstance(t.visit_hex_token(HexToken()), HexToken)
    assert isinstance(t.visit_hex_byte(HexByte(1)), HexByte)
    assert isinstance(t.visit_hex_wildcard(HexWildcard()), HexWildcard)
    assert isinstance(t.visit_hex_jump(HexJump(1, 2)), HexJump)
    assert isinstance(
        t.visit_hex_alternative(HexAlternative([[HexByte(1)], [HexByte(2)]])), HexAlternative
    )
    assert isinstance(t.visit_hex_nibble(HexNibble(high=True, value=0xA)), HexNibble)

    assert isinstance(t.visit_expression(Expression()), Expression)
    assert isinstance(t.visit_identifier(Identifier("id")), Identifier)
    assert isinstance(t.visit_string_identifier(StringIdentifier("$a")), StringIdentifier)
    assert isinstance(t.visit_string_wildcard(StringWildcard("$a*")), StringWildcard)
    assert isinstance(t.visit_string_count(StringCount("a")), StringCount)
    assert isinstance(t.visit_string_offset(StringOffset("a")), StringOffset)
    assert isinstance(t.visit_string_length(StringLength("a")), StringLength)
    assert isinstance(t.visit_integer_literal(IntegerLiteral(1)), IntegerLiteral)
    assert isinstance(t.visit_double_literal(DoubleLiteral(1.5)), DoubleLiteral)
    assert isinstance(t.visit_string_literal(StringLiteral("s")), StringLiteral)
    assert isinstance(t.visit_regex_literal(RegexLiteral("ab.*", "i")), RegexLiteral)
    assert isinstance(t.visit_boolean_literal(BooleanLiteral(True)), BooleanLiteral)
    assert isinstance(
        t.visit_binary_expression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2))),
        BinaryExpression,
    )
    assert isinstance(
        t.visit_unary_expression(UnaryExpression("not", BooleanLiteral(False))), UnaryExpression
    )
    assert isinstance(
        t.visit_parentheses_expression(ParenthesesExpression(BooleanLiteral(True))),
        ParenthesesExpression,
    )
    assert isinstance(t.visit_set_expression(SetExpression([IntegerLiteral(1)])), SetExpression)
    assert isinstance(
        t.visit_range_expression(RangeExpression(IntegerLiteral(1), IntegerLiteral(2))),
        RangeExpression,
    )
    assert isinstance(
        t.visit_function_call(
            FunctionCall("math.entropy", [IntegerLiteral(0), IntegerLiteral(10)])
        ),
        FunctionCall,
    )
    assert isinstance(
        t.visit_array_access(ArrayAccess(Identifier("arr"), IntegerLiteral(0))), ArrayAccess
    )
    assert isinstance(t.visit_member_access(MemberAccess(Identifier("pe"), "is_dll")), MemberAccess)
    assert isinstance(t.visit_condition(Condition()), Condition)

    assert isinstance(
        t.visit_for_expression(
            ForExpression(
                "any", "i", RangeExpression(IntegerLiteral(1), IntegerLiteral(2)), Identifier("i")
            )
        ),
        ForExpression,
    )
    assert isinstance(
        t.visit_for_of_expression(ForOfExpression("any", Identifier("them"), Identifier("$a"))),
        ForOfExpression,
    )
    assert isinstance(t.visit_at_expression(AtExpression("$a", IntegerLiteral(0))), AtExpression)
    assert isinstance(
        t.visit_in_expression(
            InExpression("$a", RangeExpression(IntegerLiteral(0), IntegerLiteral(10)))
        ),
        InExpression,
    )
    assert isinstance(
        t.visit_of_expression(OfExpression(IntegerLiteral(1), Identifier("them"))), OfExpression
    )

    assert isinstance(t.visit_meta(Meta("author", "me")), Meta)
    assert isinstance(t.visit_module_reference(ModuleReference("pe")), ModuleReference)
    assert isinstance(
        t.visit_dictionary_access(
            DictionaryAccess(ModuleReference("pe"), StringLiteral("CompanyName"))
        ),
        DictionaryAccess,
    )
    assert isinstance(t.visit_comment(Comment("note")), Comment)
    assert isinstance(t.visit_comment_group(CommentGroup([Comment("a")])), CommentGroup)
    assert isinstance(
        t.visit_defined_expression(DefinedExpression(Identifier("$a"))), DefinedExpression
    )
    assert isinstance(
        t.visit_string_operator_expression(
            StringOperatorExpression(StringLiteral("a"), "icontains", StringLiteral("A"))
        ),
        StringOperatorExpression,
    )

    assert isinstance(t.visit_extern_rule(ExternRule("R")), ExternRule)
    assert isinstance(t.visit_extern_rule_reference(ExternRuleReference("R")), ExternRuleReference)
    assert isinstance(t.visit_extern_import(ExternImport("mods.yar")), ExternImport)
    assert isinstance(t.visit_extern_namespace(ExternNamespace("ns")), ExternNamespace)

    pragma = CustomPragma("demo")
    with pytest.raises(TypeError):
        t.visit_pragma(pragma)
    regular_pragma = Pragma(PragmaType.PRAGMA, "pragma")
    assert isinstance(t.visit_in_rule_pragma(InRulePragma(regular_pragma)), InRulePragma)
    assert isinstance(t.visit_pragma_block(PragmaBlock([regular_pragma])), PragmaBlock)

    yf = YaraFile(rules=[Rule(name="copy", condition=BooleanLiteral(True))])
    out = t.visit_yara_file(yf)
    assert isinstance(out, YaraFile)
