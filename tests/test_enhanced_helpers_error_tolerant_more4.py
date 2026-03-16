from __future__ import annotations

from yaraast.ast.expressions import BooleanLiteral
from yaraast.lexer.tokens import TokenType as T
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


def test_enhanced_regex_pattern_token_without_slashes_and_short_modifiers() -> None:
    p = EnhancedYaraLParser("")

    _set_tokens(p, [_tok(T.REGEX, "rawpattern")])
    rp = p._parse_regex_pattern()
    assert rp.pattern == "rawpattern"
    assert rp.flags == []

    _set_tokens(
        p,
        [
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "ab"),
            _tok(T.DIVIDE, "/"),
            _tok(T.IDENTIFIER, "ix"),
        ],
    )
    rp2 = p._parse_regex_pattern()
    assert rp2.pattern == "ab"
    assert rp2.flags == []


def test_error_tolerant_parser_normal_success_and_inline_condition_line() -> None:
    parser = ErrorTolerantParser()
    result = parser.parse("rule ok {\n    condition:\n        true\n}\n")

    assert result.errors == []
    assert result.ast.rules
    assert result.ast.rules[0].name == "ok"

    p2 = ErrorTolerantParser()
    rule = p2._create_rule_from_body("inline_cond", [], ["condition: true", "}"])
    assert isinstance(rule.condition, BooleanLiteral)
    assert rule.condition.value is True
