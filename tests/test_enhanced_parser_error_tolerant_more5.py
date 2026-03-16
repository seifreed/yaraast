from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def test_enhanced_parser_iteration_cap_and_index_end_path() -> None:
    p = EnhancedYaraLParser("")
    p.tokens = [_tok(T.PLUS, "+")] * 10001 + [_tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0

    ast = p.parse()
    assert ast.rules == []
    assert any("maximum iterations" in err for err in p.errors)

    p2 = EnhancedYaraLParser("")
    p2.tokens = [_tok(T.EOF, None, YaraLTokenType.EOF)]
    p2.current = 5
    assert p2._is_at_end() is True


def test_error_tolerant_parser_valid_input_currently_recovers_cleanly() -> None:
    parser = ErrorTolerantParser()
    result = parser.parse("rule ok {\ncondition:\ntrue\n}\n")

    assert result.errors == []
    assert parser.get_recovered_rules()
    assert result.ast.rules
