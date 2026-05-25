"""Real tests for enhanced parser events mixin without test doubles."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import EventAssignment, EventStatement, JoinCondition
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


def _tok(tt: T, value: str | int | float | None, yt: YaraLTokenType | None = None) -> YaraLToken:
    return YaraLToken(type=tt, value=value, line=1, column=1, length=1, yaral_type=yt)


def _set_tokens(p: EnhancedYaraLParser, toks: list[YaraLToken]) -> None:
    p.tokens = [*toks, _tok(T.EOF, None, YaraLTokenType.EOF)]
    p.current = 0


def test_parse_event_statement_multiple_assignments_real() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
            _tok(T.IDENTIFIER, "and"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
            _tok(T.IN, "in"),
            _tok(T.STRING, "1.2.3.4"),
        ],
    )
    stmts = p._parse_event_statement()
    assert isinstance(stmts, list) and len(stmts) == 2
    assert all(isinstance(s, EventAssignment) for s in stmts)


def test_parse_join_and_pattern_helpers_real() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "join"),
            _tok(T.IDENTIFIER, "e1"),
            _tok(T.IDENTIFIER, "on"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "with"),
            _tok(T.IDENTIFIER, "e2"),
        ],
    )
    join = p._parse_join_statement()
    assert isinstance(join, JoinCondition)

    p2 = EnhancedYaraLParser("")
    _set_tokens(p2, [_tok(T.IDENTIFIER, "all")])
    all_pattern = p2._parse_complex_event_pattern()
    assert isinstance(all_pattern, EventStatement)
    assert all_pattern.text == "all"

    p3 = EnhancedYaraLParser("")
    _set_tokens(p3, [_tok(T.IDENTIFIER, "any")])
    any_pattern = p3._parse_complex_event_pattern()
    assert isinstance(any_pattern, EventStatement)
    assert any_pattern.text == "any"

    p4 = EnhancedYaraLParser("")
    _set_tokens(
        p4,
        [
            _tok(T.IDENTIFIER, "evt"),
            _tok(T.IDENTIFIER, "followed"),
            _tok(T.IDENTIFIER, "by"),
            _tok(T.IDENTIFIER, "evt2"),
        ],
    )
    temporal_pattern = p4._parse_complex_event_pattern()
    assert isinstance(temporal_pattern, EventStatement)
    assert temporal_pattern.text == "evt followed by evt2"


def test_parse_events_section_real() -> None:
    p = EnhancedYaraLParser("")
    _set_tokens(
        p,
        [
            _tok(T.IDENTIFIER, "events"),
            _tok(T.COLON, ":"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "event_type"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "LOGIN"),
            _tok(T.IDENTIFIER, "join"),
            _tok(T.IDENTIFIER, "e1"),
            _tok(T.IDENTIFIER, "on"),
            _tok(T.IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "with"),
            _tok(T.IDENTIFIER, "e2"),
            _tok(T.RBRACE, "}"),
        ],
    )
    section = p._parse_events_section()
    assert section.statements


def test_parse_function_event_statement_preserves_generated_text() -> None:
    ast = EnhancedYaraLParser(
        'rule regex_event { events: re.regex($e.target.hostname, "evil.*") nocase condition: $e }'
    ).parse()

    events = ast.rules[0].events
    assert events is not None
    statement = events.statements[0]
    assert isinstance(statement, EventStatement)
    assert statement.text == 're.regex($e.target.hostname, "evil.*") nocase'

    generated = YaraLGenerator().generate(ast)
    assert 're.regex($e.target.hostname, "evil.*") nocase' in generated


def test_parse_parenthesized_event_statement_preserves_generated_text() -> None:
    ast = EnhancedYaraLParser(
        'rule bool_event { events: ($e.metadata.event_type = "LOGIN" or $e.metadata.event_type = "AUTH") condition: $e }'
    ).parse()

    events = ast.rules[0].events
    assert events is not None
    statement = events.statements[0]
    assert isinstance(statement, EventStatement)
    assert statement.text == '($e.metadata.event_type = "LOGIN" or $e.metadata.event_type = "AUTH")'

    generated = YaraLGenerator().generate(ast)
    assert '($e.metadata.event_type = "LOGIN" or $e.metadata.event_type = "AUTH")' in generated


def test_parse_function_event_assignment_preserves_generated_text() -> None:
    ast = EnhancedYaraLParser(
        'rule capture_event { events: $host = re.capture($e.target.hostname, "(.*)") condition: $e }'
    ).parse()

    events = ast.rules[0].events
    assert events is not None
    statement = events.statements[0]
    assert isinstance(statement, EventStatement)
    assert statement.text == '$host = re.capture($e.target.hostname, "(.*)")'

    generated = YaraLGenerator().generate(ast)
    assert '$host = re.capture($e.target.hostname, "(.*)")' in generated


def test_parse_field_event_assignment_preserves_generated_text() -> None:
    ast = EnhancedYaraLParser(
        "rule host_event { events: $host = $e.target.hostname condition: $e }"
    ).parse()

    events = ast.rules[0].events
    assert events is not None
    statement = events.statements[0]
    assert isinstance(statement, EventStatement)
    assert statement.text == "$host = $e.target.hostname"

    generated = YaraLGenerator().generate(ast)
    assert "$host = $e.target.hostname" in generated


def test_parse_event_variable_comparison_preserves_generated_text() -> None:
    ast = EnhancedYaraLParser("rule cmp_event { events: $left != $right condition: $left }").parse()

    events = ast.rules[0].events
    assert events is not None
    statement = events.statements[0]
    assert isinstance(statement, EventStatement)
    assert statement.text == "$left != $right"

    generated = YaraLGenerator().generate(ast)
    assert "$left != $right" in generated


def test_parse_event_variable_reference_list_preserves_generated_text() -> None:
    ast = EnhancedYaraLParser(
        "rule list_event { events: $ip in %suspicious_ips% condition: $ip }"
    ).parse()

    events = ast.rules[0].events
    assert events is not None
    statement = events.statements[0]
    assert isinstance(statement, EventStatement)
    assert statement.text == "$ip in %suspicious_ips%"

    generated = YaraLGenerator().generate(ast)
    assert "$ip in %suspicious_ips%" in generated


def test_parse_integer_event_comparison_preserves_generated_text() -> None:
    ast = EnhancedYaraLParser(
        "rule numeric_event { events: 604800 <= $e.metadata.event_timestamp.seconds condition: $e }"
    ).parse()

    events = ast.rules[0].events
    assert events is not None
    statement = events.statements[0]
    assert isinstance(statement, EventStatement)
    assert statement.text == "604800 <= $e.metadata.event_timestamp.seconds"

    generated = YaraLGenerator().generate(ast)
    assert "604800 <= $e.metadata.event_timestamp.seconds" in generated


def test_parse_raw_event_statement_stops_before_next_event_statement() -> None:
    ast = EnhancedYaraLParser("""
        rule multi_raw {
          events:
            re.regex($e.hostname, "evil")
            $e.metadata.event_type = "LOGIN"
          condition:
            $e
        }
        """).parse()

    events = ast.rules[0].events
    assert events is not None
    assert len(events.statements) == 2
    first, second = events.statements
    assert isinstance(first, EventStatement)
    assert first.text == 're.regex($e.hostname, "evil")'
    assert isinstance(second, EventAssignment)
    assert second.event_var.name == "$e"

    generated = YaraLGenerator().generate(ast)
    assert 're.regex($e.hostname, "evil")\n    $e.metadata.event_type = "LOGIN"' in generated


def test_parse_raw_event_statement_preserves_multiline_continuation() -> None:
    ast = EnhancedYaraLParser("""
        rule multiline_raw {
          events:
            604800 <=
              $e.metadata.event_timestamp.seconds
          condition:
            $e
        }
        """).parse()

    events = ast.rules[0].events
    assert events is not None
    statement = events.statements[0]
    assert isinstance(statement, EventStatement)
    assert statement.text == "604800 <= $e.metadata.event_timestamp.seconds"


def test_parse_complex_event_patterns_preserves_generated_text() -> None:
    ast = EnhancedYaraLParser("""
        rule complex_patterns {
          events:
            all
            any
            e1 followed by e2
          condition:
            $e
        }
        """).parse()

    events = ast.rules[0].events
    assert events is not None
    assert [statement.text for statement in events.statements] == [
        "all",
        "any",
        "e1 followed by e2",
    ]

    generated = YaraLGenerator().generate(ast)
    assert "all\n    any\n    e1 followed by e2" in generated
