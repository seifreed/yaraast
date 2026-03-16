"""
Basic smoke tests for YARA-L auxiliary modules.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations


# Test that modules can be imported
def test_import_yaral_modules() -> None:
    """Test that all YARA-L modules can be imported."""
    from yaraast.yaral import ast_nodes, lexer, parser, tokens

    assert ast_nodes is not None
    assert lexer is not None
    assert parser is not None
    assert tokens is not None


def test_import_yaral_enhanced_parser() -> None:
    """Test importing enhanced parser module."""
    from yaraast.yaral import enhanced_parser

    assert enhanced_parser is not None


def test_import_yaral_generator() -> None:
    """Test importing generator module."""
    from yaraast.yaral import generator

    assert generator is not None


def test_import_yaral_optimizer() -> None:
    """Test importing optimizer module."""
    from yaraast.yaral import optimizer

    assert optimizer is not None


def test_import_yaral_validator() -> None:
    """Test importing validator module."""
    from yaraast.yaral import validator

    assert validator is not None


# Test AST node creation
def test_create_ast_nodes() -> None:
    """Test creating YARA-L AST nodes."""
    from yaraast.yaral.ast_nodes import (
        EventVariable,
        MetaEntry,
        RegexPattern,
        TimeWindow,
        UDMFieldPath,
    )

    # Create instances
    event_var = EventVariable(name="$e")
    assert event_var.name == "$e"

    meta_entry = MetaEntry(key="author", value="Test")
    assert meta_entry.key == "author"
    assert meta_entry.value == "Test"

    time_window = TimeWindow(duration=5, unit="m")
    assert time_window.duration == 5
    assert time_window.unit == "m"
    assert time_window.as_string == "5m"

    field_path = UDMFieldPath(parts=["metadata", "event_type"])
    assert field_path.path == "metadata.event_type"

    regex = RegexPattern(pattern="test.*")
    assert regex.pattern == "test.*"


# Test token types
def test_yaral_token_types() -> None:
    """Test YARA-L token type enum."""
    from yaraast.yaral.tokens import YaraLTokenType

    # Verify key token types exist
    assert YaraLTokenType.EVENTS is not None
    assert YaraLTokenType.MATCH is not None
    assert YaraLTokenType.OUTCOME is not None
    assert YaraLTokenType.OVER is not None
    assert YaraLTokenType.EVENT_VAR is not None
    assert YaraLTokenType.REFERENCE_LIST is not None
    assert YaraLTokenType.TIME_LITERAL is not None


# Test lexer token creation
def test_yaral_token_creation() -> None:
    """Test creating YARA-L tokens."""
    from yaraast.lexer.tokens import TokenType as BaseTokenType
    from yaraast.yaral.lexer import YaraLToken
    from yaraast.yaral.tokens import YaraLTokenType

    token = YaraLToken(
        type=BaseTokenType.IDENTIFIER,
        value="test",
        line=1,
        column=1,
        length=4,
        yaral_type=YaraLTokenType.EVENTS,
    )

    assert token.value == "test"
    assert token.line == 1
    assert token.yaral_type == YaraLTokenType.EVENTS


# Test parser error class
def test_yaral_parser_error() -> None:
    """Test YARA-L parser error class."""
    from yaraast.lexer.tokens import TokenType as BaseTokenType
    from yaraast.yaral.lexer import YaraLToken
    from yaraast.yaral.parser import YaraLParserError

    # Create error without token
    error1 = YaraLParserError("Test error")
    assert "Test error" in str(error1)

    # Create error with token
    token = YaraLToken(type=BaseTokenType.IDENTIFIER, value="test", line=5, column=10, length=4)
    error2 = YaraLParserError("Test error", token)
    assert "Parser error at 5:10" in str(error2)
    assert error2.token == token


# Basic round-trip test
def test_parse_and_ast_properties() -> None:
    """Test parsing and accessing AST properties."""
    from yaraast.yaral.parser import YaraLParser

    yaral_code = """
    rule test_properties {
        meta:
            author = "Test"
            version = 1

        events:
            $e.metadata.event_type = "LOGIN"

        match:
            $hostname over 5m

        outcome:
            $count = count($e.metadata.id)

        condition:
            $count > 10

        options:
            enabled = true
    }
    """

    parser = YaraLParser(yaral_code)
    ast = parser.parse()

    # Verify all properties are accessible
    rule = ast.rules[0]
    assert rule.name == "test_properties"
    assert rule.meta is not None
    assert len(rule.meta.entries) == 2

    assert rule.events is not None
    assert len(rule.events.statements) > 0

    assert rule.match is not None
    assert len(rule.match.variables) > 0

    assert rule.outcome is not None
    assert len(rule.outcome.assignments) > 0

    assert rule.condition is not None
    assert rule.condition.expression is not None

    assert rule.options is not None
    assert len(rule.options.options) > 0


# Test file with multiple rules
def test_yaral_file_operations() -> None:
    """Test YaraLFile operations."""
    from yaraast.yaral.ast_nodes import EventsSection, YaraLFile, YaraLRule

    yaral_file = YaraLFile(rules=[])
    assert len(yaral_file.rules) == 0

    rule1 = YaraLRule(name="rule1", events=EventsSection())
    yaral_file.add_rule(rule1)
    assert len(yaral_file.rules) == 1

    rule2 = YaraLRule(name="rule2", events=EventsSection())
    yaral_file.add_rule(rule2)
    assert len(yaral_file.rules) == 2

    assert yaral_file.rules[0].name == "rule1"
    assert yaral_file.rules[1].name == "rule2"
