# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests that drive yaraast.parser._rules to 100% line coverage.

Each test exercises one or more previously uncovered lines by parsing real
YARA source text through the public Parser API or by calling internal mixin
methods with real Token objects — never through mocks or stubs.

Missing lines before this file (from existing parser test suite):
  48-49   _parse_import: ExternImport 'as' without trailing identifier
  67-68   _parse_import_rule_list: empty parenthesised rule list
  77-78   _parse_import_rule_list: missing closing ')'
  117     _parse_file_pragma: fallthrough to generic Pragma construction
  133-134 _parse_define_directive: empty arguments list
  140-141 _parse_undef_directive: empty arguments list
  148-149 _parse_conditional_directive: empty arguments list
  155-156 _parse_named_pragma: empty arguments list
  224-225 _parse_extern_rule: 'extern' not followed by 'rule'
  241     _parse_qualified_identifier: first token is not an IDENTIFIER
  246-247 _parse_qualified_identifier: trailing dot without subsequent identifier
  409     _infer_in_rule_pragma_position: next token is CONDITION
  412-413 _infer_in_rule_pragma_position: next is neither STRINGS nor CONDITION but strings exist
  414     _infer_in_rule_pragma_position: neither STRINGS nor CONDITION and no strings yet
  434-435 _parse_meta_section: scope keyword present but no contextual identifier follows
  465-466 _parse_meta_scope_prefix: scope keyword without colon — backtrack to saved position
"""

from __future__ import annotations

import pytest

from yaraast.ast.extern import ExternImport
from yaraast.ast.pragmas import (
    IncludeOncePragma,
    Pragma,
    PragmaType,
)
from yaraast.ast.strings import PlainString
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.parser import Parser

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tok(tt: TokenType, value: str | int | None = None, line: int = 1) -> Token:
    """Create a Token with a fixed location, useful for token-injection tests."""
    return Token(type=tt, value=value, line=line, column=1)


def _parser_from_tokens(tokens: list[Token]) -> Parser:
    """Return a Parser whose token stream is entirely replaced by *tokens*.

    An EOF sentinel is automatically appended so the parser can detect the
    end of input correctly.
    """
    parser = Parser("rule _seed { condition: true }")
    parser.tokens = [*tokens, _tok(TokenType.EOF)]
    parser.current = 0
    return parser


# ---------------------------------------------------------------------------
# Lines 48-49: ExternImport alias path — 'as' without trailing identifier
# ---------------------------------------------------------------------------


def test_extern_import_alias_without_identifier_raises() -> None:
    """Covering lines 48-49.

    After parsing a rule list (LPAREN present → rules is not None), when the
    parser sees 'as' but the next token is not an IDENTIFIER, it must raise
    ParserError('Expected alias after 'as'').
    """
    parser = _parser_from_tokens(
        [
            _tok(TokenType.STRING, "common"),  # module name
            _tok(TokenType.LPAREN),  # begin selective rule list
            _tok(TokenType.IDENTIFIER, "Foo"),  # rule inside list
            _tok(TokenType.RPAREN),  # end selective rule list
            _tok(TokenType.AS, "as"),  # 'as' keyword
            # No IDENTIFIER follows — EOF will be next
        ]
    )

    with pytest.raises(ParserError, match="Expected alias after 'as'"):
        parser._parse_import()


# ---------------------------------------------------------------------------
# Lines 67-68: _parse_import_rule_list — empty parentheses
# ---------------------------------------------------------------------------


def test_import_rule_list_empty_parens_raises() -> None:
    """Covering lines 67-68.

    A rule list opened with '(' that is immediately closed with ')' is
    syntactically invalid; the parser must raise before consuming ')'.
    """
    parser = _parser_from_tokens(
        [
            _tok(TokenType.LPAREN),
            _tok(TokenType.RPAREN),
        ]
    )

    with pytest.raises(ParserError, match="Expected rule name in import rule list"):
        parser._parse_import_rule_list()


# ---------------------------------------------------------------------------
# Lines 77-78: _parse_import_rule_list — missing closing ')'
# ---------------------------------------------------------------------------


def test_import_rule_list_missing_rparen_raises() -> None:
    """Covering lines 77-78.

    After consuming a valid identifier inside a rule list, if ')' is absent the
    parser must raise 'Expected ')' after import rule list'.
    """
    parser = _parser_from_tokens(
        [
            _tok(TokenType.LPAREN),
            _tok(TokenType.IDENTIFIER, "Bar"),
            # No RPAREN — EOF follows
        ]
    )

    with pytest.raises(ParserError, match=r"Expected '\)' after import rule list"):
        parser._parse_import_rule_list()


# ---------------------------------------------------------------------------
# Line 117: _parse_file_pragma — unknown directive falls through to generic Pragma
# ---------------------------------------------------------------------------


def test_file_pragma_unknown_directive_produces_generic_pragma() -> None:
    """Covering lines 117-120.

    A STRING_COUNT token whose value begins with '#' but whose directive name
    is not one of the built-in keywords must produce a generic Pragma node
    with pragma_type derived from PragmaType.from_string.
    """
    parser = _parser_from_tokens([_tok(TokenType.STRING_COUNT, "#unknown_directive")])

    pragma = parser._parse_file_pragma()

    assert isinstance(pragma, Pragma)
    assert pragma.name == "unknown_directive"


# ---------------------------------------------------------------------------
# Lines 133-134: _parse_define_directive — empty argument list
# ---------------------------------------------------------------------------


def test_define_directive_empty_arguments_raises() -> None:
    """Covering lines 133-134.

    Calling _parse_define_directive with an empty list must raise
    ParserError('Expected macro name after '#define'').
    """
    parser = _parser_from_tokens([])

    with pytest.raises(ParserError, match="Expected macro name after '#define'"):
        parser._parse_define_directive([])


# ---------------------------------------------------------------------------
# Lines 140-141: _parse_undef_directive — empty argument list
# ---------------------------------------------------------------------------


def test_undef_directive_empty_arguments_raises() -> None:
    """Covering lines 140-141.

    Calling _parse_undef_directive with an empty list must raise
    ParserError('Expected macro name after '#undef'').
    """
    parser = _parser_from_tokens([])

    with pytest.raises(ParserError, match="Expected macro name after '#undef'"):
        parser._parse_undef_directive([])


# ---------------------------------------------------------------------------
# Lines 148-149: _parse_conditional_directive — empty argument list
# ---------------------------------------------------------------------------


def test_conditional_directive_empty_arguments_raises() -> None:
    """Covering lines 148-149.

    _parse_conditional_directive with an empty arguments list must raise
    ParserError with the directive name embedded in the message.
    """
    parser = _parser_from_tokens([])

    with pytest.raises(ParserError, match="Expected condition after '#ifdef'"):
        parser._parse_conditional_directive("ifdef", [])

    parser2 = _parser_from_tokens([])
    with pytest.raises(ParserError, match="Expected condition after '#ifndef'"):
        parser2._parse_conditional_directive("ifndef", [])


# ---------------------------------------------------------------------------
# Lines 155-156: _parse_named_pragma — empty argument list
# ---------------------------------------------------------------------------


def test_named_pragma_empty_arguments_raises() -> None:
    """Covering lines 155-156.

    _parse_named_pragma with an empty arguments list must raise
    ParserError('Expected pragma name after '#pragma'').
    """
    parser = _parser_from_tokens([])

    with pytest.raises(ParserError, match="Expected pragma name after '#pragma'"):
        parser._parse_named_pragma([])


# ---------------------------------------------------------------------------
# Lines 224-225: _parse_extern_rule — 'extern' not followed by 'rule'
# ---------------------------------------------------------------------------


def test_extern_rule_without_rule_keyword_raises() -> None:
    """Covering lines 224-225.

    When the token stream provides an IDENTIFIER after 'extern' instead of
    the RULE keyword, the parser must raise 'Expected 'rule' after 'extern''.
    """
    parser = _parser_from_tokens(
        [
            _tok(TokenType.IDENTIFIER, "extern"),  # start_token consumed by _advance()
            _tok(TokenType.IDENTIFIER, "foo"),  # not RULE
        ]
    )

    with pytest.raises(ParserError, match="Expected 'rule' after 'extern'"):
        parser._parse_extern_rule()


# ---------------------------------------------------------------------------
# Line 241: _parse_qualified_identifier — first token is not IDENTIFIER
# ---------------------------------------------------------------------------


def test_qualified_identifier_no_leading_identifier_raises() -> None:
    """Covering line 241.

    When the first token is not an IDENTIFIER, _parse_qualified_identifier
    must raise the caller-supplied error message immediately.
    """
    parser = _parser_from_tokens([_tok(TokenType.LPAREN)])

    with pytest.raises(ParserError, match="Custom error message"):
        parser._parse_qualified_identifier("Custom error message")


# ---------------------------------------------------------------------------
# Lines 246-247: _parse_qualified_identifier — trailing dot without identifier
# ---------------------------------------------------------------------------


def test_qualified_identifier_dot_without_subsequent_identifier_raises() -> None:
    """Covering lines 246-247.

    After consuming 'foo.', if the next token is not an IDENTIFIER the parser
    must raise 'Expected identifier after '.''.
    """
    parser = _parser_from_tokens(
        [
            _tok(TokenType.IDENTIFIER, "foo"),
            _tok(TokenType.DOT),
            # No IDENTIFIER follows — EOF is next
        ]
    )

    with pytest.raises(ParserError, match=r"Expected identifier after '\.'"):
        parser._parse_qualified_identifier("outer error")


# ---------------------------------------------------------------------------
# Line 409: _infer_in_rule_pragma_position — next token is STRINGS
# ---------------------------------------------------------------------------


def test_infer_pragma_position_before_strings_when_strings_token_follows() -> None:
    """Covering line 409.

    When the next token in the stream is STRINGS, the inferred position
    must be 'before_strings' (the first branch, not the fallthrough default).
    """
    parser = _parser_from_tokens([_tok(TokenType.STRINGS)])

    position = parser._infer_in_rule_pragma_position([])

    assert position == "before_strings"


# ---------------------------------------------------------------------------
# Line 410-411: _infer_in_rule_pragma_position — next token is CONDITION
# ---------------------------------------------------------------------------


def test_infer_pragma_position_before_condition() -> None:
    """Covering lines 410-411.

    When the next token in the stream is CONDITION, the inferred position
    must be 'before_condition'.
    """
    parser = _parser_from_tokens([_tok(TokenType.CONDITION)])

    position = parser._infer_in_rule_pragma_position([])

    assert position == "before_condition"


# ---------------------------------------------------------------------------
# Lines 412-413: _infer_in_rule_pragma_position — strings non-empty, next is neither
# ---------------------------------------------------------------------------


def test_infer_pragma_position_after_strings() -> None:
    """Covering lines 412-413.

    When next is neither STRINGS nor CONDITION but the strings argument is
    non-empty, the inferred position must be 'after_strings'.
    """
    parser = _parser_from_tokens([_tok(TokenType.EOF)])
    dummy_string = PlainString(identifier="$x", value="data", modifiers=[])

    position = parser._infer_in_rule_pragma_position([dummy_string])

    assert position == "after_strings"


# ---------------------------------------------------------------------------
# Line 414: _infer_in_rule_pragma_position — neither STRINGS nor CONDITION, no strings
# ---------------------------------------------------------------------------


def test_infer_pragma_position_default_before_strings() -> None:
    """Covering line 414.

    When next is neither STRINGS nor CONDITION and the strings list is empty,
    the inferred position falls through to the default 'before_strings'.
    """
    parser = _parser_from_tokens([_tok(TokenType.EOF)])

    position = parser._infer_in_rule_pragma_position([])

    assert position == "before_strings"


# ---------------------------------------------------------------------------
# Integration: pragma positions through real YARA source parsing
# ---------------------------------------------------------------------------


def test_in_rule_pragma_position_via_real_source_before_condition() -> None:
    """Integration test confirming 'before_condition' via full parse.

    A #define pragma placed between the strings section and the condition
    section must receive position 'before_condition'.
    """
    source = (
        "rule R {\n"
        "    strings:\n"
        '        $a = "foo"\n'
        "    #define MARKER 1\n"
        "    condition:\n"
        "        $a\n"
        "}"
    )
    yara_file = Parser(source).parse()

    assert len(yara_file.rules) == 1
    pragmas = yara_file.rules[0].pragmas
    assert len(pragmas) == 1
    assert pragmas[0].position == "before_condition"


def test_in_rule_pragma_position_via_real_source_after_strings() -> None:
    """Integration test confirming 'after_strings' via full parse.

    When two consecutive pragmas appear after the strings section, the first
    one sees a following STRING_COUNT token (not CONDITION), so its position
    is 'after_strings'; the second sees CONDITION, so its position is
    'before_condition'.
    """
    source = (
        "rule R {\n"
        "    strings:\n"
        '        $a = "foo"\n'
        "    #define A 1\n"
        "    #define B 2\n"
        "    condition:\n"
        "        $a\n"
        "}"
    )
    yara_file = Parser(source).parse()

    pragmas = yara_file.rules[0].pragmas
    assert len(pragmas) == 2
    assert pragmas[0].position == "after_strings"
    assert pragmas[1].position == "before_condition"


# ---------------------------------------------------------------------------
# Lines 434-435: _parse_meta_section — scope set but no key identifier follows
# ---------------------------------------------------------------------------


def test_meta_section_scope_without_identifier_raises() -> None:
    """Covering lines 434-435.

    When _parse_meta_scope_prefix successfully returns a non-None scope (e.g.
    PRIVATE + COLON is present) but the token that follows is not a contextual
    identifier, the parser must raise 'Expected meta key after scope'.
    """
    parser = _parser_from_tokens(
        [
            _tok(TokenType.PRIVATE),  # triggers scope = 'private'
            _tok(TokenType.COLON),  # completes the scope prefix
            _tok(TokenType.RBRACE),  # not a contextual identifier
        ]
    )

    with pytest.raises(ParserError, match="Expected meta key after scope"):
        parser._parse_meta_section()


# ---------------------------------------------------------------------------
# Lines 465-466: _parse_meta_scope_prefix — backtrack when no colon follows
# ---------------------------------------------------------------------------


def test_meta_scope_prefix_backtracks_when_no_colon_follows() -> None:
    """Covering lines 465-466.

    When a PRIVATE token appears but is not followed by COLON, the method
    must restore parser.current to its original position and return None so
    that the caller can re-interpret the PRIVATE token as a regular key.
    """
    parser = _parser_from_tokens(
        [
            _tok(TokenType.PRIVATE),  # scope candidate
            _tok(TokenType.IDENTIFIER, "some_key"),  # colon absent → backtrack
        ]
    )
    original_position = parser.current

    result = parser._parse_meta_scope_prefix()

    assert result is None
    assert parser.current == original_position


def test_meta_scope_prefix_public_backtracks_when_no_colon_follows() -> None:
    """Covering lines 465-466 via the 'public' identifier branch.

    When an IDENTIFIER whose value is 'public' appears but is not followed by
    COLON, _parse_meta_scope_prefix must restore the cursor and return None.
    """
    parser = _parser_from_tokens(
        [
            _tok(TokenType.IDENTIFIER, "public"),  # enters elif branch
            _tok(TokenType.IDENTIFIER, "mykey"),  # no colon
        ]
    )
    original_position = parser.current

    result = parser._parse_meta_scope_prefix()

    assert result is None
    assert parser.current == original_position


# ---------------------------------------------------------------------------
# Integration: real-source coverage for generic Pragma, IncludeOncePragma,
# DefineDirective, UndefDirective, ConditionalDirective via full parse
# ---------------------------------------------------------------------------


def test_generic_pragma_via_full_parse() -> None:
    """Integration: _parse_file_pragma fallthrough to generic Pragma node.

    A #custom_pragma directive at the file level must produce a Pragma node
    with the directive name preserved and an empty arguments list.
    """
    source = "#custom_pragma\nrule R { condition: true }"
    yara_file = Parser(source).parse()

    assert len(yara_file.pragmas) == 1
    assert isinstance(yara_file.pragmas[0], Pragma)
    assert yara_file.pragmas[0].name == "custom_pragma"
    assert yara_file.pragmas[0].pragma_type == PragmaType.from_string("custom_pragma")


def test_include_once_pragma_via_full_parse() -> None:
    """Integration: #include_once produces an IncludeOncePragma node."""
    source = "#include_once\nrule R { condition: true }"
    yara_file = Parser(source).parse()

    assert len(yara_file.pragmas) == 1
    assert isinstance(yara_file.pragmas[0], IncludeOncePragma)


def test_extern_import_with_rule_list_and_alias_via_full_parse() -> None:
    """Integration: ExternImport with alias parsed from real source."""
    source = 'import "common" (Foo, Bar) as clib\nrule R { condition: true }'
    yara_file = Parser(source).parse()

    assert len(yara_file.extern_imports) == 1
    ei = yara_file.extern_imports[0]
    assert isinstance(ei, ExternImport)
    assert ei.module_path == "common"
    assert sorted(ei.rules) == ["Bar", "Foo"]
    assert ei.alias == "clib"


def test_meta_with_protected_scope_via_full_parse() -> None:
    """Integration: meta entries with protected: scope prefix."""
    source = (
        'rule R {\n    meta:\n        protected: severity = "high"\n    condition:\n        true\n}'
    )
    yara_file = Parser(source).parse()

    meta = yara_file.rules[0].meta
    assert len(meta) == 1
    assert meta[0].key == "severity"
    assert meta[0].value == "high"
    assert str(meta[0].scope).lower() in {"protected", "metascope.protected"}


def test_meta_with_private_scope_via_full_parse() -> None:
    """Integration: meta entries with private: scope prefix."""
    source = (
        "rule R {\n"
        "    meta:\n"
        '        private: author = "researcher"\n'
        "    condition:\n"
        "        true\n"
        "}"
    )
    yara_file = Parser(source).parse()

    meta = yara_file.rules[0].meta
    assert len(meta) == 1
    assert meta[0].key == "author"
    assert meta[0].value == "researcher"
