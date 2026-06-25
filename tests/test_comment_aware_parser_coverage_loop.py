"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Coverage loop for yaraast/parser/comment_aware_parser.py.

Target module: yaraast.parser.comment_aware_parser
Baseline coverage: 82.38%
Missing lines exercised here:
  77-79   _parse() file-pragma branch (pragmas list / top_level_nodes)
  83-84   _parse() ExternImport branch (extern_imports + _register_extern_import)
  93-95   _parse() extern-namespace branch
  97-100  _parse() extern-rule branch
  168-169 _parse_rule() missing condition error
  194-195 _parse_rule_modifiers_with_comments() loop body (private/global)
  220-232 _parse_rule_tags_with_comments() error + loop
  254-258 _parse_rule_sections_with_comments() duplicate/unexpected meta
  262-263 _parse_rule_sections_with_comments() empty meta section
  268-272 _parse_rule_sections_with_comments() duplicate/unexpected strings
  276-277 _parse_rule_sections_with_comments() empty strings section
  280     _parse_rule_sections_with_comments() in-rule pragma branch
  284-285 _parse_rule_sections_with_comments() duplicate condition
  325     _condition_end_line() fallback (location is None)
  349-351 _ensure_condition() None branch with peek present
  362     _attach_rule_comments() trailing comment set
  393-394 _parse_strings_section() duplicated identifier error
  408-409 _parse_strings_section() empty plain-string error
  421-422 _parse_strings_section() empty hex-string error
  489-490 _parse_string_modifiers() invalid modifier for context error
  496-497 _parse_string_modifiers() missing RPAREN after modifier param
  504-505 _parse_string_modifiers() validate_string_modifiers ValueError
  524     _parse_string_modifier_parameter() xor single-value return
  537-538 _parse_hex_tokens() HexParseError re-raise
  544-545 _parse_regex_value() ValueError re-raise
  563-564 _parse_meta_section() meta key after scope error
  577-578 _parse_meta_section() non-integer after minus
  615->exit _attach_trailing_comments() guard when comment_tokens is empty
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import BooleanLiteral
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.comment_aware_parser import CommentAwareParser


# ---------------------------------------------------------------------------
# Helper: build a Token without going through the lexer
# ---------------------------------------------------------------------------
def _tok(tt: TokenType, value: str | int | float | None, line: int, col: int = 1) -> Token:
    return Token(type=tt, value=value, line=line, column=col)


# ---------------------------------------------------------------------------
# Lines 77-79: _parse() - file-pragma branch
# CommentAwareParser.parse() calls _check_file_pragma() before rule parsing.
# A STRING_COUNT token whose value starts with '#' is a file-pragma marker.
# ---------------------------------------------------------------------------
def test_parse_file_pragma_top_level_populates_pragmas_list() -> None:
    """File pragma (#include_once) found at top level by the comment-aware parse loop."""
    source = "#include_once\nrule r { condition: true }\n"
    ast = CommentAwareParser().parse(source)

    assert len(ast.pragmas) == 1
    assert ast.rules[0].name == "r"


def test_parse_define_pragma_top_level() -> None:
    """#define pragma is parsed and stored in YaraFile.pragmas."""
    source = "#define LIMIT 10\nrule r { condition: true }\n"
    ast = CommentAwareParser().parse(source)

    assert len(ast.pragmas) == 1
    # The pragma repr should include the directive name
    assert "LIMIT" in str(ast.pragmas[0])


# ---------------------------------------------------------------------------
# Lines 83-84: _parse() - ExternImport branch
# `import "file.yar" (Rule1)` produces an ExternImport, not an Import.
# ---------------------------------------------------------------------------
def test_parse_extern_import_top_level_branch() -> None:
    """
    An import statement with a selective rule list produces an ExternImport
    and is appended to ast.extern_imports (lines 83-84 in the parse() loop).
    """
    source = (
        'import "external.yar" (ExternRule)\n'
        "extern rule ExternRule\n"
        "rule uses_it { condition: ExternRule }\n"
    )
    ast = CommentAwareParser().parse(source)

    assert len(ast.extern_imports) == 1
    assert ast.extern_imports[0].module_path == "external.yar"
    assert "ExternRule" in ast.extern_imports[0].rules


# ---------------------------------------------------------------------------
# Lines 93-95: _parse() - extern-namespace branch
# ---------------------------------------------------------------------------
def test_parse_extern_namespace_top_level_branch() -> None:
    """
    A 'namespace' identifier at top level triggers the namespace parsing
    branch (lines 93-95) and appends to ast.namespaces.
    """
    source = (
        "namespace corp\nextern rule corp.DetectionRule\nrule r { condition: corp.DetectionRule }\n"
    )
    ast = CommentAwareParser().parse(source)

    assert len(ast.namespaces) == 1
    assert ast.namespaces[0].name == "corp"


# ---------------------------------------------------------------------------
# Lines 97-100: _parse() - extern-rule branch
# ---------------------------------------------------------------------------
def test_parse_extern_rule_top_level_branch() -> None:
    """
    An 'extern' keyword at top level triggers the extern-rule parsing branch
    (lines 97-100) and appends to ast.extern_rules.
    """
    source = "extern rule Signature\nrule r { condition: Signature }\n"
    ast = CommentAwareParser().parse(source)

    assert len(ast.extern_rules) == 1
    assert ast.extern_rules[0].name == "Signature"


def test_parse_extern_rule_with_modifier() -> None:
    """extern rule with private modifier is stored correctly."""
    source = "extern rule private Classified\nrule r { condition: Classified }\n"
    ast = CommentAwareParser().parse(source)

    assert len(ast.extern_rules) == 1
    rule = ast.extern_rules[0]
    assert rule.name == "Classified"
    assert len(rule.modifiers) == 1


# ---------------------------------------------------------------------------
# Lines 168-169: _parse_rule() - condition is None raises ParserError
# This fires when the rule body has no condition: section at all.
# ---------------------------------------------------------------------------
def test_parse_rule_without_condition_section_raises() -> None:
    """A rule body with only meta/strings and no condition: block raises ParserError."""
    source = 'rule no_condition { meta: author = "test" }'
    with pytest.raises(ParserError, match="Expected condition section"):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Lines 194-195: _parse_rule_modifiers_with_comments() - modifier loop body
# The loop appends when the token is PRIVATE or GLOBAL.
# ---------------------------------------------------------------------------
def test_parse_rule_modifiers_private_global_collected() -> None:
    """private and global modifiers are parsed and returned via the modifier loop body."""
    source = "private global rule PG { condition: true }\n"
    ast = CommentAwareParser().parse(source)

    rule = ast.rules[0]
    modifier_values = [str(m) for m in rule.modifiers]
    assert "private" in modifier_values
    assert "global" in modifier_values


def test_parse_private_rule_modifier() -> None:
    """private modifier alone is accepted and recorded."""
    source = "private rule OnlyPrivate { condition: false }\n"
    ast = CommentAwareParser().parse(source)

    modifier_values = [str(m) for m in ast.rules[0].modifiers]
    assert "private" in modifier_values


def test_parse_global_rule_modifier() -> None:
    """global modifier alone is accepted and recorded."""
    source = "global rule OnlyGlobal { condition: true }\n"
    ast = CommentAwareParser().parse(source)

    modifier_values = [str(m) for m in ast.rules[0].modifiers]
    assert "global" in modifier_values


# ---------------------------------------------------------------------------
# Lines 220-222: _parse_rule_tags_with_comments() - no tag after colon error
# ---------------------------------------------------------------------------
def test_parse_rule_tags_no_tag_after_colon_raises() -> None:
    """A colon after rule name with no following identifier raises ParserError."""
    p = CommentAwareParser()
    p.comment_tokens = []
    # Set up tokens: COLON then immediately LBRACE (no identifier)
    p.tokens = [
        _tok(TokenType.COLON, ":", 1),
        _tok(TokenType.LBRACE, "{", 1),
        _tok(TokenType.EOF, "", 1),
    ]
    p.current = 0
    with pytest.raises(ParserError, match="Expected tag name after ':'"):
        p._parse_rule_tags_with_comments()


# Lines 224-232: tag loop + duplicate tag detection
def test_parse_rule_tags_duplicate_raises() -> None:
    """Duplicate tag name in rule header raises ParserError."""
    source = "rule r : foo foo { condition: true }\n"
    with pytest.raises(ParserError, match='duplicated tag identifier "foo"'):
        CommentAwareParser().parse(source)


def test_parse_rule_tags_loop_collects_multiple() -> None:
    """Multiple distinct tags are parsed via the tag-loop body."""
    source = "rule r : alpha beta gamma { condition: true }\n"
    ast = CommentAwareParser().parse(source)

    tag_names = [tag.name for tag in ast.rules[0].tags]
    assert tag_names == ["alpha", "beta", "gamma"]


# ---------------------------------------------------------------------------
# Lines 253-258: _parse_rule_sections_with_comments() - duplicate / unexpected meta
# ---------------------------------------------------------------------------
def test_parse_rule_sections_duplicate_meta_raises() -> None:
    """Two meta: sections in the same rule raise 'Duplicate meta section'."""
    source = "rule r {\n" '  meta: a = "x"\n' '  meta: b = "y"\n' "  condition: true\n" "}\n"
    with pytest.raises(ParserError, match="Duplicate meta section"):
        CommentAwareParser().parse(source)


def test_parse_rule_sections_meta_after_strings_raises() -> None:
    """meta: section appearing after strings: raises 'Unexpected meta section'."""
    source = "rule r {\n" '  strings: $a = "x"\n' '  meta: b = "y"\n' "  condition: $a\n" "}\n"
    with pytest.raises(ParserError, match="Unexpected meta section"):
        CommentAwareParser().parse(source)


def test_parse_rule_sections_meta_after_condition_raises() -> None:
    """meta: after condition: raises 'Unexpected meta section'."""
    source = "rule r {\n" "  condition: true\n" '  meta: b = "y"\n' "}\n"
    with pytest.raises(ParserError, match="Unexpected meta section"):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Lines 262-263: empty meta section
# ---------------------------------------------------------------------------
def test_parse_rule_sections_empty_meta_raises() -> None:
    """meta: section with no entries raises 'Expected meta entry'."""
    source = "rule r {\n  meta:\n  condition: true\n}\n"
    with pytest.raises(ParserError, match="Expected meta entry"):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Lines 268-272: duplicate / unexpected strings section
# ---------------------------------------------------------------------------
def test_parse_rule_sections_duplicate_strings_raises() -> None:
    """Two strings: sections in the same rule raise 'Duplicate strings section'."""
    source = (
        "rule r {\n" '  strings: $a = "x"\n' '  strings: $b = "y"\n' "  condition: $a or $b\n" "}\n"
    )
    with pytest.raises(ParserError, match="Duplicate strings section"):
        CommentAwareParser().parse(source)


def test_parse_rule_sections_strings_after_condition_raises() -> None:
    """strings: section appearing after condition: raises 'Unexpected strings section'."""
    source = "rule r {\n" "  condition: true\n" '  strings: $a = "x"\n' "}\n"
    with pytest.raises(ParserError, match="Unexpected strings section"):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Lines 276-277: empty strings section
# ---------------------------------------------------------------------------
def test_parse_rule_sections_empty_strings_raises() -> None:
    """strings: section with no string definitions raises 'Expected string definition'."""
    source = "rule r {\n  strings:\n  condition: true\n}\n"
    with pytest.raises(ParserError, match="Expected string definition"):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Line 280: _parse_rule_sections_with_comments() - in-rule pragma branch
# A STRING_COUNT token inside the rule body triggers _parse_in_rule_pragma.
# ---------------------------------------------------------------------------
def test_parse_in_rule_pragma_branch() -> None:
    """
    An in-rule pragma (#define) appearing between rule sections
    is parsed via the in-rule pragma branch (line 280).
    """
    source = "rule r {\n" "  #define THRESHOLD 5\n" "  condition: true\n" "}\n"
    ast = CommentAwareParser().parse(source)

    rule = ast.rules[0]
    assert rule.name == "r"
    assert len(rule.pragmas) == 1


# ---------------------------------------------------------------------------
# Lines 284-285: duplicate condition section
# ---------------------------------------------------------------------------
def test_parse_rule_sections_duplicate_condition_raises() -> None:
    """Two condition: sections in the same rule raise 'Duplicate condition section'."""
    source = "rule r {\n" "  condition: true\n" "  condition: false\n" "}\n"
    with pytest.raises(ParserError, match="Duplicate condition section"):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Line 325: _condition_end_line() - fallback when location is None
# ---------------------------------------------------------------------------
def test_condition_end_line_fallback_when_no_location() -> None:
    """
    _condition_end_line returns the fallback line number when the condition
    expression has no location attribute.
    """
    # BooleanLiteral with no location set
    expr = BooleanLiteral(value=True)
    # Explicitly ensure location is absent so getattr returns None
    if hasattr(expr, "location"):
        expr.location = None

    result = CommentAwareParser._condition_end_line(expr, 42)
    assert result == 42


def test_condition_end_line_returns_location_end_line_when_present() -> None:
    """
    When the condition expression has a location with end_line set,
    _condition_end_line returns that end_line, not the fallback.
    """
    from yaraast.ast.base import Location

    expr = BooleanLiteral(value=True)
    expr.location = Location(line=5, column=1, end_line=7, end_column=10)

    result = CommentAwareParser._condition_end_line(expr, 99)
    assert result == 7


# ---------------------------------------------------------------------------
# Lines 349-351: _ensure_condition() - None branch with available peek token
# ---------------------------------------------------------------------------
def test_ensure_condition_none_with_peek_creates_boolean_literal() -> None:
    """
    When called with None, _ensure_condition creates a BooleanLiteral(True)
    and sets its location from the current peek token (lines 349-351).
    """
    p = CommentAwareParser()
    p.comment_tokens = []
    p.tokens = [_tok(TokenType.RBRACE, "}", 5), _tok(TokenType.EOF, "", 5)]
    p.current = 0

    result = p._ensure_condition(None)

    assert isinstance(result, BooleanLiteral)
    assert result.value is True
    # The location should have been set from the peeked RBRACE token (line 5)
    assert result.location is not None
    assert result.location.line == 5


# ---------------------------------------------------------------------------
# Line 362: _attach_rule_comments() - trailing comment set on rule
# This fires when there is a comment on the same line as the rule keyword.
# ---------------------------------------------------------------------------
def test_attach_rule_comments_trailing_comment_set_directly() -> None:
    """
    _attach_rule_comments sets rule.trailing_comment (line 362) when
    comment_tokens contains a comment matching start_token.line.

    In a full parse, such a comment is consumed earlier by condition parsing.
    This test calls the method directly with an isolated token stream to
    exercise the assignment at line 362 independently.
    """
    from yaraast.ast.expressions import BooleanLiteral
    from yaraast.ast.rules import Rule

    p = CommentAwareParser()
    p.comment_tokens = [_tok(TokenType.COMMENT, "// inline with rule", 3)]
    p.tokens = [_tok(TokenType.EOF, "", 3)]
    p.current = 0

    cond = BooleanLiteral(value=True)
    rule = Rule(name="r", modifiers=[], tags=[], meta=[], strings=[], condition=cond)
    start_token = _tok(TokenType.RULE, "rule", 3)

    p._attach_rule_comments(rule, [], start_token)

    assert rule.trailing_comment is not None
    assert "inline with rule" in rule.trailing_comment.text


# ---------------------------------------------------------------------------
# Lines 393-394: _parse_strings_section() - duplicated string identifier
# ---------------------------------------------------------------------------
def test_parse_strings_section_duplicate_named_identifier_raises() -> None:
    """
    Two string definitions sharing the same non-anonymous identifier raise
    'duplicated string identifier' (lines 393-394).
    """
    source = (
        "rule r {\n"
        "  strings:\n"
        '    $dup = "first"\n'
        '    $dup = "second"\n'
        "  condition: $dup\n"
        "}\n"
    )
    with pytest.raises(ParserError, match='duplicated string identifier "\\$dup"'):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Lines 408-409: _parse_strings_section() - empty plain-string value
# ---------------------------------------------------------------------------
def test_parse_strings_section_empty_plain_string_raises() -> None:
    """
    An empty quoted string value raises 'empty string' (lines 408-409).
    """
    source = 'rule r { strings: $a = "" condition: $a }\n'
    with pytest.raises(ParserError, match='empty string "\\$a"'):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# _parse_hex_tokens() - HexParseError re-raised as ParserError.
# ---------------------------------------------------------------------------
def test_parse_hex_tokens_parse_error_reraised_as_parser_error() -> None:
    """
    HexParseError raised inside _parse_hex_tokens is re-raised as ParserError
    (lines 537-538). An empty '{}' hex literal triggers HexParseError.
    """
    source = "rule r { strings: $h = {} condition: $h }\n"
    with pytest.raises(ParserError, match="Empty hex string"):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Lines 489-490: _parse_string_modifiers() - invalid modifier for context
# nocase is valid for plain strings but invalid for hex strings.
# ---------------------------------------------------------------------------
def test_parse_string_modifiers_invalid_for_hex_context_raises() -> None:
    """
    Applying nocase to a hex string raises the 'not valid on hex strings'
    error (lines 489-490).
    """
    source = "rule r { strings: $h = { AA BB } nocase condition: $h }\n"
    with pytest.raises(ParserError, match="not valid on hex strings"):
        CommentAwareParser().parse(source)


def test_parse_string_modifiers_invalid_for_regex_context_raises() -> None:
    """
    Applying base64 to a regex string raises the 'not valid on regex strings'
    error (lines 489-490).
    """
    source = "rule r { strings: $r = /abc/ base64 condition: $r }\n"
    with pytest.raises(ParserError, match="not valid on regex strings"):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Lines 496-497: _parse_string_modifiers() - missing RPAREN after modifier
# base64("abc" without closing paren triggers the missing RPAREN error.
# ---------------------------------------------------------------------------
def test_parse_string_modifiers_missing_rparen_after_param_raises() -> None:
    """
    A parameterised modifier (base64wide) whose closing ')' is absent raises
    'Expected ')' after base64wide parameter' (lines 496-497).
    The full token stream must include the modifier token itself so the loop
    recognises it, then LPAREN to enter the parameter branch, then the STRING
    argument, then a non-RPAREN token to trigger the error.
    """
    p = CommentAwareParser()
    p.comment_tokens = []
    p.tokens = [
        _tok(TokenType.BASE64WIDE, "base64wide", 1),
        _tok(TokenType.LPAREN, "(", 1),
        _tok(TokenType.STRING, "ABC", 1),
        # NOCASE instead of RPAREN triggers the missing-RPAREN branch
        _tok(TokenType.NOCASE, "nocase", 1),
        _tok(TokenType.EOF, "", 1),
    ]
    p.current = 0
    with pytest.raises(ParserError, match="Expected '\\)' after base64wide parameter"):
        p._parse_string_modifiers()


# ---------------------------------------------------------------------------
# Lines 504-505: _parse_string_modifiers() - validate_string_modifiers error
# ascii + wide + fullword is the combination that triggers the validator.
# Actually, 'nocase' with 'xor' raises from validate_string_modifiers.
# ---------------------------------------------------------------------------
def test_parse_string_modifiers_incompatible_combination_raises() -> None:
    """
    The combination 'nocase xor' is semantically invalid; validate_string_modifiers
    raises ValueError which is re-raised as ParserError (lines 504-505).
    """
    source = 'rule r { strings: $a = "abc" nocase xor condition: $a }\n'
    with pytest.raises(ParserError):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Line 524: _parse_string_modifier_parameter() - xor with single value (no range)
# xor(5) should parse and return the single integer, not a tuple.
# ---------------------------------------------------------------------------
def test_parse_string_modifier_parameter_xor_single_value_returned() -> None:
    """
    xor(N) with a single integer returns just that integer, not a tuple
    (line 524: return min_val when no MINUS token follows).
    """
    source = 'rule r { strings: $a = "abc" xor(5) condition: $a }\n'
    ast = CommentAwareParser().parse(source)

    modifiers = ast.rules[0].strings[0].modifiers
    xor_mod = next(m for m in modifiers if m.name == "xor")
    # Single-value xor stores an integer, not a tuple
    assert xor_mod.value == 5


# ---------------------------------------------------------------------------
# Lines 537-538: _parse_hex_tokens() - HexParseError re-raised as ParserError
# ---------------------------------------------------------------------------
def test_parse_hex_tokens_invalid_hex_raises_parser_error() -> None:
    """
    An invalid hex string content causes HexParseError inside _parse_hex_tokens
    which is caught and re-raised as ParserError (lines 537-538).
    """
    # 'ZZ' is not valid hex
    source = "rule r { strings: $h = { ZZ } condition: $h }\n"
    with pytest.raises(ParserError):
        CommentAwareParser().parse(source)


# ---------------------------------------------------------------------------
# Lines 544-545: _parse_regex_value() - ValueError re-raised as ParserError
#
# parse_regex_value raises ValueError when the regex value string contains an
# invalid modifier character after the \x00 separator. The CommentPreservingLexer
# encodes inline regex flags (e.g. /abc/si) as 'abc\x00si' in the REGEX token
# value. An unrecognised flag character 'z' causes validate_regex_modifiers to
# raise ValueError, which _parse_regex_value wraps as ParserError.
#
# The lexer itself silently skips unknown flags, so this path is only reachable
# by calling _parse_regex_value directly with a crafted invalid value.
# ---------------------------------------------------------------------------
def test_parse_regex_value_invalid_modifier_raises_parser_error() -> None:
    """
    _parse_regex_value wraps ValueError from parse_regex_value as ParserError
    (lines 544-545). The invalid modifier 'z' after the null-byte separator
    triggers validate_regex_modifiers to raise ValueError.
    """
    p = CommentAwareParser()
    p.comment_tokens = []
    p.tokens = [_tok(TokenType.EOF, "", 1)]
    p.current = 0

    # 'abc\x00z' is the internal encoding for /abc/z — 'z' is not a valid modifier
    with pytest.raises(ParserError, match="Invalid regex modifier: z"):
        p._parse_regex_value("abc\x00z")


# ---------------------------------------------------------------------------
# Lines 563-564: _parse_meta_section() - meta key required after scope prefix
# When a scoped meta entry (private:) has no identifier following the colon.
# ---------------------------------------------------------------------------
def test_parse_meta_section_missing_key_after_scope_raises() -> None:
    """
    A scoped meta prefix with no identifier after the colon raises
    'Expected meta key after scope' (lines 563-564).
    """
    # 'private:' followed immediately by something that is not an identifier
    # triggers the "Expected meta key after scope" path.
    # We drive this via the low-level method to control token stream precisely.
    p = CommentAwareParser()
    p.comment_tokens = []
    # PRIVATE token, then COLON (scope consumed), then something that is not
    # in _CONTEXTUAL_IDENTIFIER_TOKENS and is not PRIVATE.
    p.tokens = [
        _tok(TokenType.PRIVATE, "private", 1),
        _tok(TokenType.COLON, ":", 1),
        # Not an identifier — triggers the error
        _tok(TokenType.RBRACE, "}", 1),
        _tok(TokenType.EOF, "", 1),
    ]
    p.current = 0
    with pytest.raises(ParserError, match="Expected meta key after scope"):
        p._parse_meta_section()


# ---------------------------------------------------------------------------
# Lines 577-578: _parse_meta_section() - non-integer after minus in meta value
# ---------------------------------------------------------------------------
def test_parse_meta_section_minus_without_integer_raises() -> None:
    """
    A minus sign in a meta value not followed by an integer raises
    'Expected integer after '-' in meta value' (lines 577-578).
    """
    p = CommentAwareParser()
    p.comment_tokens = []
    p.tokens = [
        _tok(TokenType.IDENTIFIER, "score", 1),
        _tok(TokenType.ASSIGN, "=", 1),
        _tok(TokenType.MINUS, "-", 1),
        # Not an INTEGER — something else
        _tok(TokenType.IDENTIFIER, "bad", 1),
        _tok(TokenType.EOF, "", 1),
    ]
    p.current = 0
    with pytest.raises(ParserError, match="Expected integer after '-' in meta value"):
        p._parse_meta_section()


# ---------------------------------------------------------------------------
# Lines 615->exit: _attach_trailing_comments() - guard when empty list
# The method has an 'if self.comment_tokens:' guard; calling it with an
# empty list must not raise or mutate the node.
# ---------------------------------------------------------------------------
def test_attach_trailing_comments_no_op_when_empty() -> None:
    """
    Calling _attach_trailing_comments with an empty comment_tokens list
    leaves the node unchanged (branch 615->exit: the guard exits early).
    """
    p = CommentAwareParser()
    p.comment_tokens = []

    ast = p.parse("rule r { condition: true }\n")
    # Confirm no trailing comment is present
    original_trailing = getattr(ast, "trailing_comment", None)

    # Verify the node is not mutated when there are no comment tokens
    p.comment_tokens = []
    p._attach_trailing_comments(ast)
    assert getattr(ast, "trailing_comment", None) == original_trailing


# ---------------------------------------------------------------------------
# Integration: multiple missing-line paths in a single realistic parse
# This exercises file pragmas + extern imports + extern rules + comments
# in a combined real-world source text to confirm the paths interact cleanly.
# ---------------------------------------------------------------------------
def test_integration_pragmas_externs_and_comments_combined() -> None:
    """
    A realistic YARA source combining file pragmas, an extern import, an extern
    rule, and embedded comments exercises all corresponding parse() branches
    together with comment preservation logic.
    """
    source = (
        "// file-level comment\n"
        "#include_once\n"
        'import "sigs.yar" (KnownBad)\n'
        "extern rule KnownBad\n"
        "// rule-level comment\n"
        "private rule Detector {\n"
        "  meta:\n"
        '    description = "Detects known bad patterns"\n'
        "  strings:\n"
        '    $pattern = "malicious" nocase\n'
        "  condition: // condition comment\n"
        "    KnownBad or $pattern\n"
        "}\n"
        "// trailing file comment\n"
    )
    ast = CommentAwareParser().parse(source)

    assert len(ast.pragmas) == 1
    assert len(ast.extern_imports) == 1
    assert len(ast.extern_rules) == 1
    assert len(ast.rules) == 1
    assert ast.rules[0].name == "Detector"
    modifier_values = [str(m) for m in ast.rules[0].modifiers]
    assert "private" in modifier_values
    assert ast.trailing_comment is not None
