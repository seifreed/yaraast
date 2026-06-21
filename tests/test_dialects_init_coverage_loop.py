# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for yaraast/dialects/__init__.py targeting uncovered lines.

Each test exercises a real code path in the dialect module: the
``_is_regex_literal_start`` scanner, ``_strip_string_literals`` (line
comments, block comments, string literals, and regex literals), the
``DialectSpec`` validation guard-clauses, and the ``DialectRegistry``
API (register type-guard, get_parser_factory TypeError and None paths,
clear, and detect with content that strips to whitespace).
``detect_dialect`` TypeError guard is also covered.

No mocks are used.  All tests run against the production implementations
directly.
"""

from __future__ import annotations

import re

import pytest

from yaraast.dialects import (
    DialectRegistry,
    DialectSpec,
    YaraDialect,
    _is_regex_literal_start,
    _strip_string_literals,
    detect_dialect,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_minimal_spec(
    dialect: YaraDialect = YaraDialect.YARA,
    pattern: str = r"\btest_unique_sentinel_99\b",
    priority: int = 0,
) -> DialectSpec:
    """Return a valid DialectSpec that will never match production inputs."""
    return DialectSpec(
        dialect=dialect,
        parser_factory=lambda text: None,
        detection_patterns=[(pattern, re.IGNORECASE)],
        priority=priority,
    )


# ---------------------------------------------------------------------------
# _is_regex_literal_start — lines 38-54
# ---------------------------------------------------------------------------


class TestIsRegexLiteralStart:
    """Exercise the regex-literal context detector."""

    def test_slash_after_equals_is_regex_start(self) -> None:
        content = "condition: = /abc/"
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is True

    def test_slash_after_open_paren_is_regex_start(self) -> None:
        content = "matches (/pat/"
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is True

    def test_slash_after_keyword_is_regex_start(self) -> None:
        # "matches" precedes the slash — _REGEX_CONTEXT_KEYWORDS includes "matches"
        content = "condition: matches /x/"
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is True

    def test_slash_after_keyword_and_is_regex_start(self) -> None:
        content = "and /pattern/"
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is True

    def test_slash_followed_by_star_is_not_regex(self) -> None:
        # "/*" is the start of a block comment, not a regex
        content = "/* comment */"
        assert _is_regex_literal_start(content, 0) is False

    def test_slash_followed_by_slash_is_not_regex(self) -> None:
        # "//" is a line comment
        content = "// line comment"
        assert _is_regex_literal_start(content, 0) is False

    def test_slash_at_position_zero_with_no_comment_is_regex(self) -> None:
        # A standalone "/" at index 0 with no preceding chars is treated as regex start
        content = "/abc/"
        assert _is_regex_literal_start(content, 0) is True

    def test_slash_after_non_keyword_word_is_not_regex(self) -> None:
        # "filesize" is not in _REGEX_CONTEXT_KEYWORDS
        content = "filesize /pattern/"
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is False

    def test_slash_after_digit_is_not_regex(self) -> None:
        # digit before slash → not a regex context keyword
        content = "5 /x/"
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is False

    def test_slash_after_colon_is_regex_start(self) -> None:
        # ":" is in the set "=(:,[!~"
        content = "condition: /x/"
        # The second slash after "condition:" space
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is True

    def test_non_slash_character_returns_false(self) -> None:
        content = "abc"
        assert _is_regex_literal_start(content, 0) is False

    def test_slash_preceded_by_closing_brace_is_not_regex(self) -> None:
        # "}" is not alphanumeric, not "_", and not in "=(:,[!~"
        # → falls through to line 54 ``return False``
        content = "} /x/"
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is False

    def test_slash_preceded_by_semicolon_is_not_regex(self) -> None:
        # ";" follows the same path as "}" — triggers the final return False (line 54)
        content = "; /x/"
        idx = content.index("/")
        assert _is_regex_literal_start(content, idx) is False


# ---------------------------------------------------------------------------
# _strip_string_literals — line comment paths (lines 72-83)
# ---------------------------------------------------------------------------


class TestStripStringLiteralsLineComments:
    """Verify that line comments are blanked out while newlines are preserved."""

    def test_line_comment_content_is_blanked(self) -> None:
        content = "rule x { // this is a comment\ncondition: true }"
        stripped = _strip_string_literals(content)
        # The comment text is replaced with spaces; newline is kept
        assert "this is a comment" not in stripped
        # The newline that terminates the comment must still be present
        assert "\n" in stripped

    def test_line_comment_does_not_suppress_code_after_newline(self) -> None:
        content = "// comment\ncondition: true"
        stripped = _strip_string_literals(content)
        # Code after the newline must survive
        assert "condition" in stripped

    def test_multiple_line_comments(self) -> None:
        content = "// first\n// second\nrule x {}"
        stripped = _strip_string_literals(content)
        assert "first" not in stripped
        assert "second" not in stripped
        assert "rule" in stripped


# ---------------------------------------------------------------------------
# _strip_string_literals — block comment paths (lines 87-100)
# ---------------------------------------------------------------------------


class TestStripStringLiteralsBlockComments:
    """Verify that block comments are blanked out while newlines are preserved."""

    def test_block_comment_content_is_blanked(self) -> None:
        content = "/* secret content */rule x {}"
        stripped = _strip_string_literals(content)
        assert "secret content" not in stripped
        assert "rule" in stripped

    def test_block_comment_preserves_embedded_newlines(self) -> None:
        content = "/* line one\nline two */rule x {}"
        stripped = _strip_string_literals(content)
        # Newlines inside the block comment must be kept (they affect line counting)
        assert stripped.count("\n") >= 1
        assert "line one" not in stripped

    def test_block_comment_spanning_multiple_lines(self) -> None:
        content = "a\n/* start\nmiddle\nend */\nb"
        stripped = _strip_string_literals(content)
        assert "start" not in stripped
        assert "middle" not in stripped
        assert "end" not in stripped
        assert stripped.count("\n") == 4


# ---------------------------------------------------------------------------
# _strip_string_literals — string literal paths (lines 108, 111-114)
# ---------------------------------------------------------------------------


class TestStripStringLiteralsStringLiterals:
    """Verify escape-sequence handling and unterminated-string edge case."""

    def test_escaped_quote_inside_string_is_skipped(self) -> None:
        # The \" inside should not prematurely terminate string scanning (line 108)
        content = r'"hello\"world"'
        stripped = _strip_string_literals(content)
        # Content between quotes is replaced; the outer quotes remain
        assert stripped.startswith('"')
        assert stripped.endswith('"')
        # The inner text is gone
        assert "hello" not in stripped

    def test_unterminated_string_does_not_crash(self) -> None:
        # If the closing quote is missing, scanning stops at end-of-content (line 111 branch)
        content = '"unterminated string'
        stripped = _strip_string_literals(content)
        # Must not raise; result is a string
        assert isinstance(stripped, str)

    def test_regular_string_content_is_blanked(self) -> None:
        content = '"detector_pattern" rule x {}'
        stripped = _strip_string_literals(content)
        assert "detector_pattern" not in stripped
        assert "rule" in stripped


# ---------------------------------------------------------------------------
# _strip_string_literals — regex literal paths (lines 117-135)
# ---------------------------------------------------------------------------


class TestStripStringLiteralsRegexLiterals:
    """Verify regex literals are replaced to avoid false-positive dialect detection."""

    def test_regex_literal_content_is_blanked(self) -> None:
        content = "condition: /YARA-X-keyword/"
        stripped = _strip_string_literals(content)
        assert "YARA-X-keyword" not in stripped

    def test_regex_literal_with_flags_is_fully_consumed(self) -> None:
        content = "condition: /pattern/i"
        stripped = _strip_string_literals(content)
        # The flag character "i" after the closing slash must also be blanked
        # (it should not appear as a stray character after the slash).
        assert "pattern" not in stripped

    def test_regex_literal_with_escaped_slash_is_consumed(self) -> None:
        # A backslash-escaped forward slash inside a regex must not close the literal
        # prematurely.  The content between opening and real closing slash is blanked.
        content = r"condition: /pa\/ttern/"
        stripped = _strip_string_literals(content)
        assert "ttern" not in stripped

    def test_regex_literal_newline_is_preserved_during_scan(self) -> None:
        # Newlines inside an unterminated regex must be kept (line 122 branch)
        content = "condition: /abc\ndef"
        stripped = _strip_string_literals(content)
        assert "\n" in stripped

    def test_regex_literal_with_ms_flags(self) -> None:
        content = "condition: /pattern/ms"
        stripped = _strip_string_literals(content)
        assert "pattern" not in stripped


# ---------------------------------------------------------------------------
# DialectSpec.validate_structure — error guard branches (lines 218-247)
# ---------------------------------------------------------------------------


class TestDialectSpecValidation:
    """Confirm every guard-clause in validate_structure raises correctly."""

    def test_non_dialect_enum_raises_type_error(self) -> None:
        # Lines 218-219
        with pytest.raises(TypeError, match="DialectSpec dialect must be a YaraDialect"):
            DialectSpec(
                dialect="YARA",  # type: ignore[arg-type]
                parser_factory=lambda t: None,
                detection_patterns=[(r"\bx\b", re.IGNORECASE)],
            )

    def test_non_callable_parser_factory_raises_type_error(self) -> None:
        # Lines 221-222
        with pytest.raises(TypeError, match="parser_factory must be callable"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory="not_callable",  # type: ignore[arg-type]
                detection_patterns=[(r"\bx\b", re.IGNORECASE)],
            )

    def test_non_list_detection_patterns_raises_type_error(self) -> None:
        # Lines 224-225
        with pytest.raises(TypeError, match="detection_patterns must be a list"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=(r"\bx\b", re.IGNORECASE),  # type: ignore[arg-type]
            )

    def test_non_tuple_pattern_entry_raises_type_error(self) -> None:
        # Lines 228-229: pattern_entry that is not a 2-tuple
        with pytest.raises(TypeError, match="must contain pattern/flags pairs"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=[r"\bx\b"],  # type: ignore[list-item]
            )

    def test_three_element_tuple_pattern_entry_raises_type_error(self) -> None:
        # len(pattern_entry) != 2
        with pytest.raises(TypeError, match="must contain pattern/flags pairs"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=[(r"\bx\b", re.IGNORECASE, "extra")],  # type: ignore[list-item]
            )

    def test_non_string_pattern_raises_type_error(self) -> None:
        # Lines 232-233
        with pytest.raises(TypeError, match="detection pattern must be a string"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=[(123, re.IGNORECASE)],  # type: ignore[list-item]
            )

    def test_empty_pattern_raises_value_error(self) -> None:
        # Lines 235-236
        with pytest.raises(ValueError, match="must not be empty"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=[("", re.IGNORECASE)],
            )

    def test_non_regex_flag_raises_type_error(self) -> None:
        # Lines 238-239
        with pytest.raises(TypeError, match=r"flags must be re\.RegexFlag"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=[(r"\bx\b", 0)],  # type: ignore[list-item]
            )

    def test_invalid_regex_pattern_raises_value_error(self) -> None:
        # Lines 242-244: re.compile raises re.error
        with pytest.raises(ValueError, match="must be valid regex"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=[(r"[invalid", re.IGNORECASE)],
            )

    def test_bool_priority_raises_type_error(self) -> None:
        # Lines 246-247: bool is a subclass of int but must be rejected
        with pytest.raises(TypeError, match="priority must be an integer"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=[(r"\bx\b", re.IGNORECASE)],
                priority=True,
            )

    def test_float_priority_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="priority must be an integer"):
            DialectSpec(
                dialect=YaraDialect.YARA,
                parser_factory=lambda t: None,
                detection_patterns=[(r"\bx\b", re.IGNORECASE)],
                priority=1.5,  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# DialectRegistry.register — type guard (lines 259-260)
# ---------------------------------------------------------------------------


class TestDialectRegistryRegister:
    """Confirm register rejects non-DialectSpec arguments."""

    def test_register_non_spec_raises_type_error(self) -> None:
        # Lines 259-260
        with pytest.raises(TypeError, match="Dialect spec must be a DialectSpec"):
            DialectRegistry.register("not_a_spec")  # type: ignore[arg-type]

    def test_register_none_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="Dialect spec must be a DialectSpec"):
            DialectRegistry.register(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# DialectRegistry.get_parser_factory — TypeError and None paths (lines 280-281, 287, 291-292)
# ---------------------------------------------------------------------------


class TestDialectRegistryGetParserFactory:
    """Cover the TypeError guard and the None-return path of get_parser_factory."""

    def test_non_dialect_argument_raises_type_error(self) -> None:
        # Lines 280-281
        with pytest.raises(TypeError, match="Parser factory dialect must be a YaraDialect"):
            DialectRegistry.get_parser_factory("YARA")  # type: ignore[arg-type]

    def test_unregistered_dialect_returns_none(self) -> None:
        """After clearing the registry the YARA dialect has no factory — returns None.

        This covers line 287 (return None) and exercises the loop in
        get_parser_factory exhausting without a match.  The test restores the
        registry via _register_builtins to leave the module in a valid state.
        """
        from yaraast.dialects import _register_builtins

        DialectRegistry.clear()
        try:
            result = DialectRegistry.get_parser_factory(YaraDialect.YARA)
            assert result is None
        finally:
            _register_builtins()

    def test_registered_dialect_returns_callable(self) -> None:
        """Positive path: a registered dialect returns its factory callable."""
        factory = DialectRegistry.get_parser_factory(YaraDialect.YARA_L)
        assert callable(factory)

    def test_second_in_priority_order_dialect_triggers_loop_skip(self) -> None:
        """Requesting YARA_X forces the loop to skip the higher-priority YARA_L spec.

        The registry is sorted by descending priority, so YARA_L (priority 10)
        appears before YARA_X (priority 5).  When we ask for YARA_X the
        ``if spec.dialect == dialect`` check at line 285 is False for the YARA_L
        spec, exercising the branch that continues the loop (285->284).
        """
        factory = DialectRegistry.get_parser_factory(YaraDialect.YARA_X)
        assert callable(factory)


# ---------------------------------------------------------------------------
# DialectRegistry.clear — lines 291-292
# ---------------------------------------------------------------------------


class TestDialectRegistryClear:
    """Verify clear removes all specs and that the registry can be restored."""

    def test_clear_empties_registry_and_detect_falls_back_to_yara(self) -> None:
        from yaraast.dialects import _register_builtins

        DialectRegistry.clear()
        try:
            # With no specs registered, every content must return the YARA default
            yaral_content = (
                "rule yl {\n"
                "  events:\n"
                '    $e.metadata.event_type = "NETWORK_CONNECTION"\n'
                "  condition:\n"
                "    $e\n"
                "}"
            )
            result = DialectRegistry.detect(yaral_content)
            assert result is YaraDialect.YARA
        finally:
            _register_builtins()

    def test_clear_then_register_works(self) -> None:
        from yaraast.dialects import _register_builtins

        DialectRegistry.clear()
        try:
            spec = _make_minimal_spec()
            DialectRegistry.register(spec)
            # The spec's pattern will not match ordinary YARA content; YARA default returned
            result = DialectRegistry.detect("rule x { condition: true }")
            assert result is YaraDialect.YARA
        finally:
            DialectRegistry.clear()
            _register_builtins()


# ---------------------------------------------------------------------------
# detect_dialect — TypeError guard (lines 334-335)
# ---------------------------------------------------------------------------


class TestDetectDialect:
    """Cover the public detect_dialect type guard."""

    def test_non_string_input_raises_type_error(self) -> None:
        # Lines 334-335
        with pytest.raises(TypeError, match="dialect content must be a string"):
            detect_dialect(123)  # type: ignore[arg-type]

    def test_none_input_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="dialect content must be a string"):
            detect_dialect(None)  # type: ignore[arg-type]

    def test_classic_yara_returns_yara_dialect(self) -> None:
        result = detect_dialect('rule x { strings: $a = "hello" condition: $a }')
        assert result is YaraDialect.YARA

    def test_yaral_content_returns_yaral_dialect(self) -> None:
        content = (
            "rule yl {\n"
            "  events:\n"
            '    $e.metadata.event_type = "NETWORK_CONNECTION"\n'
            "  condition:\n"
            "    $e\n"
            "}"
        )
        result = detect_dialect(content)
        assert result is YaraDialect.YARA_L

    def test_empty_string_returns_yara_dialect(self) -> None:
        # Empty content matches no pattern → falls back to YARA default
        result = detect_dialect("")
        assert result is YaraDialect.YARA

    def test_dialect_keywords_inside_string_literals_do_not_trigger_yaral(self) -> None:
        # "events:" keyword is inside a string; after stripping it must not fire YARA-L
        content = 'rule x { strings: $a = "events: test" condition: $a }'
        result = detect_dialect(content)
        assert result is YaraDialect.YARA

    def test_yaral_keyword_inside_line_comment_does_not_trigger_yaral(self) -> None:
        # The "events:" marker appears only in a comment — must not fire YARA-L
        content = "// events:\nrule x { condition: true }"
        result = detect_dialect(content)
        assert result is YaraDialect.YARA

    def test_yaral_keyword_inside_block_comment_does_not_trigger_yaral(self) -> None:
        content = "/* events: */\nrule x { condition: true }"
        result = detect_dialect(content)
        assert result is YaraDialect.YARA
