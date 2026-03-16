"""Additional real tests for lexer helpers and include resolution."""

from __future__ import annotations

import os
from pathlib import Path

from yaraast.lexer.error_tolerant_lexer import ErrorTolerantLexer, LexerErrorInfo
from yaraast.lexer.string_escape import StringEscapeHandler
from yaraast.lexer.tokens import TokenType
from yaraast.resolution.include_resolver import IncludeResolver


def test_string_escape_handler_covers_remaining_paths() -> None:
    unknown = StringEscapeHandler(r"\q", 1).handle_backslash("q")
    assert unknown.chars == ["\\", "q"]

    short_hex = StringEscapeHandler(r"\x4", 1).handle_backslash("x")
    assert short_hex.chars == ["\\", "x"]

    eof_after_quote = StringEscapeHandler(r"\"", 1).handle_backslash('"')
    assert eof_after_quote.ends_string is True

    whitespace_only = StringEscapeHandler('\\"   ', 1).handle_backslash('"')
    assert whitespace_only.ends_string is True

    newline_after = StringEscapeHandler('\\"\n', 1).handle_backslash('"')
    assert newline_after.ends_string is True

    comment_after = StringEscapeHandler('\\" // comment', 1).handle_backslash('"')
    assert comment_after.ends_string is True

    base64wide = StringEscapeHandler('\\" base64wide', 1).handle_backslash('"')
    assert base64wide.ends_string is True


def test_error_info_format_without_context_includes_suggestion() -> None:
    error = LexerErrorInfo(
        message="Only suggestion path",
        line=1,
        column=1,
        context="",
        suggestion="Fix it",
        severity="warning",
    )

    formatted = error.format_error()
    assert "Fix it" in formatted
    assert "Context:" not in formatted


def test_error_tolerant_lexer_max_errors_and_recovery_helpers() -> None:
    lexer = ErrorTolerantLexer("@", max_errors=0)
    tokens, errors = lexer.tokenize()
    assert tokens[-1].type == TokenType.EOF
    assert any("Too many errors" in error.message for error in errors)

    invalid = ErrorTolerantLexer("€")
    tokens, errors = invalid.tokenize()
    assert tokens[-1].type == TokenType.EOF
    assert errors

    quoted = ErrorTolerantLexer('"abc')
    quoted.position = 0
    quoted._recover_from_error()
    assert quoted.position == 1

    slash = ErrorTolerantLexer("/bad token")
    slash.position = 0
    slash._recover_from_error()
    assert slash._current_char().isspace()

    hex_lexer = ErrorTolerantLexer("{AB")
    hex_lexer.position = 0
    hex_lexer._recover_from_error()
    assert hex_lexer.position == len("{AB")

    default = ErrorTolerantLexer("!rest")
    default.position = 0
    default._recover_from_error()
    assert default.position == 1

    unterminated = ErrorTolerantLexer("abc")
    unterminated.position = 0
    unterminated._recover_from_unterminated_string()
    assert unterminated.position == len("abc")


def test_error_tolerant_read_string_end_of_file_escape_variants() -> None:
    trailing_escaped_quote = ErrorTolerantLexer('"abc\\"')
    trailing_escaped_quote.position = 0
    token = trailing_escaped_quote._read_string()
    assert token.type == TokenType.STRING
    assert token.value.endswith("\\")
    assert trailing_escaped_quote.errors

    trailing_backslash = ErrorTolerantLexer('"abc\\')
    trailing_backslash.position = 0
    token = trailing_backslash._read_string()
    assert token.type == TokenType.STRING
    assert token.value.endswith("\\")
    assert any("Unterminated string" in error.message for error in trailing_backslash.errors)


def test_include_resolver_env_tree_and_cache_helpers(tmp_path: Path) -> None:
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    env_file = env_dir / "envlib.yar"
    env_file.write_text("rule envlib { condition: true }")

    main = tmp_path / "main.yar"
    main.write_text('include "envlib.yar"\nrule main { condition: true }')

    previous = os.environ.get("YARA_INCLUDE_PATH")
    os.environ["YARA_INCLUDE_PATH"] = os.pathsep.join([str(env_dir), str(env_dir)])
    try:
        resolver = IncludeResolver([str(tmp_path), str(tmp_path)])
        # deduped explicit paths + current cwd + env path duplicate collapse
        assert len(resolver.search_paths) == len(set(resolver.search_paths))

        resolved = resolver.resolve_file(str(main))
        assert resolved.includes[0].path == env_file.resolve()

        include_tree = resolver.get_include_tree(str(main))
        assert include_tree["path"].endswith("main.yar")
        assert include_tree["includes"][0]["path"].endswith("envlib.yar")

        assert resolver.get_all_resolved_files()
        resolver.clear_cache()
        assert resolver.get_all_resolved_files() == []
    finally:
        if previous is None:
            os.environ.pop("YARA_INCLUDE_PATH", None)
        else:
            os.environ["YARA_INCLUDE_PATH"] = previous
