"""Additional real tests for lexer helpers and include resolution."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from yaraast.lexer.string_escape import StringEscapeHandler
from yaraast.resolution.include_resolver import IncludeResolver


def test_string_escape_handler_covers_remaining_paths() -> None:
    with pytest.raises(ValueError, match="Invalid escape sequence"):
        StringEscapeHandler(r"\q", 1).handle_backslash("q")

    with pytest.raises(ValueError, match="Invalid hex escape sequence"):
        StringEscapeHandler(r"\x4", 1).handle_backslash("x")

    eof_after_quote = StringEscapeHandler(r"\"", 1).handle_backslash('"')
    assert eof_after_quote.chars == ['"']
    assert eof_after_quote.ends_string is False


def test_include_resolver_env_tree_and_cache_helpers(tmp_path: Path) -> None:
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    env_file = env_dir / "envlib.yar"
    env_file.write_text("rule envlib { condition: true }", encoding="utf-8")

    main = tmp_path / "main.yar"
    main.write_text('include "envlib.yar"\nrule main { condition: true }', encoding="utf-8")

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
