"""
Coverage-loop tests for yaraast/lsp/runtime.py.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Each test exercises a specific branch or statement that was not covered
by the existing test suite.  All paths are driven through the real runtime
API using real files, real document objects, and real error conditions.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from lsprotocol.types import FileChangeType, FileEvent
import pytest

from yaraast.lsp.document_context import DocumentContext as _BaseDocumentContext
from yaraast.lsp.document_types import LanguageMode, RuntimeConfig, SymbolRecord
from yaraast.lsp.runtime import (
    CacheManager,
    DocumentContext,
    LspRuntime,
    _parse_bool_setting,
    _parse_language_mode,
    _parse_non_negative_int_setting,
    _require_document_uri,
    get_document_context,
    get_optional_document_context,
    path_to_uri,
)


class _BrokenSymbolsDoc(_BaseDocumentContext):
    """A DocumentContext whose symbols() method raises, for exception-path testing."""

    def symbols(self) -> list[SymbolRecord]:
        raise RuntimeError("deliberate test failure in symbols()")


# ---------------------------------------------------------------------------
# _parse_bool_setting (lines 47-58)
# ---------------------------------------------------------------------------


def test_parse_bool_setting_bool_true() -> None:
    assert _parse_bool_setting(True, False) is True


def test_parse_bool_setting_bool_false() -> None:
    assert _parse_bool_setting(False, True) is False


def test_parse_bool_setting_non_bool_int_nonzero() -> None:
    # line 51: isinstance(value, int) and not isinstance(value, bool)
    assert _parse_bool_setting(1, False) is True
    assert _parse_bool_setting(42, False) is True


def test_parse_bool_setting_non_bool_int_zero() -> None:
    assert _parse_bool_setting(0, True) is False


def test_parse_bool_setting_truthy_strings() -> None:
    for truthy in ("1", "true", "yes", "on", " TRUE ", " Yes "):
        assert _parse_bool_setting(truthy, False) is True, f"failed for {truthy!r}"


def test_parse_bool_setting_falsy_strings() -> None:
    for falsy in ("0", "false", "no", "off", " OFF "):
        assert _parse_bool_setting(falsy, True) is False, f"failed for {falsy!r}"


def test_parse_bool_setting_unrecognized_string_returns_default() -> None:
    # line 58: string doesn't match any key, fall through to return default
    assert _parse_bool_setting("maybe", True) is True
    assert _parse_bool_setting("maybe", False) is False


def test_parse_bool_setting_unsupported_type_returns_default() -> None:
    # line 58: non-bool, non-int, non-str type
    assert _parse_bool_setting(None, True) is True
    assert _parse_bool_setting([], False) is False
    assert _parse_bool_setting(object(), True) is True


# ---------------------------------------------------------------------------
# _parse_non_negative_int_setting (lines 61-71)
# ---------------------------------------------------------------------------


def test_parse_non_negative_int_bool_returns_default() -> None:
    assert _parse_non_negative_int_setting(True, 99) == 99
    assert _parse_non_negative_int_setting(False, 7) == 7


def test_parse_non_negative_int_positive_int() -> None:
    assert _parse_non_negative_int_setting(5, 0) == 5


def test_parse_non_negative_int_negative_int_clamps_to_zero() -> None:
    assert _parse_non_negative_int_setting(-10, 5) == 0


def test_parse_non_negative_int_valid_string() -> None:
    assert _parse_non_negative_int_setting("20", 0) == 20


def test_parse_non_negative_int_invalid_string_returns_default() -> None:
    # lines 69-70: ValueError path
    assert _parse_non_negative_int_setting("abc", 42) == 42
    assert _parse_non_negative_int_setting("", 3) == 3


def test_parse_non_negative_int_unsupported_type_returns_default() -> None:
    # line 71: fall-through
    assert _parse_non_negative_int_setting(None, 5) == 5
    assert _parse_non_negative_int_setting([], 8) == 8


# ---------------------------------------------------------------------------
# _parse_language_mode (lines 74-86)
# ---------------------------------------------------------------------------


def test_parse_language_mode_non_string_returns_default() -> None:
    assert _parse_language_mode(42, LanguageMode.AUTO) is LanguageMode.AUTO
    assert _parse_language_mode(None, LanguageMode.YARA) is LanguageMode.YARA


def test_parse_language_mode_known_values() -> None:
    assert _parse_language_mode("auto", LanguageMode.YARA) is LanguageMode.AUTO
    assert _parse_language_mode("yara", LanguageMode.AUTO) is LanguageMode.YARA
    assert _parse_language_mode("yarax", LanguageMode.AUTO) is LanguageMode.YARA_X
    assert _parse_language_mode("yara-x", LanguageMode.AUTO) is LanguageMode.YARA_X
    assert _parse_language_mode("yaral", LanguageMode.AUTO) is LanguageMode.YARA_L
    assert _parse_language_mode("yara-l", LanguageMode.AUTO) is LanguageMode.YARA_L


def test_parse_language_mode_unknown_string_returns_default() -> None:
    assert _parse_language_mode("unknown", LanguageMode.AUTO) is LanguageMode.AUTO


def test_parse_language_mode_case_insensitive() -> None:
    assert _parse_language_mode("  YARA-X  ", LanguageMode.AUTO) is LanguageMode.YARA_X


# ---------------------------------------------------------------------------
# _require_document_uri (lines 89-93)
# ---------------------------------------------------------------------------


def test_require_document_uri_raises_for_non_string() -> None:
    with pytest.raises(TypeError, match="Document URI must be a string"):
        _require_document_uri(42)  # type: ignore[arg-type]


def test_require_document_uri_rejects_null_byte_string() -> None:
    with pytest.raises(ValueError, match="Document URI must not contain null bytes"):
        _require_document_uri("file:///tmp/\x00broken")


def test_require_document_uri_passes_string_through() -> None:
    uri = "file:///tmp/test.yar"
    assert _require_document_uri(uri) == uri


# ---------------------------------------------------------------------------
# LspRuntime constructor type guards (lines 173-182)
# ---------------------------------------------------------------------------


def test_runtime_rejects_invalid_index() -> None:
    with pytest.raises(TypeError, match="LSP runtime index must be a WorkspaceIndex"):
        LspRuntime(index=object())  # type: ignore[arg-type]


def test_runtime_rejects_invalid_config() -> None:
    with pytest.raises(TypeError, match="LSP runtime config must be a RuntimeConfig"):
        LspRuntime(config=object())  # type: ignore[arg-type]


def test_runtime_rejects_invalid_cache() -> None:
    with pytest.raises(TypeError, match="LSP runtime cache must be a CacheManager"):
        LspRuntime(cache=object())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _mark_dirty with cache_workspace=False (line 189->191)
# ---------------------------------------------------------------------------


def test_mark_dirty_without_cache_workspace_skips_dirty_set() -> None:
    config = RuntimeConfig(cache_workspace=False)
    runtime = LspRuntime(config=config)
    uri = "file:///tmp/test.yar"
    runtime._mark_dirty(uri)
    # _dirty_documents must not be populated when cache_workspace is off
    assert uri not in runtime._dirty_documents
    # cache generation must still be bumped
    assert runtime.cache.generation >= 1


# ---------------------------------------------------------------------------
# resolve_include_target_uri (lines 197-216)
# ---------------------------------------------------------------------------


def test_resolve_include_target_uri_finds_direct_sibling(tmp_path: Path) -> None:
    main = tmp_path / "main.yar"
    common = tmp_path / "common.yar"
    main.write_text('include "common.yar"\nrule a { condition: true }', encoding="utf-8")
    common.write_text("rule shared { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    result = runtime.resolve_include_target_uri(path_to_uri(main), "common.yar")
    assert result == path_to_uri(common)


def test_resolve_include_target_uri_keeps_symlinked_ancestor_path() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        outside = root / "outside"
        outside.mkdir()
        link = root / "linked"
        link.symlink_to(outside, target_is_directory=True)
        workspace = link / "workspace"
        workspace.mkdir()
        main = workspace / "main.yar"
        common = workspace / "common.yar"
        main.write_text('include "common.yar"\nrule a { condition: true }', encoding="utf-8")
        common.write_text("rule shared { condition: true }", encoding="utf-8")

        runtime = LspRuntime()
        runtime.set_workspace_folders([str(workspace)])

        result = runtime.resolve_include_target_uri(f"file://{main}", "common.yar")
        assert result == f"file://{common}"


def test_resolve_include_target_uri_rejects_symlink_include_target_file() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        outside = root / "outside.yar"
        outside.write_text("rule outside { condition: true }", encoding="utf-8")
        main = root / "main.yar"
        main.write_text('include "linked.yar"\nrule a { condition: true }', encoding="utf-8")
        (root / "linked.yar").symlink_to(outside)

        runtime = LspRuntime()
        runtime.set_workspace_folders([str(root)])

        result = runtime.resolve_include_target_uri(path_to_uri(main), "linked.yar")
        assert result is None


def test_resolve_include_target_uri_falls_through_to_suffix_scan(tmp_path: Path) -> None:
    # The URI has a real path but the direct candidate doesn't exist,
    # so the scan at line 211 must find the file via suffix matching.
    main = tmp_path / "main.yar"
    subdir = tmp_path / "sub"
    subdir.mkdir()
    shared = subdir / "shared.yar"
    main.write_text("rule a { condition: true }", encoding="utf-8")
    shared.write_text("rule shared { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    # "shared.yar" won't be found as a direct sibling of main.yar's parent
    # when the file is in a subdirectory, but the suffix scan must locate it.
    result = runtime.resolve_include_target_uri(path_to_uri(main), "shared.yar")
    assert result == path_to_uri(shared)


def test_resolve_include_target_uri_prefers_exact_relative_match_over_suffix_collision(
    tmp_path: Path,
) -> None:
    main = tmp_path / "main.yar"
    collision_root = tmp_path / "aaa"
    collision_root.mkdir()
    collision = collision_root / "sub"
    collision.mkdir()
    wrong = collision / "shared.yar"
    right = tmp_path / "sub"
    right.mkdir()
    target = right / "shared.yar"
    main.write_text("rule a { condition: true }", encoding="utf-8")
    wrong.write_text("rule wrong { condition: true }", encoding="utf-8")
    target.write_text("rule right { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    result = runtime.resolve_include_target_uri(path_to_uri(main), "sub/shared.yar")
    assert result == path_to_uri(target)


def test_resolve_include_target_uri_prefers_deeper_workspace_root_for_exact_matches(
    tmp_path: Path,
) -> None:
    src = tmp_path / "src"
    shallow_root = tmp_path
    deep_root = tmp_path / "z"
    shallow_target = shallow_root / "sub" / "shared.yar"
    deep_target = deep_root / "sub" / "shared.yar"
    main = src / "main.yar"
    src.mkdir()
    shallow_target.parent.mkdir()
    deep_target.parent.mkdir(parents=True)
    main.write_text("rule a { condition: true }", encoding="utf-8")
    shallow_target.write_text("rule shallow { condition: true }", encoding="utf-8")
    deep_target.write_text("rule deep { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.index.workspace_folders = [shallow_root, deep_root]

    result = runtime.resolve_include_target_uri(path_to_uri(main), "sub/shared.yar")
    assert result == path_to_uri(deep_target)


def test_resolve_include_target_uri_skips_inaccessible_workspace_roots(tmp_path: Path) -> None:
    main = tmp_path / "main.yar"
    subdir = tmp_path / "sub"
    subdir.mkdir()
    target = subdir / "shared.yar"
    main.write_text("rule a { condition: true }", encoding="utf-8")
    target.write_text("rule shared { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.index.workspace_folders = [Path("a" * 5000), tmp_path]

    result = runtime.resolve_include_target_uri(path_to_uri(main), "sub/shared.yar")
    assert result == path_to_uri(target)


def test_resolve_include_target_uri_rejects_parent_relative_escape(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    main = rules_dir / "main.yar"
    shared = tmp_path / "shared.yar"
    main.write_text('include "../shared.yar"\nrule a { condition: true }', encoding="utf-8")
    shared.write_text("rule shared { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    assert runtime.resolve_include_target_uri(path_to_uri(main), "../shared.yar") is None


def test_resolve_include_target_uri_rejects_null_byte_include_path(tmp_path: Path) -> None:
    main = tmp_path / "main.yar"
    main.write_text("rule a { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    assert runtime.resolve_include_target_uri(path_to_uri(main), "\x00broken") is None


def test_resolve_include_target_uri_with_null_path_uri_uses_suffix_scan(tmp_path: Path) -> None:
    # A non-file URI yields path=None from uri_to_path, which skips the
    # direct-candidate check (line 199->211) and goes straight to the suffix scan.
    shared = tmp_path / "lib.yar"
    shared.write_text("rule lib { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    result = runtime.resolve_include_target_uri("https://example.com/editor", "lib.yar")
    assert result == path_to_uri(shared)


def test_resolve_include_target_uri_oserror_on_symlink_loop(tmp_path: Path) -> None:
    # A circular symlink causes OSError in Path.resolve(strict=True) inside the runtime;
    # the implementation catches that and falls through to the suffix scan (lines 202-203).
    loop_a = tmp_path / "loop_a"
    loop_b = tmp_path / "loop_b"
    loop_a.symlink_to(loop_b)
    loop_b.symlink_to(loop_a)

    main = tmp_path / "main.yar"
    main.write_text("rule a { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    # The include path traverses the symlink loop; direct resolve raises OSError.
    # No workspace file matches "loop_a/target.yar", so the result is None.
    result = runtime.resolve_include_target_uri(path_to_uri(main), "loop_a/target.yar")
    assert result is None


def test_resolve_include_target_uri_returns_none_when_not_found(tmp_path: Path) -> None:
    main = tmp_path / "main.yar"
    main.write_text("rule a { condition: true }", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])

    assert runtime.resolve_include_target_uri(path_to_uri(main), "missing.yar") is None


# ---------------------------------------------------------------------------
# _sync_document_to_index (lines 218-236)
# ---------------------------------------------------------------------------


def test_sync_document_to_index_no_op_when_cache_workspace_false() -> None:
    # line 220: early return when cache_workspace is off
    config = RuntimeConfig(cache_workspace=False)
    runtime = LspRuntime(config=config)
    gen_before = runtime.cache.generation
    runtime._sync_document_to_index("file:///anything.yar")
    assert runtime.cache.generation == gen_before


def test_sync_document_to_index_removes_missing_uri(tmp_path: Path) -> None:
    # lines 223-226: ctx is None -> remove from index and bump generation
    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    gen_before = runtime.cache.generation
    runtime._sync_document_to_index("file:///no_such_doc.yar")
    assert runtime.cache.generation > gen_before


def test_sync_document_to_index_skips_non_file_backed_doc() -> None:
    # lines 227-230: ctx exists but backed_by_file=False
    runtime = LspRuntime()
    uri = "file:///tmp/synthetic.yar"
    # Open a document for a non-existent file path -> backed_by_file=False
    runtime.open_document(uri, "rule x { condition: true }")
    assert not runtime.documents[uri].backed_by_file
    gen_before = runtime.cache.generation
    runtime._sync_document_to_index(uri)
    assert runtime.cache.generation > gen_before


# ---------------------------------------------------------------------------
# open_document - re-open promotes synthetic doc to file-backed (line 254->256)
# ---------------------------------------------------------------------------


def test_open_document_promotes_synthetic_to_file_backed(tmp_path: Path) -> None:
    # True branch of line 254: second open when file now exists -> sets backed_by_file=True
    rule_file = tmp_path / "rule.yar"
    content = "rule promo { condition: true }\n"
    runtime = LspRuntime()
    uri = path_to_uri(rule_file)

    # First open: file does not exist yet -> backed_by_file=False
    runtime.open_document(uri, content)
    assert not runtime.documents[uri].backed_by_file

    # Create the file on disk, then re-open
    rule_file.write_text(content, encoding="utf-8")
    runtime.open_document(uri, content)

    # backed_by_file must now be True (line 254->256)
    assert runtime.documents[uri].backed_by_file


def test_open_document_reopen_without_backing_file_skips_promotion() -> None:
    # False branch of line 254 (254->256): file still doesn't exist -> backed_by_file stays False
    runtime = LspRuntime()
    uri = "file:///tmp/never_exists.yar"
    runtime.open_document(uri, "rule a { condition: true }")
    assert not runtime.documents[uri].backed_by_file

    # Re-open: file still doesn't exist -> _document_is_backed_by_file False
    runtime.open_document(uri, "rule a_v2 { condition: true }")
    assert not runtime.documents[uri].backed_by_file
    assert runtime.documents[uri].text == "rule a_v2 { condition: true }"


# ---------------------------------------------------------------------------
# update_document (line 260-261)
# ---------------------------------------------------------------------------


def test_update_document_delegates_to_open_document() -> None:
    runtime = LspRuntime()
    uri = "file:///tmp/update_test.yar"
    ctx = runtime.update_document(uri, "rule u { condition: true }")
    assert isinstance(ctx, DocumentContext)
    assert ctx.text == "rule u { condition: true }"


# ---------------------------------------------------------------------------
# save_document (lines 263-282)
# ---------------------------------------------------------------------------


def test_save_document_returns_none_when_no_ctx_and_no_text() -> None:
    # line 269: ctx is None, text is None -> return None
    runtime = LspRuntime()
    result = runtime.save_document("file:///nonexistent.yar", text=None)
    assert result is None


def test_save_document_opens_new_doc_when_no_ctx_but_text_given() -> None:
    runtime = LspRuntime()
    uri = "file:///tmp/new_save.yar"
    ctx = runtime.save_document(uri, text="rule s { condition: true }")
    assert ctx is not None
    assert ctx.text == "rule s { condition: true }"


def test_save_document_updates_path_backed_doc_and_marks_dirty(tmp_path: Path) -> None:
    # lines 279-280: path_backed=True, text is not None -> update + _mark_dirty
    rule_file = tmp_path / "save_test.yar"
    rule_file.write_text("rule a { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule a { condition: true }\n")

    gen_before = runtime.cache.generation
    new_text = "rule b { condition: true }\n"
    ctx = runtime.save_document(uri, text=new_text)

    assert ctx is not None
    assert ctx.text == new_text
    assert runtime.cache.generation > gen_before


def test_save_document_path_backed_no_text_syncs_to_index(tmp_path: Path) -> None:
    # False branch of line 278 (278->281): path_backed=True, text=None -> skip update, sync
    rule_file = tmp_path / "save_no_text.yar"
    rule_file.write_text("rule snt { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule snt { condition: true }\n")
    original_text = runtime.documents[uri].text

    ctx = runtime.save_document(uri, text=None)

    assert ctx is not None
    assert ctx.text == original_text  # text unchanged


def test_save_document_non_path_backed_with_text_update(tmp_path: Path) -> None:
    # path_backed=False branch: text is not None -> update but no _mark_dirty
    runtime = LspRuntime()
    uri = "file:///tmp/not_on_disk.yar"
    runtime.open_document(uri, "rule orig { condition: true }")

    gen_before = runtime.cache.generation
    result = runtime.save_document(uri, text="rule updated { condition: true }")

    assert result is not None
    assert result.text == "rule updated { condition: true }"
    assert runtime.cache.generation > gen_before


# ---------------------------------------------------------------------------
# close_document (lines 284-309)
# ---------------------------------------------------------------------------


def test_close_document_with_cache_file_backed_sets_is_open_false(tmp_path: Path) -> None:
    # lines 305-306: file still exists -> keep doc in cache with is_open=False
    rule_file = tmp_path / "close_test.yar"
    rule_file.write_text("rule c { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule c { condition: true }\n")
    assert runtime.documents[uri].is_open

    runtime.close_document(uri)

    # File still exists -> document kept but marked as closed
    assert uri in runtime.documents
    assert not runtime.documents[uri].is_open


def test_close_document_without_cache_removes_doc() -> None:
    # lines 307-309: cache_workspace=False -> pop doc
    config = RuntimeConfig(cache_workspace=False)
    runtime = LspRuntime(config=config)
    uri = "file:///tmp/nocache_close.yar"
    runtime.open_document(uri, "rule x { condition: true }")
    assert uri in runtime.documents

    runtime.close_document(uri)
    assert uri not in runtime.documents


def test_close_document_noop_when_doc_missing() -> None:
    runtime = LspRuntime()
    # Must not raise even when the document was never opened
    runtime.close_document("file:///tmp/ghost.yar")


def test_close_document_removes_non_file_backed_synthetic_doc(tmp_path: Path) -> None:
    # lines 299-304: cache_workspace=True, backed_by_file=False -> remove doc
    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = "file:///tmp/purely_synthetic.yar"
    runtime.open_document(uri, "rule syn { condition: true }")
    assert not runtime.documents[uri].backed_by_file

    runtime.close_document(uri)
    assert uri not in runtime.documents


# ---------------------------------------------------------------------------
# get_document (lines 311-339)
# ---------------------------------------------------------------------------


def test_get_document_returns_none_for_missing_uri_without_load() -> None:
    runtime = LspRuntime()
    result = runtime.get_document("file:///tmp/absent.yar", load_workspace=False)
    assert result is None


def test_get_document_returns_none_when_read_fails(tmp_path: Path) -> None:
    # lines 325-327: file exists but read_text raises PermissionError
    rule_file = tmp_path / "no_perms.yar"
    rule_file.write_text("rule perm { condition: true }\n", encoding="utf-8")
    os.chmod(rule_file, 0o000)
    try:
        runtime = LspRuntime()
        result = runtime.get_document(path_to_uri(rule_file))
        assert result is None
    finally:
        os.chmod(rule_file, stat.S_IRUSR | stat.S_IWUSR)


def test_get_document_returns_none_for_symlinked_ancestor_path(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link_dir = tmp_path / "linked"
    link_dir.symlink_to(outside, target_is_directory=True)
    rule_file = link_dir / "ancestor.yar"
    rule_file.write_text("rule ancestor { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()

    assert runtime.get_document(rule_file.as_uri()) is None


def test_get_document_loads_from_disk_without_cache(tmp_path: Path) -> None:
    # line 335->338 skipped: cache_workspace=False -> read but don't cache
    rule_file = tmp_path / "load_test.yar"
    rule_file.write_text("rule loaded { condition: true }\n", encoding="utf-8")

    config = RuntimeConfig(cache_workspace=False)
    runtime = LspRuntime(config=config)
    ctx = runtime.get_document(path_to_uri(rule_file))

    assert ctx is not None
    assert "loaded" in ctx.text
    # With cache_workspace=False the doc must not be persisted
    assert path_to_uri(rule_file) not in runtime.documents


def test_get_document_sets_backed_by_file_for_cached_doc(tmp_path: Path) -> None:
    # line 315->317: ctx already cached, load_workspace=True, file exists
    rule_file = tmp_path / "cached.yar"
    rule_file.write_text("rule cached { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule cached { condition: true }\n")

    ctx = runtime.get_document(uri)
    assert ctx is not None
    assert ctx.backed_by_file


# ---------------------------------------------------------------------------
# iter_workspace_documents (lines 353-361)
# ---------------------------------------------------------------------------


def test_iter_workspace_documents_includes_index_files(tmp_path: Path) -> None:
    # lines 358-360 True branch: files in index not in self.documents are loaded and returned
    rule_file = tmp_path / "indexed.yar"
    rule_file.write_text("rule indexed { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    # Clear preloaded docs to force iter_workspace_documents to pull from index
    runtime.documents.clear()

    docs = runtime.iter_workspace_documents()
    uris = {d.uri for d in docs}
    assert path_to_uri(rule_file) in uris


def test_iter_workspace_documents_keeps_symlinked_ancestor_path(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    workspace_root = link / "workspace"
    workspace_root.mkdir()
    rule_file = workspace_root / "indexed.yar"
    rule_file.write_text("rule indexed { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(workspace_root)])
    runtime.documents.clear()

    docs = runtime.iter_workspace_documents()
    uris = {d.uri for d in docs}
    assert rule_file.absolute().as_uri() in uris


def test_set_workspace_folders_keeps_symlinked_ancestor_path(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    workspace_root = link / "workspace"
    workspace_root.mkdir()
    rule_file = workspace_root / "preload.yar"
    rule_file.write_text("rule preload { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(workspace_root)])

    assert rule_file.absolute().as_uri() in runtime.documents


def test_iter_workspace_documents_skips_unreadable_index_file(tmp_path: Path) -> None:
    # False branch of line 359 (359->355): get_document returns None -> skip, continue loop
    rule_file = tmp_path / "unreadable_iter.yar"
    rule_file.write_text("rule ui { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    runtime.documents.clear()

    os.chmod(rule_file, 0o000)
    try:
        docs = runtime.iter_workspace_documents()
    finally:
        os.chmod(rule_file, stat.S_IRUSR | stat.S_IWUSR)

    # File was unreadable -> get_document returned None -> not added to result
    uris = {d.uri for d in docs}
    assert path_to_uri(rule_file) not in uris


# ---------------------------------------------------------------------------
# set_workspace_folders (lines 363-377)
# ---------------------------------------------------------------------------


def test_set_workspace_folders_promotes_backed_by_file(tmp_path: Path) -> None:
    # True branch of line 366: open doc whose file now exists -> backed_by_file=True (line 367)
    rule_file = tmp_path / "promo.yar"
    runtime = LspRuntime()
    uri = path_to_uri(rule_file)

    # Open before file exists -> backed_by_file=False
    runtime.open_document(uri, "rule promo { condition: true }")
    assert not runtime.documents[uri].backed_by_file

    rule_file.write_text("rule promo { condition: true }\n", encoding="utf-8")
    runtime.set_workspace_folders([str(tmp_path)])

    assert runtime.documents[uri].backed_by_file


def test_set_workspace_folders_skips_promotion_for_synthetic_doc(tmp_path: Path) -> None:
    # False branch of line 366 (366->368): doc exists but file doesn't -> no promotion
    runtime = LspRuntime()
    uri = "file:///tmp/synthetic_no_file.yar"
    runtime.open_document(uri, "rule sfx { condition: true }")
    assert not runtime.documents[uri].backed_by_file

    # Call set_workspace_folders; doc is open so it won't be pruned, but
    # _document_is_backed_by_file is False -> skip line 367
    runtime.set_workspace_folders([str(tmp_path)])

    assert uri in runtime.documents
    assert not runtime.documents[uri].backed_by_file


def test_set_workspace_folders_keeps_in_workspace_non_open_doc(tmp_path: Path) -> None:
    # line 371: doc is not open but is in the workspace -> continue (don't prune)
    rule_file = tmp_path / "in_workspace.yar"
    rule_file.write_text("rule iw { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    ctx = runtime.get_document(uri)
    assert ctx is not None
    assert not ctx.is_open  # loaded from disk, not editor-open

    # Re-set the SAME workspace folder -> doc is not open but belongs to workspace
    # -> line 371: continue (keep doc)
    runtime.set_workspace_folders([str(tmp_path)])
    assert uri in runtime.documents


def test_set_workspace_folders_prunes_non_open_out_of_workspace_docs(tmp_path: Path) -> None:
    # line 371: non-open doc that no longer belongs to any workspace folder is removed
    folder_a = tmp_path / "a"
    folder_a.mkdir()
    folder_b = tmp_path / "b"
    folder_b.mkdir()

    rule_a = folder_a / "rule_a.yar"
    rule_a.write_text("rule ra { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(folder_a)])
    uri_a = path_to_uri(rule_a)

    # Load doc from disk (not open -> is_open=False)
    ctx = runtime.get_document(uri_a)
    assert ctx is not None
    assert not ctx.is_open

    # Switch workspace to folder_b -> doc in folder_a should be pruned
    runtime.set_workspace_folders([str(folder_b)])
    assert uri_a not in runtime.documents


def test_set_workspace_folders_with_cache_workspace_preloads_files(tmp_path: Path) -> None:
    # line 375->exit: cache_workspace=True -> preload all workspace files
    rule_file = tmp_path / "preload.yar"
    rule_file.write_text("rule preloaded { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()  # cache_workspace defaults to True
    runtime.set_workspace_folders([str(tmp_path)])

    # After set_workspace_folders the file must be in cache (preloaded)
    uri = path_to_uri(rule_file)
    assert uri in runtime.documents


# ---------------------------------------------------------------------------
# update_config (lines 379-427)
# ---------------------------------------------------------------------------


def test_update_config_none_is_noop() -> None:
    runtime = LspRuntime()
    gen = runtime.cache.generation
    runtime.update_config(None)
    assert runtime.cache.generation == gen


def test_update_config_non_dict_raises_type_error() -> None:
    runtime = LspRuntime()
    with pytest.raises(TypeError, match="LSP runtime settings must be a dictionary"):
        runtime.update_config("bad")  # type: ignore[arg-type]


def test_update_config_empty_dict_is_noop() -> None:
    runtime = LspRuntime()
    gen = runtime.cache.generation
    runtime.update_config({})
    assert runtime.cache.generation == gen


def test_update_config_unwraps_yara_key(tmp_path: Path) -> None:
    # line 387->389: settings wrapped under "YARA" key
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"cacheWorkspace": False}})
    assert runtime.config.cache_workspace is False


def test_update_config_rule_name_validation_string() -> None:
    # lines 399->401: ruleNameValidation is a non-empty string -> store it
    runtime = LspRuntime()
    runtime.update_config({"ruleNameValidation": "PascalCase"})
    assert runtime.config.rule_name_validation == "PascalCase"


def test_update_config_rule_name_validation_none() -> None:
    runtime = LspRuntime()
    runtime.update_config({"ruleNameValidation": None})
    assert runtime.config.rule_name_validation is None


def test_update_config_rule_name_validation_empty_string_becomes_none() -> None:
    runtime = LspRuntime()
    runtime.update_config({"ruleNameValidation": ""})
    assert runtime.config.rule_name_validation is None


def test_update_config_rule_name_validation_non_string_ignored() -> None:
    # False branch of line 399 (399->401): value is not None and not a string -> skip
    runtime = LspRuntime()
    previous = runtime.config.rule_name_validation
    runtime.update_config({"ruleNameValidation": 42})
    # Neither None nor string -> no assignment, value unchanged
    assert runtime.config.rule_name_validation == previous


def test_update_config_language_mode_change_propagates_to_open_docs(tmp_path: Path) -> None:
    # lines 409-412: changing dialectMode must update all cached documents
    runtime = LspRuntime()
    uri = "file:///tmp/mode_doc.yar"
    runtime.open_document(uri, "rule m { condition: true }")
    assert runtime.documents[uri].language_mode is LanguageMode.AUTO

    runtime.update_config({"dialectMode": "yara-x"})

    assert runtime.config.language_mode is LanguageMode.YARA_X
    assert runtime.documents[uri].language_mode is LanguageMode.YARA_X


def test_update_config_disable_cache_workspace_prunes_non_open_docs() -> None:
    # line 418: not cache_workspace -> keep only open docs
    runtime = LspRuntime()
    open_uri = "file:///tmp/open.yar"
    closed_uri = "file:///tmp/closed.yar"
    runtime.open_document(open_uri, "rule open { condition: true }")
    runtime.open_document(closed_uri, "rule closed { condition: true }")
    runtime.documents[closed_uri].is_open = False

    runtime.update_config({"cacheWorkspace": False})

    assert open_uri in runtime.documents
    assert closed_uri not in runtime.documents


def test_update_config_enable_cache_workspace_syncs_and_preloads(tmp_path: Path) -> None:
    # lines 419-426: toggling cache_workspace from False to True.
    # Open an open doc and a non-open doc so both branches of line 423 are hit.
    rule_file = tmp_path / "preload2.yar"
    rule_file.write_text("rule preload2 { condition: true }\n", encoding="utf-8")

    config = RuntimeConfig(cache_workspace=False)
    runtime = LspRuntime(config=config)
    runtime.set_workspace_folders([str(tmp_path)])

    # Open doc (is_open=True -> line 423 True -> sync to index)
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule preload2 { condition: true }\n")
    assert runtime.documents[uri].is_open

    # Also inject a closed doc (is_open=False -> branch 423->422 False path)
    closed_uri = "file:///tmp/closed_toggle.yar"
    runtime.open_document(closed_uri, "rule ct { condition: true }")
    runtime.documents[closed_uri].is_open = False

    gen_before = runtime.cache.generation
    runtime.update_config({"cacheWorkspace": True})

    assert runtime.config.cache_workspace is True
    assert runtime.cache.generation > gen_before


def test_update_config_metadata_validation() -> None:
    runtime = LspRuntime()
    runtime.update_config({"metadataValidation": [{"key": "author", "required": True}]})
    assert runtime.config.metadata_validation == [{"key": "author", "required": True}]


def test_update_config_code_formatting() -> None:
    runtime = LspRuntime()
    runtime.update_config({"codeFormatting": {"indent": 4}})
    assert runtime.config.code_formatting == {"indent": 4}


def test_update_config_diagnostics_debounce_ms() -> None:
    runtime = LspRuntime()
    runtime.update_config({"diagnosticsDebounceMs": 500})
    assert runtime.config.diagnostics_debounce_ms == 500


# ---------------------------------------------------------------------------
# handle_watched_files (lines 429-466)
# ---------------------------------------------------------------------------


def _make_file_event(uri: str, change_type: FileChangeType = FileChangeType.Changed) -> Any:
    return FileEvent(uri=uri, type=change_type)


class _ChangeWithNoUri:
    """Simulates a change object that has no uri attribute."""


class _ChangeWithFalsyUri:
    """Simulates a change object whose uri is an empty string."""

    uri = ""


def test_handle_watched_files_skips_change_without_uri() -> None:
    # line 433: getattr returns None -> continue
    runtime = LspRuntime()
    runtime.handle_watched_files([_ChangeWithNoUri()])
    assert runtime.documents == {}


def test_handle_watched_files_skips_change_with_falsy_uri() -> None:
    # line 433: uri is "" -> falsy -> continue
    runtime = LspRuntime()
    runtime.handle_watched_files([_ChangeWithFalsyUri()])
    assert runtime.documents == {}


def test_handle_watched_files_skips_change_with_null_path_uri() -> None:
    # line 436: uri_to_path returns None -> continue
    runtime = LspRuntime()
    runtime.handle_watched_files([_make_file_event("https://example.com/foo.yar")])
    assert runtime.documents == {}


def test_handle_watched_files_read_failure_clears_document(tmp_path: Path) -> None:
    # lines 445-448: file exists but read_text raises -> pop doc, continue
    rule_file = tmp_path / "unreadable.yar"
    rule_file.write_text("rule u { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    uri = path_to_uri(rule_file)

    # Put a stale doc in the cache (is_open=False so the new-file branch is taken)
    runtime.open_document(uri, "rule u { condition: true }\n")
    runtime.documents[uri].is_open = False

    os.chmod(rule_file, 0o000)
    try:
        runtime.handle_watched_files([_make_file_event(uri, FileChangeType.Changed)])
    finally:
        os.chmod(rule_file, stat.S_IRUSR | stat.S_IWUSR)

    assert uri not in runtime.documents


def test_handle_watched_files_file_deleted_removes_non_open_doc(tmp_path: Path) -> None:
    # lines 463-466: file gone, doc not open -> pop and remove from index
    rule_file = tmp_path / "gone.yar"
    rule_file.write_text("rule gone { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule gone { condition: true }\n")
    runtime.documents[uri].is_open = False

    rule_file.unlink()
    runtime.handle_watched_files([_make_file_event(uri, FileChangeType.Deleted)])

    assert uri not in runtime.documents


def test_handle_watched_files_file_cached_no_cache_workspace(tmp_path: Path) -> None:
    # lines 453-455: file exists, cache_workspace=False -> pop and bump gen
    rule_file = tmp_path / "nocache.yar"
    rule_file.write_text("rule nc { condition: true }\n", encoding="utf-8")

    config = RuntimeConfig(cache_workspace=False)
    runtime = LspRuntime(config=config)
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule nc { condition: true }\n")
    runtime.documents[uri].is_open = False

    gen_before = runtime.cache.generation
    runtime.handle_watched_files([_make_file_event(uri, FileChangeType.Changed)])
    assert runtime.cache.generation > gen_before


# ---------------------------------------------------------------------------
# Module-level helpers: get_document_context / get_optional_document_context
# ---------------------------------------------------------------------------


def test_get_document_context_with_no_runtime_returns_fallback() -> None:
    # line 554: runtime is None -> fallback DocumentContext
    ctx = get_document_context(None, None, "rule x { condition: true }")
    assert isinstance(ctx, DocumentContext)
    assert ctx.uri == "file://local.yar"


def test_get_document_context_with_runtime_and_uri() -> None:
    runtime = LspRuntime()
    uri = "file:///tmp/gdc_test.yar"
    ctx = get_document_context(runtime, uri, "rule y { condition: true }")
    assert isinstance(ctx, DocumentContext)
    assert ctx.uri == uri


def test_get_document_context_with_runtime_but_no_uri_returns_fallback() -> None:
    runtime = LspRuntime()
    ctx = get_document_context(runtime, None, "rule z { condition: true }")
    assert isinstance(ctx, DocumentContext)
    # uri=None is falsy so the function uses the fallback_uri
    assert ctx.uri == "file://local.yar"


def test_get_document_context_custom_fallback_uri() -> None:
    ctx = get_document_context(
        None, None, "rule a { condition: true }", fallback_uri="file:///custom.yar"
    )
    assert ctx.uri == "file:///custom.yar"


def test_get_optional_document_context_no_runtime_returns_none() -> None:
    # lines 562-564: runtime is None -> return None
    result = get_optional_document_context(None, "file:///tmp/x.yar", "rule x { condition: true }")
    assert result is None


def test_get_optional_document_context_no_uri_returns_none() -> None:
    runtime = LspRuntime()
    result = get_optional_document_context(runtime, None, "rule x { condition: true }")
    assert result is None


def test_get_optional_document_context_with_runtime_and_uri() -> None:
    runtime = LspRuntime()
    uri = "file:///tmp/godc_test.yar"
    ctx = get_optional_document_context(runtime, uri, "rule o { condition: true }")
    assert ctx is not None
    assert ctx.uri == uri


# ---------------------------------------------------------------------------
# _sync_document_to_index exception handler (lines 233-234)
# ---------------------------------------------------------------------------


def test_sync_document_to_index_handles_update_exception(tmp_path: Path) -> None:
    # lines 233-234: index.update_document raises -> exception is caught and logged.
    # Injecting a DocumentContext subclass whose symbols() raises ensures the broad
    # except clause is exercised with a real in-process exception, not a mock.
    rule_file = tmp_path / "sync_exc.yar"
    rule_file.write_text("rule exc { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)

    # Replace the real document with a broken one that raises inside symbols()
    broken = _BrokenSymbolsDoc(
        uri,
        "rule exc { condition: true }\n",
        is_open=True,
        backed_by_file=True,
    )
    runtime.documents[uri] = broken

    gen_before = runtime.cache.generation
    runtime._sync_document_to_index(uri)
    # Exception must be swallowed; generation still bumped
    assert runtime.cache.generation > gen_before


# ---------------------------------------------------------------------------
# save_document non-path-backed, text=None (lines 274->276)
# ---------------------------------------------------------------------------


def test_save_document_non_path_backed_no_text_returns_ctx() -> None:
    # lines 274->276: doc exists, not path-backed, text=None -> bump gen and return ctx
    runtime = LspRuntime()
    uri = "file:///tmp/synthetic_save_no_text.yar"
    runtime.open_document(uri, "rule snt { condition: true }")
    assert not runtime.documents[uri].backed_by_file

    gen_before = runtime.cache.generation
    result = runtime.save_document(uri, text=None)

    assert result is not None
    assert result.text == "rule snt { condition: true }"
    assert runtime.cache.generation > gen_before


# ---------------------------------------------------------------------------
# close_document file-backed doc whose file was deleted (lines 294-298)
# ---------------------------------------------------------------------------


def test_close_document_removes_doc_when_backing_file_deleted(tmp_path: Path) -> None:
    # lines 294-298: cache_workspace=True, backed_by_file=True, file gone -> remove doc
    rule_file = tmp_path / "delete_me.yar"
    rule_file.write_text("rule dm { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule dm { condition: true }\n")
    assert runtime.documents[uri].backed_by_file

    rule_file.unlink()
    runtime.close_document(uri)

    assert uri not in runtime.documents


# ---------------------------------------------------------------------------
# get_document returns None for directory URI (line 322)
# ---------------------------------------------------------------------------


def test_get_document_returns_none_for_directory_uri(tmp_path: Path) -> None:
    # line 322: path_is_dir(path) is True -> return None
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    runtime = LspRuntime()
    result = runtime.get_document(path_to_uri(subdir))
    assert result is None


# ---------------------------------------------------------------------------
# ensure_document - text change with file-backed doc (lines 346-351)
# ---------------------------------------------------------------------------


def test_ensure_document_updates_text_and_notes_file_backed(tmp_path: Path) -> None:
    # lines 346-348 True branch: ctx.text != text -> update and mark dirty; then line 349
    # True branch: file exists -> backed_by_file=True
    rule_file = tmp_path / "ensure.yar"
    rule_file.write_text("rule ens { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule ens { condition: true }\n")

    new_text = "rule ens_v2 { condition: true }\n"
    gen_before = runtime.cache.generation
    ctx = runtime.ensure_document(uri, new_text)

    assert ctx.text == new_text
    assert ctx.backed_by_file
    assert runtime.cache.generation > gen_before


def test_ensure_document_no_change_no_backing_file() -> None:
    # False branch of line 349 (349->351): file doesn't exist -> backed_by_file stays False
    runtime = LspRuntime()
    uri = "file:///tmp/no_backing.yar"
    runtime.open_document(uri, "rule nb { condition: true }")
    assert not runtime.documents[uri].backed_by_file

    # ensure with same text: no update, no dirty, but line 349 is still evaluated
    ctx = runtime.ensure_document(uri, "rule nb { condition: true }")
    assert not ctx.backed_by_file


# ---------------------------------------------------------------------------
# handle_watched_files - open + backed_by_file doc update (lines 440-442)
# ---------------------------------------------------------------------------


def test_handle_watched_files_syncs_open_file_backed_doc(tmp_path: Path) -> None:
    # lines 440-442: file exists, doc is_open=True and backed_by_file=True -> sync
    rule_file = tmp_path / "watched_open.yar"
    rule_file.write_text("rule wo { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule wo { condition: true }\n")
    assert runtime.documents[uri].is_open
    assert runtime.documents[uri].backed_by_file

    gen_before = runtime.cache.generation
    runtime.handle_watched_files([FileEvent(uri=uri, type=FileChangeType.Changed)])
    # Generation must be bumped (sync happened)
    assert runtime.cache.generation > gen_before
    assert uri in runtime.documents


# ---------------------------------------------------------------------------
# handle_watched_files - cache_workspace=True new file discovery (lines 450-452)
# ---------------------------------------------------------------------------


def test_handle_watched_files_caches_new_file_with_cache_workspace(tmp_path: Path) -> None:
    # lines 450-452: file exists, no open doc in cache, cache_workspace=True -> open+cache
    rule_file = tmp_path / "discover.yar"
    rule_file.write_text("rule disc { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    # Intentionally do NOT call set_workspace_folders so doc isn't preloaded
    uri = path_to_uri(rule_file)
    assert uri not in runtime.documents

    runtime.handle_watched_files([FileEvent(uri=uri, type=FileChangeType.Created)])

    ctx = runtime.documents.get(uri)
    assert ctx is not None
    assert not ctx.is_open  # line 451: ctx.is_open = False


# ---------------------------------------------------------------------------
# handle_watched_files - deleted file for open+backed doc (lines 459-462)
# ---------------------------------------------------------------------------


def test_handle_watched_files_preserves_open_backed_doc_on_delete(tmp_path: Path) -> None:
    # lines 459-462: file deleted, doc is_open=True and backed_by_file=True
    # -> remove from index but keep doc (it's open in editor)
    rule_file = tmp_path / "keep_open.yar"
    rule_file.write_text("rule ko { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule ko { condition: true }\n")
    assert runtime.documents[uri].is_open
    assert runtime.documents[uri].backed_by_file

    rule_file.unlink()
    gen_before = runtime.cache.generation
    runtime.handle_watched_files([FileEvent(uri=uri, type=FileChangeType.Deleted)])

    # Doc still in cache (it's open in editor), generation bumped
    assert uri in runtime.documents
    assert runtime.cache.generation > gen_before


# ---------------------------------------------------------------------------
# Delegation methods (lines 469, 472, 475, 480, 489, 503, 518, 527, 530, 533,
# 536, 539, 542)
# ---------------------------------------------------------------------------


def test_runtime_delegation_methods(tmp_path: Path) -> None:
    """Verify every delegation method reaches the real implementation."""
    rule_file = tmp_path / "delegation.yar"
    rule_file.write_text("rule deleg { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, "rule deleg { condition: true }\n")

    from lsprotocol.types import Position

    # workspace_symbols (line 469)
    syms = runtime.workspace_symbols("")
    assert isinstance(syms, list)

    # workspace_symbol_records (line 472)
    recs = runtime.workspace_symbol_records("")
    assert isinstance(recs, list)

    # resolve_symbol (line 475)
    resolved = runtime.resolve_symbol(
        uri, "rule deleg { condition: true }\n", Position(line=0, character=6)
    )
    assert resolved is not None
    assert resolved.name == "deleg"

    # find_rule_definition (line 480)
    defn = runtime.find_rule_definition("deleg", uri)
    assert defn is not None

    # find_rule_references (line 489)
    refs = runtime.find_rule_references("deleg")
    assert isinstance(refs, list)
    assert len(refs) >= 1

    # find_rule_reference_records (line 503)
    ref_recs = runtime.find_rule_reference_records("deleg")
    assert isinstance(ref_recs, list)
    assert len(ref_recs) >= 1

    # find_rule_reference_records_in_document (line 518)
    in_doc_recs = runtime.find_rule_reference_records_in_document("deleg", uri)
    assert isinstance(in_doc_recs, list)

    # get_rule_link_records_for_document (line 527)
    link_recs = runtime.get_rule_link_records_for_document(uri)
    assert isinstance(link_recs, list)

    # rename_rule (line 530)
    edits = runtime.rename_rule("deleg", "deleg_renamed")
    assert isinstance(edits, dict)

    # should_debounce (line 533)
    deb = runtime.should_debounce(uri, "diagnostics")
    assert isinstance(deb, bool)

    # record_latency (line 536)
    runtime.record_latency("test_op", 5.0)

    # get_latency_metrics (line 539)
    metrics = runtime.get_latency_metrics()
    assert isinstance(metrics, dict)

    # get_status (line 542)
    status = runtime.get_status()
    assert isinstance(status, dict)


# ---------------------------------------------------------------------------
# CacheManager property accessors (coverage for property bodies)
# ---------------------------------------------------------------------------


def test_cache_manager_properties_return_correct_types() -> None:
    cm = CacheManager()
    assert isinstance(cm.workspace_symbol_cache, dict)
    assert isinstance(cm.rule_definition_cache, dict)
    assert isinstance(cm.rule_references_cache, dict)
    assert isinstance(cm.rule_reference_records_cache, dict)
    assert cm.generation == 0
    cm.bump_generation()
    assert cm.generation == 1
    assert cm.workspace_symbol_cache == {}
