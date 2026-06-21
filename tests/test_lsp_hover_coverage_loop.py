"""Regression tests targeting uncovered lines in yaraast/lsp/hover.py.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Lines targeted (74.10% -> closer to 100%):
  114-116  _hover_for_module fallback via extended module_docs
  138-141  _hover_for_module_member dotted-AST path (comment context)
  143-145  _hover_for_module_member elif-word-dot path (hash-prefixed dotted word)
  155      _hover_for_string word-prefix fallback (resolved=None, word starts with $)
  203      _hover_for_module_by_word when module_info is not None
  229-231  _hover_for_rule workspace-rule branch
  304      _render_member_hover unknown-kind returns None
  315      _get_string_identifier_hover prepend-$ path (identifier lstripped to non-$)
  321-322  _get_string_identifier_hover except-Exception branch (corrupted cache)
  336      _get_meta_hover returns None when key has no meta value
  348      _get_include_hover runtime returns None for unresolvable include
  376-392  _get_workspace_rule_hover all internal branches
"""

from __future__ import annotations

from lsprotocol.types import Hover, MarkupContent, Position, Range

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_types import ResolvedSymbol
from yaraast.lsp.hover import HoverProvider
from yaraast.lsp.lsp_docs import MODULE_DOCS
from yaraast.lsp.runtime import LspRuntime


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def _range(start_char: int = 0, end_char: int = 4) -> Range:
    return Range(start=_pos(0, start_char), end=_pos(0, end_char))


def _text(hover: Hover) -> str:
    assert isinstance(hover.contents, MarkupContent)
    return hover.contents.value


def _doc(source: str) -> DocumentContext:
    return DocumentContext("file://test.yar", source)


# ---------------------------------------------------------------------------
# Lines 114-116: _hover_for_module fallback via extended module_docs
# ---------------------------------------------------------------------------


def test_hover_for_module_uses_module_docs_fallback_when_doc_returns_none() -> None:
    """_hover_for_module falls back to self.module_docs when get_module_info returns None.

    A resolved symbol whose normalized_name is NOT in MODULE_DOCS makes
    DocumentContext.get_module_info return None.  When the provider has
    that name in its own module_docs dict, lines 114-116 fire and a Hover
    is returned from the fallback branch.
    """
    provider = HoverProvider()
    # Add a name that is absent from MODULE_DOCS so that get_module_info returns None.
    custom_name = "_xtest_custom_module_"
    assert custom_name not in MODULE_DOCS
    provider.module_docs = {**MODULE_DOCS, custom_name: "Custom module for testing."}

    doc = _doc("rule r { condition: true }")
    word_range = _range(0, len(custom_name))
    resolved = ResolvedSymbol(
        uri="file://test.yar",
        name=custom_name,
        normalized_name=custom_name,
        kind="module",
        range=word_range,
    )

    hover = provider._hover_for_module(doc, resolved, word_range)

    assert hover is not None
    hover_text = _text(hover)
    assert custom_name in hover_text
    assert "(module)" in hover_text
    assert "Custom module for testing." in hover_text


# ---------------------------------------------------------------------------
# Lines 138-141: _hover_for_module_member dotted-AST path
# ---------------------------------------------------------------------------


def test_hover_for_module_member_uses_dotted_ast_path_in_comment_context() -> None:
    """Lines 138-141: dotted symbol resolved from AST even when resolve_symbol returns None.

    In a C-style comment, resolve_symbol returns None but
    get_dotted_symbol_at_position still finds the qualified name.  The
    hover provider follows that path and returns a function hover.
    """
    provider = HoverProvider()
    # The // prefix causes resolve_symbol to return None for position 0:2,
    # but get_dotted_symbol_at_position scans only [a-zA-Z0-9_.] chars and
    # still finds 'pe.imphash' at that position.
    hover = provider.get_hover("//pe.imphash", _pos(0, 2))

    assert hover is not None
    hover_text = _text(hover)
    assert "imphash" in hover_text
    assert "(function)" in hover_text


# ---------------------------------------------------------------------------
# Lines 143-145: _hover_for_module_member elif-word-dot path
# ---------------------------------------------------------------------------


def test_hover_for_module_member_elif_word_dot_path_for_hash_prefixed_dotted_word() -> None:
    """Lines 143-145: elif '.' in word path when get_dotted_symbol_at_position returns None.

    A word like '#a.b' contains a dot but get_dotted_symbol_at_position
    cannot parse it (# is not in the allowed character set).  The elif
    branch at lines 143-145 fires and calls _get_module_member_hover with
    the two split parts.  Since '#a' is not a real module the call returns
    None, and the checker falls through to the string-identifier handler.
    """
    provider = HoverProvider()
    doc = _doc("#a.b")
    word = "#a.b"
    word_range = _range(0, len(word))

    # Call _hover_for_module_member directly to exercise lines 143-145.
    result = provider._hover_for_module_member(doc, None, word, word_range, _pos(0, 0))

    # The module '#a' does not exist so the method returns None.
    assert result is None

    # Confirm via the full hover path that the elif branch executes without error.
    full_hover = provider.get_hover("#a.b", _pos(0, 0))
    # The string-identifier fallback fires after module_member returns None.
    assert full_hover is not None
    assert "string identifier" in _text(full_hover)


# ---------------------------------------------------------------------------
# Line 155: _hover_for_string word-prefix fallback (resolved=None)
# ---------------------------------------------------------------------------


def test_hover_for_string_word_prefix_fallback_when_resolved_is_none() -> None:
    """Line 155: word starts with $ but resolved is None.

    When _hover_for_string is called with resolved=None and a word that
    starts with '$', the fallback at line 155 fires and returns a
    string-identifier Hover via _get_string_identifier_hover.
    """
    provider = HoverProvider()
    doc = _doc("rule r { condition: true }")
    word_range = _range(0, 2)

    hover = provider._hover_for_string(doc, None, "$z", word_range)

    assert hover is not None
    assert "string identifier" in _text(hover)


# ---------------------------------------------------------------------------
# Line 203: _hover_for_module_by_word when module_info is not None
# ---------------------------------------------------------------------------


def test_hover_for_module_by_word_returns_hover_for_module_name_word() -> None:
    """Line 203: _hover_for_module_by_word fires when word matches a known module.

    A bare 'pe' token outside a rule context resolves to an 'identifier'
    symbol (not 'module'), so _hover_for_module returns None.  The
    _hover_for_module_by_word checker then matches it via
    get_module_info(word) at line 203.
    """
    provider = HoverProvider()
    hover = provider.get_hover("pe", _pos(0, 0))

    assert hover is not None
    hover_text = _text(hover)
    assert "pe" in hover_text
    assert "(module)" in hover_text


# ---------------------------------------------------------------------------
# Lines 229-231: _hover_for_rule workspace-rule branch
# ---------------------------------------------------------------------------


def test_hover_for_rule_returns_workspace_rule_hover_from_another_document() -> None:
    """Lines 229-231: workspace rule hover branch fires when rule is defined elsewhere.

    When a rule is referenced from main.yar but defined in lib.yar, and
    _get_rule_hover returns None for the current document, the provider
    falls into the workspace lookup at lines 229-231.
    """
    runtime = LspRuntime()
    runtime.open_document("file://lib.yar", "rule library_rule { condition: true }")
    runtime.open_document("file://main.yar", "rule main { condition: library_rule }")

    provider = HoverProvider(runtime)
    main_text = "rule main { condition: library_rule }"
    hover = provider.get_hover(main_text, _pos(0, 23), "file://main.yar")

    assert hover is not None
    hover_text = _text(hover)
    assert "library_rule" in hover_text
    assert "lib.yar" in hover_text


# ---------------------------------------------------------------------------
# Line 304: _render_member_hover unknown kind returns None
# ---------------------------------------------------------------------------


def test_render_member_hover_returns_none_for_unknown_kind() -> None:
    """Line 304: _render_member_hover returns None for unrecognised member kinds.

    Passing a member_info dict with kind 'unknown' exercises the final
    return None at line 304 after both 'function' and 'field' branches
    are skipped.
    """
    provider = HoverProvider()
    member_info = {"kind": "unknown", "module": "pe", "member": "x"}
    word_range = _range(0, 2)

    result = provider._render_member_hover(member_info, word_range)

    assert result is None


# ---------------------------------------------------------------------------
# Line 315: _get_string_identifier_hover prepend-$ path
# ---------------------------------------------------------------------------


def test_get_string_identifier_hover_prepends_dollar_when_identifier_lacks_it() -> None:
    """Line 315: non-$ identifier is prefixed with '$' after lstrip.

    An identifier '@a' is lstripped of '@' to 'a'.  Since 'a' does not
    start with '$', line 315 prepends it to form '$a'.  The rendered
    hover should reference '$a'.
    """
    provider = HoverProvider()
    doc = _doc('rule r { strings: $a = "x" condition: $a }')
    word_range = _range(0, 2)

    hover = provider._get_string_identifier_hover(doc, "@a", word_range)

    assert hover is not None
    hover_text = _text(hover)
    assert "$a" in hover_text


# ---------------------------------------------------------------------------
# Lines 321-322: _get_string_identifier_hover except-Exception branch
# ---------------------------------------------------------------------------


def test_get_string_identifier_hover_except_branch_fires_on_corrupted_cache() -> None:
    """Lines 321-322: except Exception catches error from get_string_definition_info.

    Injecting a non-dict value into the DocumentContext analysis cache
    causes _copy_info_dict to raise ValueError when it attempts dict()
    on a string.  The broad except at lines 321-322 catches this and the
    method falls through to return a fallback Hover with string_info=None.
    """
    provider = HoverProvider()
    doc = _doc('rule r { strings: $a = "x" condition: $a }')

    # Warm up the cache with a valid entry first so the revision key is set.
    _ = doc.get_string_definition_info("$a")

    # Overwrite the cache entry with a non-dict string value.  The next call
    # to get_string_definition_info will invoke _copy_info_dict("corrupted")
    # which raises ValueError.
    doc.set_cached("string_definition_info:$a", "corrupted")

    word_range = _range(0, 2)
    hover = provider._get_string_identifier_hover(doc, "$a", word_range)

    # The except branch fires and the fallback renders a generic string hover.
    assert hover is not None
    assert "string identifier" in _text(hover)


# ---------------------------------------------------------------------------
# Line 336: _get_meta_hover returns None for missing meta key
# ---------------------------------------------------------------------------


def test_get_meta_hover_returns_none_when_key_not_in_meta() -> None:
    """Line 336: _get_meta_hover returns None when get_meta_value returns None.

    Requesting hover for a meta key that does not exist in the rule causes
    doc.get_meta_value to return None and the decorated method returns None
    at line 336.
    """
    provider = HoverProvider()
    doc = _doc('rule r { meta: author = "me" condition: true }')
    word_range = _range(0, 8)

    result = provider._get_meta_hover(doc, "nonexistent_key", word_range)

    assert result is None


# ---------------------------------------------------------------------------
# Line 348: _get_include_hover when runtime.resolve_include_target_uri returns None
# ---------------------------------------------------------------------------


def test_get_include_hover_returns_none_when_runtime_cannot_resolve_include() -> None:
    """Line 348: returns None when runtime is set but include cannot be resolved.

    When a uri and runtime are both provided but the include target file
    does not exist on disk and is not in the workspace index, the runtime
    returns None from resolve_include_target_uri and the hover method
    returns None at line 348.
    """
    runtime = LspRuntime()
    provider = HoverProvider(runtime)
    doc = _doc("rule r { condition: true }")
    word_range = _range(0, 12)

    result = provider._get_include_hover(
        doc,
        "does_not_exist.yar",
        word_range,
        "file:///nonexistent_dir/main.yar",
    )

    assert result is None


# ---------------------------------------------------------------------------
# Lines 376-392: _get_workspace_rule_hover all internal branches
# ---------------------------------------------------------------------------


def test_get_workspace_rule_hover_returns_none_when_runtime_is_none() -> None:
    """Line 376: _get_workspace_rule_hover returns None immediately when runtime is None."""
    provider = HoverProvider()  # no runtime
    word_range = _range(0, 8)

    result = provider._get_workspace_rule_hover("file://main.yar", "myrule", word_range)

    assert result is None


def test_get_workspace_rule_hover_returns_none_when_rule_not_in_workspace() -> None:
    """Line 379: _get_workspace_rule_hover returns None when find_rule_definition returns None."""
    runtime = LspRuntime()
    runtime.open_document("file://a.yar", "rule known { condition: true }")
    provider = HoverProvider(runtime)
    word_range = _range(0, 8)

    result = provider._get_workspace_rule_hover("file://a.yar", "unknown_rule", word_range)

    assert result is None


def test_get_workspace_rule_hover_returns_none_when_definition_in_same_file() -> None:
    """Line 381: _get_workspace_rule_hover returns None when definition.uri == current_uri."""
    runtime = LspRuntime()
    runtime.open_document("file://a.yar", "rule same_file_rule { condition: true }")
    provider = HoverProvider(runtime)
    word_range = _range(0, 14)

    # The rule is defined in the same file as current_uri, so hover returns None.
    result = provider._get_workspace_rule_hover("file://a.yar", "same_file_rule", word_range)

    assert result is None


def test_get_workspace_rule_hover_returns_none_when_target_document_not_loaded() -> None:
    """Line 385: _get_workspace_rule_hover returns None when target document is absent.

    The workspace index records lib_rule as living in lib.yar, but the
    document is removed from the runtime's documents dict before the hover
    call, so get_document returns None.
    """
    runtime = LspRuntime()
    runtime.open_document("file://lib.yar", "rule lib_rule { condition: true }")
    runtime.open_document("file://main.yar", "rule main { condition: lib_rule }")
    provider = HoverProvider(runtime)
    word_range = _range(0, 8)

    # Evict the library document to trigger the target_doc is None branch.
    del runtime.documents["file://lib.yar"]

    result = provider._get_workspace_rule_hover("file://main.yar", "lib_rule", word_range)

    assert result is None


def test_get_workspace_rule_hover_returns_none_when_rule_info_missing_from_target() -> None:
    """Line 389: _get_workspace_rule_hover returns None when target doc lacks rule_info.

    The workspace index points to lib.yar for lib_rule, but lib.yar's
    document is replaced with one that defines a different rule.
    get_rule_info('lib_rule') returns None, triggering line 389.
    """
    runtime = LspRuntime()
    runtime.open_document("file://lib.yar", "rule lib_rule { condition: true }")
    runtime.open_document("file://main.yar", "rule main { condition: lib_rule }")
    provider = HoverProvider(runtime)
    word_range = _range(0, 8)

    # Replace the lib document so get_rule_info for 'lib_rule' returns None.
    runtime.documents["file://lib.yar"] = DocumentContext(
        "file://lib.yar", "rule unrelated { condition: true }"
    )

    result = provider._get_workspace_rule_hover("file://main.yar", "lib_rule", word_range)

    assert result is None


def test_get_workspace_rule_hover_returns_hover_for_cross_file_rule() -> None:
    """Line 392: _get_workspace_rule_hover returns a Hover for a cross-file rule.

    This is the happy path that reaches render_workspace_rule_hover at
    line 392 and validates the full workspace rule hover content.
    """
    runtime = LspRuntime()
    runtime.open_document("file://lib.yar", "rule cross_file_rule { condition: true }")
    runtime.open_document("file://main.yar", "rule main { condition: cross_file_rule }")
    provider = HoverProvider(runtime)
    word_range = _range(0, 15)

    hover = provider._get_workspace_rule_hover("file://main.yar", "cross_file_rule", word_range)

    assert hover is not None
    hover_text = _text(hover)
    assert "cross_file_rule" in hover_text
    assert "lib.yar" in hover_text


# ---------------------------------------------------------------------------
# Integration: get_hover exercises all paths end-to-end
# ---------------------------------------------------------------------------


def test_get_hover_fires_module_docs_fallback_via_public_api() -> None:
    """Confirm the MODULE_DOCS fallback path via the public get_hover API.

    A bare 'pe' token that resolves to 'identifier' (not 'module') triggers
    _hover_for_module_by_word at line 203 using the document's get_module_info.
    """
    provider = HoverProvider()
    hover = provider.get_hover("pe", _pos(0, 0))

    assert hover is not None
    assert "(module)" in _text(hover)
    assert "PE" in _text(hover)


def test_get_hover_workspace_rule_integration(tmp_path: object) -> None:
    """Workspace rule hover end-to-end: rule defined in lib, referenced in main."""
    assert hasattr(tmp_path, "__truediv__"), "tmp_path must be a pathlib.Path-like object"
    from pathlib import Path

    tmp = Path(str(tmp_path))
    lib_file = tmp / "lib.yar"
    main_file = tmp / "main.yar"
    lib_file.write_text("rule ws_rule { condition: true }\n", encoding="utf-8")
    main_file.write_text("rule entry { condition: ws_rule }\n", encoding="utf-8")

    runtime = LspRuntime()
    lib_uri = lib_file.resolve().as_uri()
    main_uri = main_file.resolve().as_uri()
    runtime.open_document(lib_uri, lib_file.read_text(encoding="utf-8"))
    runtime.open_document(main_uri, main_file.read_text(encoding="utf-8"))

    provider = HoverProvider(runtime)
    main_text = main_file.read_text(encoding="utf-8")
    hover = provider.get_hover(main_text, _pos(0, 24), main_uri)

    assert hover is not None
    hover_text = _text(hover)
    assert "ws_rule" in hover_text


def test_get_string_identifier_hover_at_sign_prefix_builds_dollar_identifier() -> None:
    """Line 315 via public _get_string_identifier_hover: '@' stripped to 'a', '$' prepended."""
    provider = HoverProvider()
    doc = _doc('rule r { strings: $count = "x" condition: $count }')
    word_range = _range(0, 6)

    hover = provider._get_string_identifier_hover(doc, "@count", word_range)

    assert hover is not None
    assert "$count" in _text(hover)


def test_meta_hover_returns_none_for_absent_key_in_metablock() -> None:
    """Line 336 via integration: meta key not defined in rule returns None."""
    provider = HoverProvider()
    runtime = LspRuntime()
    uri = "file://sample.yar"
    source = 'rule r { meta: version = "1.0" condition: true }'
    runtime.open_document(uri, source)
    provider = HoverProvider(runtime)

    doc = runtime.documents[uri]
    word_range = _range(0, 10)
    result = provider._get_meta_hover(doc, "absent_key", word_range)

    assert result is None


def test_hover_for_string_fallback_with_at_sign_word_prefix() -> None:
    """Line 155: word starts with '@' and resolved is None fires string fallback."""
    provider = HoverProvider()
    doc = _doc("rule r { condition: true }")
    word_range = _range(0, 2)

    hover = provider._hover_for_string(doc, None, "@z", word_range)

    assert hover is not None
    hover_text = _text(hover)
    assert "string identifier" in hover_text


def test_hover_for_string_fallback_with_bang_word_prefix() -> None:
    """Line 155: word starts with '!' and resolved is None fires string fallback."""
    provider = HoverProvider()
    doc = _doc("rule r { condition: true }")
    word_range = _range(0, 2)

    hover = provider._hover_for_string(doc, None, "!z", word_range)

    assert hover is not None
    hover_text = _text(hover)
    assert "string identifier" in hover_text


# ---------------------------------------------------------------------------
# Branch 114->122: _hover_for_module when name absent from both sources
# ---------------------------------------------------------------------------


def test_hover_for_module_returns_none_when_name_absent_from_all_docs() -> None:
    """Branch 114->122: _hover_for_module returns None when name not in module_docs.

    A resolved 'module' symbol whose name is absent from both
    get_module_info and self.module_docs falls through to the unconditional
    return None at line 122 via the False branch of line 114.
    """
    provider = HoverProvider()
    doc = _doc("rule r { condition: true }")
    word_range = _range(0, 12)
    resolved = ResolvedSymbol(
        uri="file://test.yar",
        name="_not_any_module_",
        normalized_name="_not_any_module_",
        kind="module",
        range=word_range,
    )

    result = provider._hover_for_module(doc, resolved, word_range)

    assert result is None


# ---------------------------------------------------------------------------
# Branch 144->146: _hover_for_module_member when word has >1 dot
# ---------------------------------------------------------------------------


def test_hover_for_module_member_skips_multipart_dotted_word() -> None:
    """Branch 144->146: elif branch entered but len(parts)!=2 so returns None.

    A word like 'a.b.c' has a dot but splitting yields 3 parts.  The elif
    at line 143 is entered and the inner if at line 144 evaluates to False,
    so the method returns None at line 146 without calling _get_module_member_hover.
    """
    provider = HoverProvider()
    doc = _doc("a.b.c")
    word_range = _range(0, 5)

    result = provider._hover_for_module_member(doc, None, "a.b.c", word_range, _pos(0, 0))

    assert result is None


# ---------------------------------------------------------------------------
# Branch 230->233: _hover_for_rule workspace branch finds nothing
# ---------------------------------------------------------------------------


def test_hover_for_rule_workspace_branch_returns_none_when_no_workspace_match() -> None:
    """Branch 230->233: runtime is set but workspace rule hover finds no match.

    When runtime and uri are present but the word matches no rule in the
    workspace, _get_workspace_rule_hover returns None and _hover_for_rule
    falls to return None at line 233 via the False branch of line 230.
    """
    runtime = LspRuntime()
    runtime.open_document("file://a.yar", "rule foo { condition: true }")
    provider = HoverProvider(runtime)

    hover = provider.get_hover("nonexistent_rule_name", _pos(0, 0), "file://a.yar")

    assert hover is None


# ---------------------------------------------------------------------------
# Line 386: _get_workspace_rule_hover when target_doc is None (stale cache)
# ---------------------------------------------------------------------------


def test_get_workspace_rule_hover_returns_none_when_target_doc_none_stale_cache(
    tmp_path: object,
) -> None:
    """Line 386: returns None when find_rule_definition has stale cache after file removal.

    After caching the rule definition location, the file and its document
    are removed.  The cached location still points to the deleted file.
    get_document returns None because the file does not exist on disk.
    Line 386 fires.
    """
    from pathlib import Path

    tmp = Path(str(tmp_path))
    lib_path = tmp / "stale_lib.yar"
    main_path = tmp / "stale_main.yar"
    lib_path.write_text("rule stale_rule { condition: true }\n", encoding="utf-8")
    main_path.write_text("rule main { condition: stale_rule }\n", encoding="utf-8")

    lib_uri = lib_path.resolve().as_uri()
    main_uri = main_path.resolve().as_uri()

    runtime = LspRuntime()
    runtime.open_document(lib_uri, lib_path.read_text(encoding="utf-8"))
    runtime.open_document(main_uri, main_path.read_text(encoding="utf-8"))

    # Prime the rule-definition cache while both documents are present.
    defn = runtime.find_rule_definition("stale_rule", main_uri)
    assert defn is not None

    # Remove the library file from disk and evict the document.
    # The cache is not invalidated because we do NOT mutate runtime state
    # through the normal API — generation remains unchanged.
    lib_path.unlink()
    del runtime.documents[lib_uri]

    provider = HoverProvider(runtime)
    word_range = _range(0, 10)

    result = provider._get_workspace_rule_hover(main_uri, "stale_rule", word_range)

    assert result is None


# ---------------------------------------------------------------------------
# Line 390: _get_workspace_rule_hover when rule_info is None (stale cache)
# ---------------------------------------------------------------------------


def test_get_workspace_rule_hover_returns_none_when_rule_info_is_none_stale_cache() -> None:
    """Line 390: returns None when target_doc exists but rule_info is None (stale cache).

    The rule-definition cache is primed to point at lib.yar.  The document
    at lib.yar is then replaced with one that does not define lib_rule.
    find_rule_definition returns the stale cached location; get_document
    returns the new document; get_rule_info returns None; line 390 fires.
    """
    runtime = LspRuntime()
    runtime.open_document("file://cache_lib.yar", "rule cache_rule { condition: true }")
    runtime.open_document("file://cache_main.yar", "rule main { condition: cache_rule }")

    # Prime the cache.
    defn = runtime.find_rule_definition("cache_rule", "file://cache_main.yar")
    assert defn is not None

    # Replace the library document without invalidating the cache.
    runtime.documents["file://cache_lib.yar"] = DocumentContext(
        "file://cache_lib.yar", "rule completely_different { condition: true }"
    )

    provider = HoverProvider(runtime)
    word_range = _range(0, 10)

    result = provider._get_workspace_rule_hover("file://cache_main.yar", "cache_rule", word_range)

    assert result is None
