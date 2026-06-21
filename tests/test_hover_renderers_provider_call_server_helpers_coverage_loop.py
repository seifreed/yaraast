# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression coverage for three LSP helper modules.

Targets:
  yaraast/lsp/hover_renderers.py       — missing lines/branches
  yaraast/lsp/provider_call_helpers.py — missing lines 21, 23, 45
  yaraast/lsp/server_feature_helpers.py — missing lines/branches

All tests exercise the real production code paths; no mocks or stubs are used.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from lsprotocol.types import (
    Diagnostic,
    Hover,
    MarkupContent,
    MarkupKind,
    Position,
    Range,
    SemanticTokens,
)

from yaraast.lsp.hover_renderers import (
    include_hover,
    meta_hover,
    module_field_hover,
    module_function_hover,
    module_hover,
    rule_hover,
    string_identifier_hover,
    workspace_rule_hover,
)
from yaraast.lsp.provider_call_helpers import (
    _accepts_positional_count,
    call_range_with_optional_uri,
    call_with_optional_uri,
)
from yaraast.lsp.server_feature_helpers import (
    get_diagnostics,
    get_document_source,
    get_semantic_tokens,
    get_semantic_tokens_range,
    get_workspace_folders,
)

# ---------------------------------------------------------------------------
# Helpers shared by all sections
# ---------------------------------------------------------------------------


def _range(start: int = 0, end: int = 4) -> Range:
    return Range(start=Position(line=0, character=start), end=Position(line=0, character=end))


def _hover_text(hover: Hover) -> str:
    assert isinstance(hover.contents, MarkupContent)
    return hover.contents.value


def _hover_kind(hover: Hover) -> MarkupKind:
    assert isinstance(hover.contents, MarkupContent)
    return hover.contents.kind


# ===========================================================================
# Section 1 — hover_renderers.py
# ===========================================================================


# ---------------------------------------------------------------------------
# module_hover (line 10-17): basic rendering
# ---------------------------------------------------------------------------


def test_module_hover_renders_markdown() -> None:
    """module_hover must return a Hover with the module name and description."""
    word_range = _range(0, 2)
    hover = module_hover("pe", "Portable Executable module.", word_range)
    text = _hover_text(hover)
    assert "**pe**" in text
    assert "(module)" in text
    assert "Portable Executable module." in text
    assert hover.range == word_range
    assert _hover_kind(hover) is MarkupKind.Markdown


# ---------------------------------------------------------------------------
# module_function_hover (lines 20-30): with and without description
# ---------------------------------------------------------------------------


def test_module_function_hover_with_description() -> None:
    """module_function_hover includes the description when present."""
    member_info: dict[str, Any] = {
        "module": "pe",
        "member": "imports",
        "parameters": [("dll", "string"), ("func", "string")],
        "return_type": "boolean",
        "description": "Check if the PE imports a function.",
    }
    hover = module_function_hover(member_info, _range(0, 7))
    text = _hover_text(hover)
    assert "**imports**" in text
    assert "(function)" in text
    assert "pe.imports(dll: string, func: string) -> boolean" in text
    assert "Check if the PE imports a function." in text


def test_module_function_hover_without_description() -> None:
    """module_function_hover omits the description block when the key is absent/empty."""
    member_info: dict[str, Any] = {
        "module": "math",
        "member": "entropy",
        "parameters": [("start", "integer"), ("length", "integer")],
        "return_type": "float",
        "description": "",
    }
    hover = module_function_hover(member_info, _range(0, 7))
    text = _hover_text(hover)
    assert "**entropy**" in text
    # Empty description must not produce a trailing double-newline + text
    assert text.endswith("```")


# ---------------------------------------------------------------------------
# module_field_hover (lines 33-42): with and without description
# ---------------------------------------------------------------------------


def test_module_field_hover_with_description() -> None:
    """module_field_hover includes the field description when present."""
    member_info: dict[str, Any] = {
        "module": "pe",
        "member": "number_of_sections",
        "type": "integer",
        "description": "Number of sections in the PE image.",
    }
    hover = module_field_hover(member_info, _range(0, 17))
    text = _hover_text(hover)
    assert "**number_of_sections**" in text
    assert "(field)" in text
    assert "pe.number_of_sections: integer" in text
    assert "Number of sections in the PE image." in text


def test_module_field_hover_without_description() -> None:
    """module_field_hover omits description block when key is absent/empty.

    This exercises the branch where member_info.get('description') is falsy
    (line 40 -> 42 branch NOT taken), covering the else path for that condition.
    """
    member_info: dict[str, Any] = {
        "module": "pe",
        "member": "machine",
        "type": "integer",
        "description": "",
    }
    hover = module_field_hover(member_info, _range(0, 7))
    text = _hover_text(hover)
    assert "**machine**" in text
    assert text.endswith("```")


# ---------------------------------------------------------------------------
# string_identifier_hover (lines 45-65): None branch, no-modifiers, with-modifiers
# ---------------------------------------------------------------------------


def test_string_identifier_hover_with_none_info() -> None:
    """string_identifier_hover returns a generic placeholder when string_info is None."""
    hover = string_identifier_hover("$s1", None, _range(0, 3))
    text = _hover_text(hover)
    assert "**$s1**" in text
    assert "string identifier" in text
    assert "strings section" in text


def test_string_identifier_hover_without_modifiers() -> None:
    """string_identifier_hover with a string_info that has an empty modifiers list.

    The branch at line 61 (if string_info['modifiers']) evaluates False; the
    modifier suffix must be absent from the output.
    """
    string_info: dict[str, Any] = {
        "type": "text string",
        "value": '"hello world"',
        "modifiers": [],
    }
    hover = string_identifier_hover("$greet", string_info, _range(0, 6))
    text = _hover_text(hover)
    assert "**$greet**" in text
    assert '"hello world"' in text
    assert "Modifiers" not in text


def test_string_identifier_hover_with_modifiers() -> None:
    """string_identifier_hover with non-empty modifiers exercises the True branch at line 61.

    This is the previously missing branch (40->42 in coverage terms refers to this
    conditional for modifiers being truthy).
    """
    string_info: dict[str, Any] = {
        "type": "text string",
        "value": '"malware"',
        "modifiers": ["nocase", "wide"],
    }
    hover = string_identifier_hover("$mal", string_info, _range(0, 4))
    text = _hover_text(hover)
    assert "**$mal**" in text
    assert '"malware"' in text
    assert "Modifiers: nocase, wide" in text


# ---------------------------------------------------------------------------
# meta_hover (lines 68-75): simple rendering
# ---------------------------------------------------------------------------


def test_meta_hover_renders_key_and_value() -> None:
    """meta_hover must wrap key and value in the expected markdown structure."""
    hover = meta_hover("author", "John Doe", _range(0, 6))
    text = _hover_text(hover)
    assert "**author**" in text
    assert "(metadata)" in text
    assert "John Doe" in text


# ---------------------------------------------------------------------------
# include_hover (lines 78-84): resolved and unresolved paths
# ---------------------------------------------------------------------------


def test_include_hover_with_resolved_path() -> None:
    """include_hover with a real resolved_path shows the 'Resolved to' block."""
    hover = include_hover("utils.yar", "/rules/utils.yar", _range(0, 9))
    text = _hover_text(hover)
    assert "**utils.yar**" in text
    assert "(include)" in text
    assert "Resolved to" in text
    assert "/rules/utils.yar" in text


def test_include_hover_with_none_resolved_path() -> None:
    """include_hover with resolved_path=None takes the else branch at line 82-83.

    This is the previously missing line 83: the fallback message for unresolvable
    include paths.
    """
    hover = include_hover("missing.yar", None, _range(0, 11))
    text = _hover_text(hover)
    assert "**missing.yar**" in text
    assert "(include)" in text
    assert "Include path referenced from the current rule file." in text
    assert "Resolved to" not in text


# ---------------------------------------------------------------------------
# rule_hover (lines 87-109): all YARA-L section branches
# ---------------------------------------------------------------------------

_BASE_RULE_INFO: dict[str, Any] = {
    "modifiers": [],
    "tags": [],
    "meta": [],
    "strings_count": 0,
    "has_events": False,
    "has_match": False,
    "has_outcome": False,
    "has_options": False,
}


def test_rule_hover_minimal() -> None:
    """rule_hover with a plain rule produces just the name and kind."""
    hover = rule_hover("my_rule", _BASE_RULE_INFO, _range(0, 7))
    text = _hover_text(hover)
    assert "**my_rule**" in text
    assert "(rule)" in text
    assert "Tags" not in text
    assert "Metadata" not in text
    assert "Strings" not in text
    assert "YARA-L" not in text


def test_rule_hover_with_modifiers_and_tags() -> None:
    """rule_hover must include modifier brackets and tags line when both are present."""
    info = {**_BASE_RULE_INFO, "modifiers": ["private"], "tags": ["malware", "trojan"]}
    hover = rule_hover("tagged_rule", info, _range(0, 11))
    text = _hover_text(hover)
    assert "[private]" in text
    assert "Tags: malware, trojan" in text


def test_rule_hover_with_meta() -> None:
    """rule_hover must render each meta key-value pair in the Metadata section."""
    info = {**_BASE_RULE_INFO, "meta": [("author", "Alice"), ("date", "2026-01-01")]}
    hover = rule_hover("meta_rule", info, _range(0, 9))
    text = _hover_text(hover)
    assert "**Metadata:**" in text
    assert "- author: Alice" in text
    assert "- date: 2026-01-01" in text


def test_rule_hover_with_strings_count() -> None:
    """rule_hover must show strings count when strings_count is non-zero."""
    info = {**_BASE_RULE_INFO, "strings_count": 3}
    hover = rule_hover("str_rule", info, _range(0, 8))
    text = _hover_text(hover)
    assert "**Strings:** 3 defined" in text


def test_rule_hover_with_has_events() -> None:
    """rule_hover must append the YARA-L events note when has_events is True.

    This is missing line 100 in the coverage report.
    """
    info = {**_BASE_RULE_INFO, "has_events": True}
    hover = rule_hover("events_rule", info, _range(0, 11))
    text = _hover_text(hover)
    assert "**YARA-L:** events section present" in text


def test_rule_hover_with_has_match() -> None:
    """rule_hover must append the YARA-L match note when has_match is True.

    This is missing line 102 in the coverage report.
    """
    info = {**_BASE_RULE_INFO, "has_match": True}
    hover = rule_hover("match_rule", info, _range(0, 10))
    text = _hover_text(hover)
    assert "**YARA-L:** match section present" in text


def test_rule_hover_with_has_outcome() -> None:
    """rule_hover must append the YARA-L outcome note when has_outcome is True.

    This is missing line 104 in the coverage report.
    """
    info = {**_BASE_RULE_INFO, "has_outcome": True}
    hover = rule_hover("outcome_rule", info, _range(0, 12))
    text = _hover_text(hover)
    assert "**YARA-L:** outcome section present" in text


def test_rule_hover_with_has_options() -> None:
    """rule_hover must append the YARA-L options note when has_options is True.

    This is missing line 106 in the coverage report.
    """
    info = {**_BASE_RULE_INFO, "has_options": True}
    hover = rule_hover("options_rule", info, _range(0, 12))
    text = _hover_text(hover)
    assert "**YARA-L:** options section present" in text


def test_rule_hover_all_yaral_sections() -> None:
    """rule_hover with all YARA-L sections enabled must include all four notes."""
    info = {
        **_BASE_RULE_INFO,
        "has_events": True,
        "has_match": True,
        "has_outcome": True,
        "has_options": True,
    }
    hover = rule_hover("full_yaral_rule", info, _range(0, 14))
    text = _hover_text(hover)
    assert "**YARA-L:** events section present" in text
    assert "**YARA-L:** match section present" in text
    assert "**YARA-L:** outcome section present" in text
    assert "**YARA-L:** options section present" in text


# ---------------------------------------------------------------------------
# workspace_rule_hover (lines 112-134): modifiers, tags, meta branches
# ---------------------------------------------------------------------------


def test_workspace_rule_hover_minimal() -> None:
    """workspace_rule_hover with empty modifiers, tags, and meta."""
    info: dict[str, Any] = {"modifiers": [], "tags": [], "meta": []}
    hover = workspace_rule_hover("ws_rule", info, "file:///rules/ws.yar", _range(0, 7))
    text = _hover_text(hover)
    assert "**ws_rule**" in text
    assert "(rule)" in text
    assert "Defined in:" in text
    assert "Modifiers" not in text
    assert "Tags" not in text
    assert "Metadata" not in text


def test_workspace_rule_hover_with_modifiers() -> None:
    """workspace_rule_hover includes the Modifiers line when modifiers is non-empty.

    This is missing line 121 in the coverage report.
    """
    info: dict[str, Any] = {"modifiers": ["global"], "tags": [], "meta": []}
    hover = workspace_rule_hover("global_rule", info, "file:///rules/global.yar", _range(0, 11))
    text = _hover_text(hover)
    assert "Modifiers: global" in text


def test_workspace_rule_hover_with_tags() -> None:
    """workspace_rule_hover includes the Tags line when tags is non-empty.

    This is missing line 124 in the coverage report.
    """
    info: dict[str, Any] = {"modifiers": [], "tags": ["ransomware"], "meta": []}
    hover = workspace_rule_hover("tagged_ws", info, "file:///rules/tagged.yar", _range(0, 9))
    text = _hover_text(hover)
    assert "Tags: ransomware" in text


def test_workspace_rule_hover_with_meta() -> None:
    """workspace_rule_hover includes the Metadata section when meta is non-empty.

    Lines 127-130 are covered by this path.
    """
    info: dict[str, Any] = {
        "modifiers": [],
        "tags": [],
        "meta": [("author", "Bob"), ("version", "1.0")],
    }
    hover = workspace_rule_hover("meta_ws", info, "file:///rules/meta.yar", _range(0, 7))
    text = _hover_text(hover)
    assert "Metadata:" in text
    assert "`author`: `Bob`" in text
    assert "`version`: `1.0`" in text


def test_workspace_rule_hover_truncates_meta_beyond_five() -> None:
    """workspace_rule_hover must truncate meta display to the first 5 entries."""
    pairs = [(f"k{i}", f"v{i}") for i in range(8)]
    info: dict[str, Any] = {"modifiers": [], "tags": [], "meta": pairs}
    hover = workspace_rule_hover("big_meta", info, "file:///rules/big.yar", _range(0, 8))
    text = _hover_text(hover)
    assert "`k4`: `v4`" in text
    assert "`k5`: `v5`" not in text


# ===========================================================================
# Section 2 — provider_call_helpers.py
# ===========================================================================


# ---------------------------------------------------------------------------
# _accepts_positional_count: VAR_POSITIONAL early return (line 21)
# ---------------------------------------------------------------------------


def test_accepts_positional_count_var_positional_returns_true() -> None:
    """A function declared with *args must cause an early True return at line 21.

    The VAR_POSITIONAL branch fires before any count arithmetic.
    """

    def varargs_fn(*args: Any) -> None:
        pass

    # Any count must return True for a pure *args function
    assert _accepts_positional_count(varargs_fn, 0) is True
    assert _accepts_positional_count(varargs_fn, 99) is True


def test_accepts_positional_count_var_positional_with_leading_positional() -> None:
    """A function with (pos, *args) must still hit the VAR_POSITIONAL branch."""

    def mixed_fn(text: str, *args: Any) -> None:
        pass

    assert _accepts_positional_count(mixed_fn, 1) is True
    assert _accepts_positional_count(mixed_fn, 5) is True


# ---------------------------------------------------------------------------
# _accepts_positional_count: KEYWORD_ONLY continue branch (line 23)
# ---------------------------------------------------------------------------


def test_accepts_positional_count_skips_keyword_only_params() -> None:
    """A function with keyword-only params triggers the 'continue' at line 23.

    Keyword-only parameters (declared after a bare *) are not positional and
    must be skipped.  The count calculation is based solely on positional params.
    """

    def kw_only_fn(text: str, *, flag: bool = False) -> None:
        pass

    # text is the one positional param; flag is keyword-only and must be ignored
    assert _accepts_positional_count(kw_only_fn, 1) is True
    assert _accepts_positional_count(kw_only_fn, 2) is False


def test_accepts_positional_count_all_keyword_only() -> None:
    """A function where every parameter is keyword-only: accepted count is 0."""

    def all_kw_fn(*, a: int = 0, b: int = 0) -> None:
        pass

    assert _accepts_positional_count(all_kw_fn, 0) is True
    assert _accepts_positional_count(all_kw_fn, 1) is False


# ---------------------------------------------------------------------------
# call_with_optional_uri: both dispatch paths
# ---------------------------------------------------------------------------


def test_call_with_optional_uri_dispatches_two_arg_method() -> None:
    """call_with_optional_uri passes (text, uri) when method accepts 2 positionals."""

    def provider_with_uri(text: str, uri: str) -> tuple[str, str]:
        return text, uri

    result = call_with_optional_uri(provider_with_uri, "source", "file:///a.yar")
    assert result == ("source", "file:///a.yar")


def test_call_with_optional_uri_falls_back_to_one_arg_method() -> None:
    """call_with_optional_uri omits uri when method only accepts 1 positional."""

    def provider_no_uri(text: str) -> str:
        return text.upper()

    result = call_with_optional_uri(provider_no_uri, "hello", "file:///a.yar")
    assert result == "HELLO"


# ---------------------------------------------------------------------------
# call_range_with_optional_uri: both dispatch paths (line 45 covers the fallback)
# ---------------------------------------------------------------------------


def test_call_range_with_optional_uri_dispatches_three_arg_method() -> None:
    """call_range_with_optional_uri passes (text, range_, uri) for a 3-arg method."""

    def provider_with_uri(text: str, range_: Range, uri: str) -> tuple[str, str]:
        return text, uri

    word_range = _range(0, 4)
    result = call_range_with_optional_uri(provider_with_uri, "data", word_range, "file:///b.yar")
    assert result == ("data", "file:///b.yar")


def test_call_range_with_optional_uri_falls_back_to_two_arg_method() -> None:
    """call_range_with_optional_uri omits uri when method only accepts 2 positionals.

    This is missing line 45 — the fallback return method(text, range_).
    """
    received: list[Any] = []

    def provider_no_uri(text: str, range_: Range) -> str:
        received.append((text, range_))
        return "ok"

    word_range = _range(1, 5)
    result = call_range_with_optional_uri(provider_no_uri, "src", word_range, "file:///c.yar")
    assert result == "ok"
    assert received == [("src", word_range)]


# ===========================================================================
# Section 3 — server_feature_helpers.py
# ===========================================================================

# ---------------------------------------------------------------------------
# get_document_source: runtime present but get_document returns None (line 19->23)
# ---------------------------------------------------------------------------


def _make_server(
    *,
    runtime: Any = None,
    workspace_source: str = "rule r { condition: true }",
) -> SimpleNamespace:
    """Build a minimal server-like object exercising get_document_source paths."""
    workspace_doc = SimpleNamespace(source=workspace_source)
    workspace = SimpleNamespace(get_text_document=lambda _uri: workspace_doc)
    return SimpleNamespace(runtime=runtime, workspace=workspace)


def test_get_document_source_runtime_none_uses_workspace() -> None:
    """get_document_source falls through to workspace when runtime is None."""
    server = _make_server(runtime=None, workspace_source="rule x { condition: true }")
    result = get_document_source(cast(Any, server), "file:///x.yar")
    assert result == "rule x { condition: true }"


def test_get_document_source_runtime_returns_none_document() -> None:
    """get_document_source continues past runtime when get_document returns None.

    This exercises branch 19->23: runtime is not None, but document is None,
    so the fallback_text / workspace path is reached.
    """
    runtime = SimpleNamespace(get_document=lambda *_a, **_k: None)
    server = _make_server(runtime=runtime, workspace_source="rule q { condition: true }")
    result = get_document_source(cast(Any, server), "file:///q.yar")
    assert result == "rule q { condition: true }"


def test_get_document_source_runtime_document_has_non_str_text() -> None:
    """get_document_source skips runtime document when its .text is not a str.

    The isinstance check at line 21 is False; execution falls to fallback_text
    path, then workspace.
    """
    bad_doc = SimpleNamespace(text=b"binary content")  # bytes, not str
    runtime = SimpleNamespace(get_document=lambda *_a, **_k: bad_doc)
    server = _make_server(runtime=runtime, workspace_source="rule w { condition: true }")
    result = get_document_source(cast(Any, server), "file:///w.yar")
    assert result == "rule w { condition: true }"


def test_get_document_source_uses_fallback_text_when_provided() -> None:
    """get_document_source returns fallback_text instead of querying workspace.

    This covers line 24: fallback_text is not None, so we return it early.
    The runtime returns None for the document, causing us to reach line 23.
    """
    runtime = SimpleNamespace(get_document=lambda *_a, **_k: None)
    server = _make_server(runtime=runtime, workspace_source="rule z { condition: false }")
    result = get_document_source(
        cast(Any, server),
        "file:///z.yar",
        fallback_text="rule fallback { condition: true }",
    )
    assert result == "rule fallback { condition: true }"


def test_get_document_source_returns_runtime_document_text_directly() -> None:
    """get_document_source returns document.text from runtime when it is a valid str."""
    doc = SimpleNamespace(text="rule real { condition: true }")
    runtime = SimpleNamespace(get_document=lambda *_a, **_k: doc)
    server = _make_server(runtime=runtime, workspace_source="should not be used")
    result = get_document_source(cast(Any, server), "file:///real.yar")
    assert result == "rule real { condition: true }"


# ---------------------------------------------------------------------------
# get_workspace_folders: branch coverage for non-string URI and None-path
# ---------------------------------------------------------------------------


def test_get_workspace_folders_skips_non_string_folder_uri() -> None:
    """get_workspace_folders must skip folder objects whose uri is not a str.

    This exercises the False branch of 'isinstance(uri, str)' at line 55 (55->53).
    """
    params = SimpleNamespace(
        workspace_folders=[
            SimpleNamespace(uri=None),  # uri is None, not str — must be skipped
            SimpleNamespace(uri=42),  # uri is int — must be skipped
        ],
        root_uri=None,
        root_path=None,
    )
    result = get_workspace_folders(cast(Any, params))
    assert result == []


def test_get_workspace_folders_skips_folder_uri_with_non_localhost_netloc() -> None:
    """get_workspace_folders skips a file: URI whose netloc is not localhost.

    uri_to_path returns None for file://remotehost/path, which causes the
    'if path is not None' guard at line 57 to be False (57->53 arc).
    """
    # file://remotehost/rules resolves to None in uri_to_path (non-localhost netloc)
    params = SimpleNamespace(
        workspace_folders=[SimpleNamespace(uri="file://remotehost/rules")],
        root_uri=None,
        root_path=None,
    )
    result = get_workspace_folders(cast(Any, params))
    assert result == []


def test_get_workspace_folders_includes_valid_file_uri(tmp_path: Any) -> None:
    """get_workspace_folders must include folders with valid file: URIs."""
    params = SimpleNamespace(
        workspace_folders=[SimpleNamespace(uri=tmp_path.as_uri())],
        root_uri=None,
        root_path=None,
    )
    result = get_workspace_folders(cast(Any, params))
    assert str(tmp_path) in result


def test_get_workspace_folders_deduplicates_overlapping_sources(tmp_path: Any) -> None:
    """get_workspace_folders must deduplicate when folder URI and root_uri resolve identically."""
    folder_uri = tmp_path.as_uri()
    params = SimpleNamespace(
        workspace_folders=[SimpleNamespace(uri=folder_uri)],
        root_uri=folder_uri,  # same path — should appear only once
        root_path=None,
    )
    result = get_workspace_folders(cast(Any, params))
    assert result.count(str(tmp_path)) == 1


def test_get_workspace_folders_appends_root_path_string(tmp_path: Any) -> None:
    """get_workspace_folders includes a non-URI root_path as a raw string."""
    raw_path = str(tmp_path)
    params = SimpleNamespace(
        workspace_folders=[],
        root_uri=None,
        root_path=raw_path,
    )
    result = get_workspace_folders(cast(Any, params))
    assert raw_path in result


# ---------------------------------------------------------------------------
# _accepts_positional_count: optional-positional branch (line 25->19, False arm)
# ---------------------------------------------------------------------------


def test_accepts_positional_count_optional_positional_param_not_required() -> None:
    """A function with an optional positional param hits the False arm at line 25.

    When a positional parameter has a default value, line 25
    ('if parameter.default is inspect.Parameter.empty') is False and 'required'
    stays at 0.  The loop continues (25->19 arc) rather than incrementing.
    """

    def optional_fn(text: str, uri: str = "") -> str:
        return text + uri

    # required=0, accepted=2: count=0 (too few) -> False
    assert _accepts_positional_count(optional_fn, 0) is False
    # count=1 is between required(0) and accepted(2) -> True
    assert _accepts_positional_count(optional_fn, 1) is True
    # count=2 exactly at accepted ceiling -> True
    assert _accepts_positional_count(optional_fn, 2) is True
    # count=3 beyond accepted -> False
    assert _accepts_positional_count(optional_fn, 3) is False


# ---------------------------------------------------------------------------
# get_diagnostics / get_semantic_tokens / get_semantic_tokens_range
# These functions in server_feature_helpers delegate to provider methods through
# call_with_optional_uri / call_range_with_optional_uri.
# ---------------------------------------------------------------------------


def _make_full_server(
    *,
    diagnostics: list[Diagnostic] | None = None,
    semantic_tokens_data: list[int] | None = None,
) -> SimpleNamespace:
    """Build a minimal server satisfying get_diagnostics / get_semantic_tokens callers."""
    diag_list: list[Diagnostic] = diagnostics if diagnostics is not None else []
    tokens_data: list[int] = semantic_tokens_data if semantic_tokens_data is not None else []

    diag_provider = SimpleNamespace(get_diagnostics=lambda text, uri: diag_list)
    tokens_provider = SimpleNamespace(
        get_semantic_tokens=lambda text, uri: SemanticTokens(data=tokens_data),
        get_semantic_tokens_range=lambda text, range_, uri: SemanticTokens(data=tokens_data),
    )
    return SimpleNamespace(
        diagnostics_provider=diag_provider,
        semantic_tokens_provider=tokens_provider,
    )


def test_get_diagnostics_returns_provider_result() -> None:
    """get_diagnostics delegates to diagnostics_provider.get_diagnostics via optional URI.

    This covers lines 31-32 in server_feature_helpers.
    """
    server = _make_full_server(diagnostics=[])
    result = get_diagnostics(cast(Any, server), "rule r { condition: true }", "file:///r.yar")
    assert result == []


def test_get_semantic_tokens_returns_provider_result() -> None:
    """get_semantic_tokens delegates to semantic_tokens_provider.get_semantic_tokens.

    This covers lines 36-37 in server_feature_helpers.
    """
    server = _make_full_server(semantic_tokens_data=[1, 2, 3])
    result = get_semantic_tokens(cast(Any, server), "rule r { condition: true }", "file:///r.yar")
    assert isinstance(result, SemanticTokens)
    assert list(result.data) == [1, 2, 3]


def test_get_semantic_tokens_range_returns_provider_result() -> None:
    """get_semantic_tokens_range delegates to semantic_tokens_provider.get_semantic_tokens_range.

    This covers lines 43-44 in server_feature_helpers.
    """
    server = _make_full_server(semantic_tokens_data=[4, 5])
    word_range = _range(0, 10)
    result = get_semantic_tokens_range(
        cast(Any, server), "rule r { condition: true }", "file:///r.yar", word_range
    )
    assert isinstance(result, SemanticTokens)
    assert list(result.data) == [4, 5]
