"""Incremental/runtime tests for the YARAAST LSP runtime."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from lsprotocol.types import Position, Range
import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.lsp.diagnostics import DiagnosticsProvider
from yaraast.lsp.document_query_resolution_ranges import (
    narrow_range_to_name,
    range_contains_position,
)
from yaraast.lsp.document_query_resolution_text import position_is_in_non_code_segment
from yaraast.lsp.document_types import LanguageMode
from yaraast.lsp.runtime import DocumentContext, LspRuntime, RuntimeConfig, path_to_uri
from yaraast.lsp.semantic_tokens import SemanticTokensProvider
from yaraast.lsp.utf16 import utf8_col_to_utf16


def _cache_stats(status: dict[str, object]) -> dict[str, Any]:
    cache_stats = status["cache_stats"]
    assert isinstance(cache_stats, dict)
    return cache_stats


def _string_info(doc: DocumentContext, identifier: str) -> dict[str, Any]:
    info = doc.get_string_definition_info(identifier)
    assert info is not None
    return info


class _ByteStringDocument(DocumentContext):
    def ast(self) -> YaraFile:
        return YaraFile(
            rules=[
                Rule(
                    name="sample",
                    strings=[PlainString(identifier="$a", value=b'ab"\x00\xff')],
                )
            ]
        )


def test_runtime_persists_workspace_symbol_index(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text(
        """
rule sample {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    runtime.get_document(path_to_uri(rule_file))

    cache_file = tmp_path / ".yaraast" / "lsp-workspace-index.json"
    assert cache_file.exists()

    payload = json.loads(cache_file.read_text(encoding="utf-8"))
    assert any(
        symbol["name"] == "sample" for symbols in payload["symbols"].values() for symbol in symbols
    )

    second_runtime = LspRuntime()
    second_runtime.set_workspace_folders([str(tmp_path)])
    names = {symbol.name for symbol in second_runtime.workspace_symbols("")}
    assert {"sample", "$a"} <= names


def test_runtime_update_config_rejects_non_mapping_settings() -> None:
    runtime = LspRuntime()

    runtime.update_config(None)
    runtime.update_config({})

    invalid_settings: tuple[Any, ...] = ([], "", "YARA")
    for settings in invalid_settings:
        with pytest.raises(TypeError, match="LSP runtime settings must be a dictionary"):
            runtime.update_config(cast(Any, settings))


@pytest.mark.parametrize("dialect_mode", ["", "unknown", 123, None, object()])
def test_runtime_update_config_ignores_invalid_dialect_modes(dialect_mode: Any) -> None:
    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yarax"}})

    runtime.update_config({"YARA": {"dialectMode": dialect_mode}})

    assert runtime.config.language_mode == LanguageMode.YARA_X


def test_runtime_workspace_symbols_ignore_persisted_index_when_cache_disabled(
    tmp_path: Path,
) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule cached_old { condition: true }\n", encoding="utf-8")

    cached_runtime = LspRuntime()
    cached_runtime.set_workspace_folders([str(tmp_path)])
    cached_runtime.get_document(path_to_uri(rule_file))

    rule_file.write_text("rule current_disk { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.update_config({"YARA": {"cacheWorkspace": False}})
    runtime.set_workspace_folders([str(tmp_path)])

    names = {symbol.name for symbol in runtime.workspace_symbols("")}
    assert "current_disk" in names
    assert "cached_old" not in names


def test_runtime_get_document_invalidates_workspace_symbol_cache(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule loaded_later { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(rule_file)

    runtime = LspRuntime()
    assert runtime.workspace_symbols("") == []

    runtime.get_document(uri)

    names = {symbol.name for symbol in runtime.workspace_symbols("")}
    assert "loaded_later" in names


def test_runtime_workspace_symbol_queries_reject_non_strings_before_cache_update() -> None:
    runtime = LspRuntime()
    runtime.open_document("file:///sample.yar", "rule sample { condition: true }\n")

    with pytest.raises(TypeError, match="Workspace symbol query must be a string"):
        runtime.workspace_symbols(cast(Any, object()))

    with pytest.raises(TypeError, match="Workspace symbol query must be a string"):
        runtime.workspace_symbol_records(cast(Any, object()))

    assert runtime.cache.workspace_symbol_cache == {}


def test_runtime_latency_metrics_and_debounce() -> None:
    runtime = LspRuntime()
    runtime.record_latency("diagnostics", 10.0)
    runtime.record_latency("diagnostics", 20.0)

    metrics = runtime.get_latency_metrics()
    assert metrics["diagnostics"]["count"] == 2.0
    assert metrics["diagnostics"]["avg_ms"] == 15.0

    uri = "file:///sample.yar"
    assert runtime.should_debounce(uri, "push_diagnostics", debounce_ms=100) is False
    assert runtime.should_debounce(uri, "push_diagnostics", debounce_ms=100) is True

    status = runtime.get_status()
    cache_stats = _cache_stats(status)
    assert cache_stats["workspace_generation"] >= 0
    assert cache_stats["workspace_symbol_queries"] == 0
    assert cache_stats["rule_definition_entries"] == 0
    assert cache_stats["rule_reference_entries"] == 0
    assert cache_stats["rule_reference_record_entries"] == 0
    assert cache_stats["document_analysis_entries"] == 0


def test_runtime_status_and_workspace_symbols_handle_dirty_open_document(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text(
        """
rule sample {
  condition:
    true
}
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    runtime.get_document(uri)
    runtime.open_document(
        uri,
        """
rule sample {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip(),
        version=2,
    )

    status = runtime.get_status()
    assert status["dirty_documents"] == 1
    assert str(tmp_path / ".yaraast" / "lsp-workspace-index.json") == status["index_path"]

    names = [symbol.name for symbol in runtime.workspace_symbols("")]
    assert names.count("sample") == 1
    assert "$a" in names

    loaded_doc = runtime.get_document(uri)
    assert loaded_doc is not None
    doc = runtime.ensure_document(uri, loaded_doc.text)
    sections = {(symbol.kind, symbol.name, symbol.container_name) for symbol in doc.symbols()}
    assert ("section", "strings", "sample") in sections
    assert ("section_header", "strings", "sample") in sections
    assert ("section", "condition", "sample") in sections
    assert ("section_header", "condition", "sample") in sections
    assert ("rule_block", "sample", None) in sections


def test_document_context_ignores_section_names_inside_literals() -> None:
    text = """
rule sample {
  strings:
    $a = "condition: decoy"
  condition:
    $a
}
""".lstrip()
    doc = DocumentContext("file://sample.yar", text)

    condition_header = doc.find_symbol_record("section_header", "condition", "sample")
    condition_section = doc.find_symbol_record("section", "condition", "sample")

    assert condition_header is not None
    assert condition_header.range.start.line == 3
    assert condition_header.range.start.character == 2
    assert condition_section is not None
    assert condition_section.range.start.line == 3


def test_runtime_workspace_symbol_cache_invalidates_on_document_change(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule sample { condition: true }\n", encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    uri = path_to_uri(rule_file)
    runtime.open_document(uri, rule_file.read_text(encoding="utf-8"), version=1)

    first = runtime.workspace_symbol_records("")
    second = runtime.workspace_symbol_records("")
    assert [record.name for record in first] == [record.name for record in second]
    assert runtime.cache.workspace_symbol_cache

    runtime.update_document(uri, 'rule sample { strings: $a = "x" condition: $a }\n', version=2)
    third = runtime.workspace_symbol_records("")

    assert "$a" in [record.name for record in third]


def test_document_context_symbol_indexes_invalidate_on_update() -> None:
    runtime = LspRuntime()
    uri = "file:///sample.yar"
    text_v1 = 'import "pe"\nrule sample { condition: true }\n'
    text_v2 = 'include "common.yar"\nrule beta { condition: true }\n'

    doc = runtime.ensure_document(uri, text_v1)
    assert doc.get_import_modules() == ["pe"]
    assert doc.get_rule_names() == ["sample"]
    assert doc.find_symbol_record("import", "pe") is not None

    doc.update(text_v2, version=2)

    assert doc.get_import_modules() == []
    assert doc.get_include_paths() == ["common.yar"]
    assert doc.get_rule_names() == ["beta"]
    assert doc.find_symbol_record("import", "pe") is None
    assert doc.find_symbol_record("include", "common.yar") is not None


def test_document_context_rejects_invalid_text_inputs() -> None:
    with pytest.raises(TypeError, match="Document text must be a string"):
        DocumentContext("file://sample.yar", cast(Any, object()))

    doc = DocumentContext("file://sample.yar", "rule r { condition: true }")

    with pytest.raises(TypeError, match="Document text must be a string"):
        doc.update(cast(Any, object()))


def test_document_context_constructor_rejects_invalid_state_inputs() -> None:
    with pytest.raises(TypeError, match="Document is_open flag must be a boolean"):
        DocumentContext(
            "file://sample.yar",
            "rule r { condition: true }",
            is_open=cast(Any, "yes"),
        )

    with pytest.raises(TypeError, match="Document language_mode must be a LanguageMode"):
        DocumentContext(
            "file://sample.yar",
            "rule r { condition: true }",
            language_mode=cast(Any, object()),
        )


def test_runtime_rejects_invalid_document_uri_inputs() -> None:
    runtime = LspRuntime()
    invalid_uri = cast(str, object())

    with pytest.raises(TypeError, match="Document URI must be a string"):
        runtime.open_document(invalid_uri, "rule r { condition: true }")

    with pytest.raises(TypeError, match="Document URI must be a string"):
        runtime.update_document(invalid_uri, "rule r { condition: true }")

    with pytest.raises(TypeError, match="Document URI must be a string"):
        runtime.ensure_document(invalid_uri, "rule r { condition: true }")

    with pytest.raises(TypeError, match="Document URI must be a string"):
        runtime.save_document(invalid_uri)

    with pytest.raises(TypeError, match="Document URI must be a string"):
        runtime.get_document(invalid_uri)

    with pytest.raises(TypeError, match="Document URI must be a string"):
        runtime.close_document(invalid_uri)


def test_runtime_rejects_invalid_config_inputs() -> None:
    with pytest.raises(TypeError, match="LSP runtime config must be a RuntimeConfig"):
        LspRuntime(config=cast(Any, object()))

    with pytest.raises(TypeError, match="RuntimeConfig cache_workspace must be a boolean"):
        RuntimeConfig(cache_workspace=cast(Any, "yes"))

    with pytest.raises(
        TypeError, match="RuntimeConfig rule_name_validation must be a string or None"
    ):
        RuntimeConfig(rule_name_validation=cast(Any, object()))

    with pytest.raises(TypeError, match="RuntimeConfig metadata_validation must be a list"):
        RuntimeConfig(metadata_validation=cast(Any, object()))

    with pytest.raises(TypeError, match="RuntimeConfig code_formatting must be a dictionary"):
        RuntimeConfig(code_formatting=cast(Any, object()))

    with pytest.raises(TypeError, match="RuntimeConfig language_mode must be a LanguageMode"):
        RuntimeConfig(language_mode=cast(Any, object()))

    with pytest.raises(TypeError, match="RuntimeConfig diagnostics_debounce_ms must be an integer"):
        RuntimeConfig(diagnostics_debounce_ms=cast(Any, True))

    with pytest.raises(
        ValueError, match="RuntimeConfig diagnostics_debounce_ms must be non-negative"
    ):
        RuntimeConfig(diagnostics_debounce_ms=-1)


def test_document_context_rule_scope_excludes_range_end_position() -> None:
    text = "rule sample { condition: true }\nrule other { condition: true }\n"
    doc = DocumentContext("file://sample.yar", text)

    assert doc.rule_name_at_position(Position(line=0, character=30)) == "sample"
    assert doc.rule_name_at_position(Position(line=0, character=31)) is None
    assert doc.rule_name_at_position(Position(line=1, character=0)) == "other"


def test_lsp_range_contains_position_uses_exclusive_end() -> None:
    range_ = Range(start=Position(line=0, character=5), end=Position(line=0, character=11))

    assert range_contains_position(range_, Position(line=0, character=5)) is True
    assert range_contains_position(range_, Position(line=0, character=10)) is True
    assert range_contains_position(range_, Position(line=0, character=11)) is False


def test_runtime_indexes_yaral_sections_as_section_symbols(tmp_path: Path) -> None:
    rule_file = tmp_path / "login.yar"
    text = """
rule login_event {
  events:
    $e.metadata.event_type = "USER_LOGIN"
  match:
    $e over 5m
  outcome:
    $risk = 80
  condition:
    $e
}
""".lstrip()
    rule_file.write_text(text, encoding="utf-8")

    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yaral"}})
    uri = path_to_uri(rule_file)
    doc = runtime.ensure_document(uri, text)

    sections = {(symbol.kind, symbol.name, symbol.container_name) for symbol in doc.symbols()}
    assert ("section", "events", "login_event") in sections
    assert ("section_header", "events", "login_event") in sections
    assert ("section", "match", "login_event") in sections
    assert ("section", "outcome", "login_event") in sections
    assert ("section", "condition", "login_event") in sections

    events_record = next(
        symbol
        for symbol in doc.symbols()
        if symbol.kind == "section"
        and symbol.name == "events"
        and symbol.container_name == "login_event"
    )
    match_record = next(
        symbol
        for symbol in doc.symbols()
        if symbol.kind == "section"
        and symbol.name == "match"
        and symbol.container_name == "login_event"
    )
    assert events_record.range.start.line == 1
    assert events_record.range.end.line == 2
    assert match_record.range.start.line == 3
    assert match_record.range.end.line == 4


def test_document_context_get_rule_info_includes_structural_summary(tmp_path: Path) -> None:
    doc_path = tmp_path / "doc.yar"
    text = """
rule sample : a b {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    info = doc.get_rule_info("sample")
    assert info is not None
    assert info["name"] == "sample"
    assert info["tags"] == ["a", "b"]
    assert info["strings_count"] == 1
    assert ("author", "me") in info["meta"]


def test_document_context_exposes_rule_meta_items_and_string_identifiers(tmp_path: Path) -> None:
    doc_path = tmp_path / "doc.yar"
    text = """
rule sample {
  meta:
    author = "me"
    family = "demo"
  strings:
    $a = "x"
    $b = "y"
  condition:
    $a and $b
}
""".lstrip()
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    assert doc.get_rule_meta_items("sample") == [("author", "me"), ("family", "demo")]
    assert doc.get_rule_string_identifiers("sample") == ["$a", "$b"]
    assert doc.get_rule_sections("sample") == ["meta", "strings", "condition"]


def test_document_context_hides_anonymous_string_internal_ids() -> None:
    text = """
rule sample {
  strings:
    $a = "x"
    $ = "one"
    $ = "two"
  condition:
    true
}
""".lstrip()
    doc = DocumentContext("file://sample.yar", text)

    string_symbols = [
        symbol
        for symbol in doc.symbols()
        if symbol.kind == "string" and symbol.container_name == "sample"
    ]

    assert [symbol.name for symbol in string_symbols] == ["$a", "$", "$"]
    assert doc.get_rule_string_identifiers("sample") == ["$a", "$", "$"]
    assert doc.find_string_definition("$anon_1") is None
    assert doc.get_string_definition_info("$anon_1") is None
    assert string_symbols[1].range.start.line == 3
    assert string_symbols[1].range.start.character == 4
    assert string_symbols[1].range.end.character == 5


def test_document_context_returns_line_and_symbol_snapshots() -> None:
    text = "rule sample { condition: true }\n"
    doc = DocumentContext("file://sample.yar", text)

    lines = doc.lines
    symbols = doc.symbols()
    assert lines
    assert symbols

    lines.clear()
    symbols.clear()

    assert doc.lines
    assert doc.symbols()


def test_document_context_caches_structural_helpers_per_revision(tmp_path: Path) -> None:
    doc_path = tmp_path / "doc.yar"
    text_v1 = """
rule sample {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    text_v2 = """
rule sample {
  meta:
    author = "you"
  strings:
    $b = "y"
  condition:
    $b
}
""".lstrip()
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text_v1, version=1)
    doc = runtime.ensure_document(uri, text_v1)

    info_first = doc.get_rule_info("sample")
    info_second = doc.get_rule_info("sample")
    assert info_first == info_second
    assert info_first is not None
    info_first["name"] = "corrupted"
    assert doc.get_rule_info("sample") == info_second

    meta_items = doc.get_rule_meta_items("sample")
    assert meta_items == [("author", "me")]
    meta_items.clear()
    assert doc.get_rule_meta_items("sample") == [("author", "me")]

    string_ids = doc.get_rule_string_identifiers("sample")
    assert string_ids == ["$a"]
    string_ids.clear()
    assert doc.get_rule_string_identifiers("sample") == ["$a"]

    sections = doc.get_rule_sections("sample")
    assert sections == ["meta", "strings", "condition"]
    sections.clear()
    assert doc.get_rule_sections("sample") == ["meta", "strings", "condition"]

    string_info = _string_info(doc, "$a")
    assert string_info["value"] == "x"
    string_info["value"] = "corrupted"
    assert _string_info(doc, "$a")["value"] == "x"

    doc.update(text_v2, version=2)

    info_third = doc.get_rule_info("sample")
    assert info_third is not info_first
    assert doc.get_rule_meta_items("sample") == [("author", "you")]
    assert doc.get_rule_string_identifiers("sample") == ["$b"]
    assert _string_info(doc, "$b")["value"] == "y"


def test_document_context_string_info_byte_plain_string_is_json_safe() -> None:
    doc = _ByteStringDocument("file:///bytes.yar", "")

    info = _string_info(doc, "$a")

    assert info["value"] == 'ab\\"\\x00\\xff'
    assert json.loads(json.dumps(info))["value"] == 'ab\\"\\x00\\xff'


def test_document_context_caches_local_navigation_helpers_per_revision() -> None:
    runtime = LspRuntime()
    uri = "file:///sample.yar"
    text_v1 = """
rule a { condition: true }
rule b { condition: a }
""".lstrip()
    text_v2 = """
rule c { condition: true }
rule d { condition: c }
""".lstrip()

    doc = runtime.ensure_document(uri, text_v1)

    rule_def_first = doc.find_rule_definition("a")
    rule_def_second = doc.find_rule_definition("a")
    assert rule_def_first == rule_def_second
    assert rule_def_first is not None
    rule_def_first.uri = "file:///corrupted.yar"
    assert doc.find_rule_definition("a") == rule_def_second

    rule_refs_first = doc.rule_reference_records("a")
    rule_refs_second = doc.rule_reference_records("a")
    assert rule_refs_first == rule_refs_second
    assert {record.role for record in rule_refs_first} == {"declaration", "use"}
    rule_refs_first[0].role = "corrupted"
    assert doc.rule_reference_records("a") == rule_refs_second
    rule_refs_first.clear()
    assert doc.rule_reference_records("a") == rule_refs_second

    doc.update(text_v2, version=2)

    rule_def_third = doc.find_rule_definition("c")
    assert rule_def_third is not rule_def_first
    rule_refs_third = doc.rule_reference_records("c")
    assert rule_refs_third is not rule_refs_first
    assert {record.role for record in rule_refs_third} == {"declaration", "use"}


def test_document_context_caches_string_reference_helpers_per_revision() -> None:
    runtime = LspRuntime()
    uri = "file:///sample.yar"
    text_v1 = """
rule a {
  strings:
    $a = "x"
  condition:
    $a and #a > 0
}
""".lstrip()
    text_v2 = """
rule a {
  strings:
    $b = "y"
  condition:
    $b and #b > 0
}
""".lstrip()

    doc = runtime.ensure_document(uri, text_v1)

    refs_first = doc.find_string_reference_records("$a")
    refs_second = doc.find_string_reference_records("$a")
    assert refs_first == refs_second
    assert {record.role for record in refs_first} == {"declaration", "read"}
    refs_first[0].role = "corrupted"
    assert doc.find_string_reference_records("$a") == refs_second
    refs_first.clear()
    assert doc.find_string_reference_records("$a") == refs_second

    doc.update(text_v2, version=2)

    refs_third = doc.find_string_reference_records("$b")
    assert refs_third is not refs_first
    assert {record.role for record in refs_third} == {"declaration", "read"}


def test_document_context_exposes_top_level_modules_includes_and_rules(tmp_path: Path) -> None:
    doc_path = tmp_path / "doc.yar"
    text = """
import "pe"
include "common.yar"

rule alpha { condition: true }
rule beta { condition: true }
""".lstrip()
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    assert doc.get_import_modules() == ["pe"]
    assert doc.get_include_paths() == ["common.yar"]
    assert doc.get_rule_names() == ["alpha", "beta"]


def test_document_context_reference_records_skip_comments_and_string_literals() -> None:
    runtime = LspRuntime()
    text = """
rule alpha {
  strings:
    $a = "literal alpha // not a reference"
    $msg = "mention $a in a literal"
  condition:
    // alpha and $a in comment
    alpha and $a
}
""".lstrip()
    doc = runtime.ensure_document("file:///references.yar", text)

    rule_records = doc.rule_reference_records("alpha")
    string_records = doc.find_string_reference_records("$a")

    assert len(rule_records) == 2
    assert {record.role for record in rule_records} == {"declaration", "use"}
    assert len(string_records) == 2
    assert {record.role for record in string_records} == {"declaration", "read"}


def test_document_context_reference_records_validate_resolved_symbol_kind() -> None:
    runtime = LspRuntime()
    text = """
rule alpha {
  condition:
    alpha and alphabet and alpha_count
}
""".lstrip()
    doc = runtime.ensure_document("file:///resolved-symbols.yar", text)

    records = doc.rule_reference_records("alpha")

    assert len(records) == 2
    assert {record.role for record in records} == {"declaration", "use"}


def test_document_context_rule_reference_ranges_cover_full_identifier() -> None:
    runtime = LspRuntime()
    text = """
rule alpha {
  condition:
    true
}

rule beta {
  condition:
    filesize \\ 2 > alpha
}
""".lstrip()
    doc = runtime.ensure_document("file:///rule-reference-range.yar", text)

    uses = [
        record.location.range
        for record in doc.rule_reference_records("alpha", include_declaration=False)
    ]

    assert len(uses) == 1
    assert uses[0].end.character - uses[0].start.character == len("alpha")


def test_narrow_range_to_name_keeps_range_for_empty_name() -> None:
    doc = DocumentContext("file:///range.yar", "rule alpha { condition: true }")
    node_range = Range(Position(line=0, character=5), Position(line=0, character=10))

    assert narrow_range_to_name(doc, node_range, "") == node_range


def test_document_context_rule_reference_ranges_use_utf16_columns() -> None:
    runtime = LspRuntime()
    text = """
rule sample {
  condition:
    /* 😀😀 */ sample
}
""".lstrip()
    line = text.splitlines()[2]
    reference_start = line.index("sample")
    reference_end = reference_start + len("sample")
    doc = runtime.ensure_document("file:///rule-reference-utf16.yar", text)

    uses = [
        record.location.range
        for record in doc.rule_reference_records("sample", include_declaration=False)
    ]

    assert len(uses) == 1
    assert uses[0].start.character == utf8_col_to_utf16(line, reference_start)
    assert uses[0].end.character == utf8_col_to_utf16(line, reference_end)


def test_document_context_reference_records_use_ast_spans_for_string_count_and_length() -> None:
    runtime = LspRuntime()
    text = """
rule sample {
  strings:
    $a = "x"
  condition:
    #a > 0 and !a > 0 and @a == 1
}
""".lstrip()
    doc = runtime.ensure_document("file:///ast-refs.yar", text)

    records = doc.find_string_reference_records("$a")

    assert len(records) == 4
    assert {record.role for record in records} == {"declaration", "read"}


def test_document_context_exposes_module_info() -> None:
    runtime = LspRuntime()
    doc = runtime.ensure_document(
        "file://sample.yar", 'import "pe"\nrule sample { condition: true }\n'
    )

    info = doc.get_module_info("pe")

    assert info is not None
    assert info["name"] == "pe"
    assert "PE file format module" in info["description"]


def test_document_context_exposes_module_member_info_for_imported_modules() -> None:
    text = 'import "pe"\nrule sample { condition: pe.imphash() }\n'
    runtime = LspRuntime()
    uri = "file://sample.yar"
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    info = doc.get_module_member_info("pe.imphash")

    assert info is not None
    assert info["module"] == "pe"
    assert info["member"] == "imphash"
    assert info["kind"] == "function"
    info["member"] = "corrupted"
    cached_info = doc.get_module_member_info("pe.imphash")
    assert cached_info is not None
    assert cached_info["member"] == "imphash"


def test_document_context_exposes_include_info(tmp_path: Path) -> None:
    include_file = tmp_path / "common.yar"
    include_file.write_text("rule common { condition: true }\n", encoding="utf-8")
    doc_path = tmp_path / "sample.yar"
    text = 'include "common.yar"\nrule sample { condition: true }\n'
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    info = doc.get_include_info("common.yar")

    assert info["path"] == "common.yar"
    assert info["resolved_path"] == str(include_file.resolve())
    info["path"] = "corrupted.yar"
    assert doc.get_include_info("common.yar")["path"] == "common.yar"


def test_document_context_exposes_dotted_symbol_at_position() -> None:
    text = 'import "pe"\nrule sample { condition: pe.imphash() }\n'
    runtime = LspRuntime()
    uri = "file://sample.yar"
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    dotted = doc.get_dotted_symbol_at_position(Position(line=1, character=35))

    assert dotted is not None
    token, dotted_range = dotted
    assert token == "pe.imphash"
    assert dotted_range.start.line == 1

    trailing_line = "rule sample { condition: pe.imphash"
    trailing_text = f'import "pe"\n{trailing_line}'
    trailing_runtime = LspRuntime()
    trailing_uri = "file://trailing.yar"
    trailing_runtime.open_document(trailing_uri, trailing_text)
    trailing_doc = trailing_runtime.ensure_document(trailing_uri, trailing_text)

    trailing_dotted = trailing_doc.get_dotted_symbol_at_position(
        Position(line=1, character=len(trailing_line))
    )

    assert trailing_dotted is not None
    trailing_token, trailing_range = trailing_dotted
    assert trailing_token == "pe.imphash"
    assert trailing_range.end.character == len(trailing_line)


def test_dotted_symbol_lookup_uses_utf16_position_and_range() -> None:
    text = 'import "pe"\nrule sample { condition: /* 😀 */ pe.imphash() }\n'
    line = text.splitlines()[1]
    token_start = line.index("pe.imphash")
    token_end = token_start + len("pe.imphash")
    lsp_token_start = utf8_col_to_utf16(line, token_start)
    lsp_token_end = utf8_col_to_utf16(line, token_end)
    runtime = LspRuntime()
    uri = "file://sample.yar"
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    dotted = doc.get_dotted_symbol_at_position(Position(line=1, character=lsp_token_end))

    assert dotted is not None
    token, dotted_range = dotted
    assert token == "pe.imphash"
    assert dotted_range.start.character == lsp_token_start
    assert dotted_range.end.character == lsp_token_end


def test_runtime_indexes_import_and_include_with_quoted_ranges(tmp_path: Path) -> None:
    include_path = tmp_path / "common.yar"
    include_path.write_text("rule shared { condition: true }\n", encoding="utf-8")
    doc_path = tmp_path / "doc.yar"
    text = 'import "pe"\ninclude "common.yar"\nrule sample { condition: true }\n'
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)
    symbols = doc.symbols()

    import_record = next(
        symbol for symbol in symbols if symbol.kind == "import" and symbol.name == "pe"
    )
    include_record = next(
        symbol for symbol in symbols if symbol.kind == "include" and symbol.name == "common.yar"
    )

    assert import_record.range.start.line == 0
    assert import_record.range.start.character == 8
    assert import_record.range.end.character == 10

    assert include_record.range.start.line == 1
    assert include_record.range.start.character == 9
    assert include_record.range.end.character == 19


def test_runtime_indexes_import_ranges_as_utf16_columns() -> None:
    text = '/* 😀 */ import "pe"\nrule sample { condition: true }\n'
    line = text.splitlines()[0]
    module_start = line.index("pe")
    module_end = module_start + len("pe")
    doc = DocumentContext("file://utf16-import.yar", text)

    import_record = next(
        symbol for symbol in doc.symbols() if symbol.kind == "import" and symbol.name == "pe"
    )

    assert import_record.range.start.character == utf8_col_to_utf16(line, module_start)
    assert import_record.range.end.character == utf8_col_to_utf16(line, module_end)


def test_runtime_indexes_section_header_ranges_as_utf16_columns() -> None:
    text = """
rule sample {
  /* 😀 */ strings:
    $a = "x"
  condition:
    true
}
""".lstrip()
    line = text.splitlines()[1]
    header_start = line.index("strings")
    header_end = header_start + len("strings")
    doc = DocumentContext("file://utf16-section.yar", text)

    header_record = next(
        symbol
        for symbol in doc.symbols()
        if symbol.kind == "section_header" and symbol.name == "strings"
    )

    assert header_record.range.start.character == utf8_col_to_utf16(line, header_start)
    assert header_record.range.end.character == utf8_col_to_utf16(line, header_end)


def test_runtime_indexes_string_symbol_ranges_as_utf16_columns() -> None:
    text = """
rule sample {
  strings:
    /* 😀 */ $a = "x"
  condition:
    $a
}
""".lstrip()
    line = text.splitlines()[2]
    string_start = line.index("$a")
    string_end = string_start + len("$a")
    doc = DocumentContext("file://utf16-string-symbol.yar", text)

    string_record = next(
        symbol for symbol in doc.symbols() if symbol.kind == "string" and symbol.name == "$a"
    )

    assert string_record.range.start.character == utf8_col_to_utf16(line, string_start)
    assert string_record.range.end.character == utf8_col_to_utf16(line, string_end)


def test_runtime_resolve_symbol_prefers_symbol_records(tmp_path: Path) -> None:
    doc_path = tmp_path / "doc.yar"
    text = """
import "pe"

rule sample {
  strings:
    $a = "x"
  condition:
    $a and pe.is_pe
}
""".lstrip()
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    imported = doc.resolve_symbol(Position(line=0, character=9))
    rule = doc.resolve_symbol(Position(line=2, character=6))
    string_def = doc.resolve_symbol(Position(line=4, character=5))

    assert imported is not None and imported.kind == "module" and imported.normalized_name == "pe"
    assert rule is not None and rule.kind == "rule" and rule.normalized_name == "sample"
    assert (
        string_def is not None
        and string_def.kind == "string"
        and string_def.normalized_name == "$a"
    )


def test_runtime_resolve_symbol_checks_non_code_segments_with_utf16_columns() -> None:
    text = 'import "pe"\nrule sample { condition: /* 😀 */ pe.imphash/*comment*/ }\n'
    line = text.splitlines()[1]
    member_end = line.index("pe.imphash") + len("pe.imphash")
    doc = DocumentContext("file://utf16-non-code.yar", text)

    resolved = doc.resolve_symbol(Position(line=1, character=utf8_col_to_utf16(line, member_end)))

    assert resolved is not None
    assert resolved.kind == "module_member"
    assert resolved.normalized_name == "pe.imphash"


def test_runtime_resolve_ast_symbol_ranges_use_utf16_columns() -> None:
    text = """
import "pe"

rule sample {
  condition:
    /* 😀😀 */ pe.is_pe
}
""".lstrip()
    line = text.splitlines()[4]
    member_start = line.index("pe.is_pe")
    member_end = member_start + len("pe.is_pe")
    doc = DocumentContext("file://utf16-ast-symbol.yar", text)

    resolved = doc.resolve_symbol(
        Position(line=4, character=utf8_col_to_utf16(line, member_start + 3))
    )

    assert resolved is not None
    assert resolved.kind == "module_member"
    assert resolved.normalized_name == "pe.is_pe"
    assert resolved.range.start.character == utf8_col_to_utf16(line, member_start)
    assert resolved.range.end.character == utf8_col_to_utf16(line, member_end)


def test_runtime_ast_symbol_ranges_use_exclusive_end_columns() -> None:
    text = "rule sample { condition: /* 😀😀 */ 1 + 2 }\n"
    line = text.splitlines()[0]
    expression_end = line.index("2") + len("2")
    doc = DocumentContext("file://exclusive-ast-symbol.yar", text)

    condition = doc.find_symbol_record("condition", "condition", "sample")

    assert condition is not None
    assert condition.range.end.character == utf8_col_to_utf16(line, expression_end)


def test_runtime_resolve_string_operator_ranges_use_utf16_columns() -> None:
    text = """
rule sample {
  strings:
    $a = "x"
  condition:
    /* 😀😀 */ #a > 0
}
""".lstrip()
    line = text.splitlines()[4]
    reference_start = line.index("#a")
    reference_end = reference_start + len("#a")
    doc = DocumentContext("file://utf16-string-operator.yar", text)

    resolved = doc.resolve_symbol(
        Position(line=4, character=utf8_col_to_utf16(line, reference_start + 1))
    )

    assert resolved is not None
    assert resolved.kind == "string"
    assert resolved.normalized_name == "$a"
    assert resolved.range.start.character == utf8_col_to_utf16(line, reference_start)
    assert resolved.range.end.character == utf8_col_to_utf16(line, reference_end)


def test_runtime_resolves_module_member_structurally(tmp_path: Path) -> None:
    doc_path = tmp_path / "doc.yar"
    text = """
import "pe"

rule sample {
  condition:
    pe.is_pe
}
""".lstrip()
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    resolved = doc.resolve_symbol(Position(line=4, character=7))
    assert resolved is not None
    assert resolved.kind == "module_member"
    assert resolved.normalized_name == "pe.is_pe"
    assert resolved.range.start.line == 4
    assert resolved.range.start.character == 4
    assert resolved.range.end.character == 12


def test_text_resolution_does_not_treat_division_as_regex(tmp_path: Path) -> None:
    doc_path = tmp_path / "doc.yar"
    text = """
rule sample {
  condition:
    filesize \\ 2 > 0 and other_rule
}
rule other_rule { condition: true }
""".lstrip()
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    resolved = doc.resolve_symbol(Position(line=2, character=29))

    assert resolved is not None
    assert resolved.kind == "rule"
    assert resolved.normalized_name == "other_rule"

    assert position_is_in_non_code_segment(doc, Position(line=2, character=29)) is False


def test_runtime_indexes_meta_keys_with_exact_ranges(tmp_path: Path) -> None:
    doc_path = tmp_path / "doc.yar"
    text = """
rule sample {
  meta:
    author = "me"
  condition:
    true
}
""".lstrip()
    uri = path_to_uri(doc_path)

    runtime = LspRuntime()
    runtime.open_document(uri, text)
    doc = runtime.ensure_document(uri, text)

    meta_record = next(
        symbol
        for symbol in doc.symbols()
        if symbol.kind == "meta" and symbol.name == "author" and symbol.container_name == "sample"
    )
    assert meta_record.range.start.line == 2
    assert meta_record.range.start.character == 4
    assert meta_record.range.end.character == 10


def test_diagnostics_provider_uses_runtime_cache_and_skips_classic_validation_for_yaral() -> None:
    text = """
rule login_event {
  meta:
    author = "sec"
  events:
    $e.metadata.event_type = "USER_LOGIN"
  match:
    $e over 5m
  condition:
    $e
}
""".lstrip()
    uri = "file:///login.yar"

    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yaral"}})
    provider = DiagnosticsProvider(runtime)

    diagnostics = provider.get_diagnostics(text, uri)
    diagnostics_again = provider.get_diagnostics(text, uri)

    assert diagnostics == []
    assert diagnostics_again == diagnostics

    broken_uri = "file:///broken.yar"
    broken_first = provider.get_diagnostics("rule {", broken_uri)
    broken_second = provider.get_diagnostics("rule {", broken_uri)
    assert broken_first == broken_second
    assert broken_first
    broken_first.clear()
    assert provider.get_diagnostics("rule {", broken_uri) == broken_second


def test_semantic_tokens_provider_caches_full_and_range_results() -> None:
    text = """
rule sample {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    uri = "file:///sample.yar"

    runtime = LspRuntime()
    provider = SemanticTokensProvider(runtime)

    full_a = provider.get_semantic_tokens(text, uri)
    full_b = provider.get_semantic_tokens(text, uri)
    assert full_a == full_b
    full_a.data = []
    assert provider.get_semantic_tokens(text, uri) == full_b

    range_ = Range(start=Position(line=2, character=0), end=Position(line=3, character=20))
    range_a = provider.get_semantic_tokens_range(text, range_, uri)
    range_b = provider.get_semantic_tokens_range(text, range_, uri)
    assert range_a == range_b
    range_a.data = []
    assert provider.get_semantic_tokens_range(text, range_, uri) == range_b

    metrics = runtime.get_latency_metrics()
    assert "semantic_tokens_full" in metrics
    assert "semantic_tokens_range" in metrics


def test_document_context_caches_resolve_symbol_per_revision() -> None:
    runtime = LspRuntime()
    uri = "file:///sample.yar"
    text_v1 = """
rule sample {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    text_v2 = """
rule sample {
  strings:
    $b = "y"
  condition:
    $b
}
""".lstrip()

    doc = runtime.ensure_document(uri, text_v1)

    first = doc.resolve_symbol(Position(line=2, character=5))
    second = doc.resolve_symbol(Position(line=2, character=5))
    assert first == second
    assert first is not None
    assert first.normalized_name == "$a"
    first.normalized_name = "$corrupted"
    assert doc.resolve_symbol(Position(line=2, character=5)) == second

    doc.update(text_v2, version=2)

    third = doc.resolve_symbol(Position(line=2, character=5))
    assert third is not first
    assert third is not None
    assert third.normalized_name == "$b"


def test_runtime_caches_rule_link_records_per_document_and_invalidates_on_update(
    tmp_path: Path,
) -> None:
    rule_file = tmp_path / "sample.yar"
    text_v1 = """
rule target { condition: true }
rule sample { condition: target }
""".lstrip()
    text_v2 = """
rule target { condition: true }
rule sample { condition: true }
""".lstrip()
    rule_file.write_text(text_v1, encoding="utf-8")
    uri = path_to_uri(rule_file)

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    runtime.open_document(uri, text_v1, version=1)

    first = runtime.get_rule_link_records_for_document(uri)
    second = runtime.get_rule_link_records_for_document(uri)
    assert first == second
    assert len(first) == 1
    assert first[0].rule_name == "target"
    first[0].rule_name = "corrupted"
    assert runtime.get_rule_link_records_for_document(uri) == second
    first.clear()
    assert runtime.get_rule_link_records_for_document(uri) == second

    runtime.update_document(uri, text_v2, version=2)

    third = runtime.get_rule_link_records_for_document(uri)
    assert third == []


def test_runtime_rule_link_records_handle_missing_loaded_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule_file = tmp_path / "missing.yar"
    rule_file.write_text("rule sample { condition: true }\n", encoding="utf-8")
    uri = path_to_uri(rule_file)
    runtime = LspRuntime()

    def missing_document(_uri: str, *, load_workspace: bool = True) -> None:
        return None

    monkeypatch.setattr(runtime, "get_document", missing_document)

    assert runtime.get_rule_link_records_for_document(uri) == []


def test_document_context_caches_local_rule_link_records_per_revision() -> None:
    text = """
rule shared_rule {
  condition:
    true
}

rule main {
  condition:
    shared_rule
}
""".lstrip()
    runtime = LspRuntime()
    doc = runtime.ensure_document("file://local.yar", text)

    first = doc.get_local_rule_link_records()
    second = doc.get_local_rule_link_records()
    assert first == second
    assert len(first) == 1
    assert first[0].rule_name == "shared_rule"
    first[0].rule_name = "corrupted"
    assert doc.get_local_rule_link_records() == second
    first.clear()
    assert doc.get_local_rule_link_records() == second

    doc.update(text.replace("shared_rule", "renamed_rule", 1), version=2)
    refreshed = doc.get_local_rule_link_records()
    assert refreshed is not first


def test_runtime_caches_workspace_rule_navigation_and_invalidates_on_update(tmp_path: Path) -> None:
    common = tmp_path / "common.yar"
    user = tmp_path / "user.yar"
    common.write_text("rule shared_rule { condition: true }\n", encoding="utf-8")
    user.write_text(
        """
rule local_rule {
  condition:
    shared_rule
}
""".lstrip(),
        encoding="utf-8",
    )

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    current_uri = path_to_uri(user)

    definition_first = runtime.find_rule_definition("shared_rule", current_uri)
    definition_second = runtime.find_rule_definition("shared_rule", current_uri)
    assert definition_first == definition_second
    assert definition_first is not None
    definition_first.uri = "file:///corrupted.yar"
    assert runtime.find_rule_definition("shared_rule", current_uri) == definition_second

    refs_first = runtime.find_rule_references("shared_rule", current_uri=current_uri)
    refs_second = runtime.find_rule_references("shared_rule", current_uri=current_uri)
    assert refs_first == refs_second  # Compare by value, not identity (cache returns copies)
    assert len(refs_first) == 2
    refs_first[0].uri = "file:///corrupted.yar"
    assert runtime.find_rule_references("shared_rule", current_uri=current_uri) == refs_second
    refs_first.clear()
    refs_after_mutation = runtime.find_rule_references("shared_rule", current_uri=current_uri)
    assert refs_after_mutation == refs_second

    records_first = runtime.find_rule_reference_records("shared_rule", current_uri=current_uri)
    records_second = runtime.find_rule_reference_records("shared_rule", current_uri=current_uri)
    assert records_first == records_second  # Compare by value, not identity (cache returns copies)
    assert {record.role for record in records_first} == {"declaration", "use"}
    records_first[0].role = "corrupted"
    assert (
        runtime.find_rule_reference_records("shared_rule", current_uri=current_uri)
        == records_second
    )

    status = runtime.get_status()
    cache_stats = _cache_stats(status)
    assert cache_stats["rule_definition_entries"] >= 1
    assert cache_stats["rule_reference_entries"] >= 1
    assert cache_stats["rule_reference_record_entries"] >= 1

    runtime.update_document(
        current_uri,
        """
rule local_rule {
  condition:
    true
}
""".lstrip(),
        version=2,
    )

    refs_third = runtime.find_rule_references("shared_rule", current_uri=current_uri)
    assert refs_third is not refs_first
    assert len(refs_third) == 1
