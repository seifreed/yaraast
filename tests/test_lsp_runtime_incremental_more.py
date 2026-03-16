"""Incremental/runtime tests for the YARAAST LSP runtime."""

from __future__ import annotations

import json
from pathlib import Path

from lsprotocol.types import Position, Range

from yaraast.lsp.diagnostics import DiagnosticsProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri
from yaraast.lsp.semantic_tokens import SemanticTokensProvider


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
    cache_stats = status["cache_stats"]
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

    doc = runtime.ensure_document(uri, runtime.get_document(uri).text)
    sections = {(symbol.kind, symbol.name, symbol.container_name) for symbol in doc.symbols()}
    assert ("section", "strings", "sample") in sections
    assert ("section_header", "strings", "sample") in sections
    assert ("section", "condition", "sample") in sections
    assert ("section_header", "condition", "sample") in sections
    assert ("rule_block", "sample", None) in sections


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
    assert runtime._workspace_symbol_cache

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
    assert info_first is info_second
    assert doc.get_rule_meta_items("sample") == [("author", "me")]
    assert doc.get_string_definition_info("$a")["value"] == "x"

    doc.update(text_v2, version=2)

    info_third = doc.get_rule_info("sample")
    assert info_third is not info_first
    assert doc.get_rule_meta_items("sample") == [("author", "you")]
    assert doc.get_rule_string_identifiers("sample") == ["$b"]
    assert doc.get_string_definition_info("$b")["value"] == "y"


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
    assert rule_def_first is rule_def_second

    rule_refs_first = doc.rule_reference_records("a")
    rule_refs_second = doc.rule_reference_records("a")
    assert rule_refs_first is rule_refs_second
    assert {record.role for record in rule_refs_first} == {"declaration", "use"}

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
    assert refs_first is refs_second
    assert {record.role for record in refs_first} == {"declaration", "read"}

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
    assert diagnostics_again is diagnostics


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
    assert full_a is full_b

    range_ = Range(start=Position(line=2, character=0), end=Position(line=3, character=20))
    range_a = provider.get_semantic_tokens_range(text, range_, uri)
    range_b = provider.get_semantic_tokens_range(text, range_, uri)
    assert range_a is range_b

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
    assert first is second
    assert first is not None
    assert first.normalized_name == "$a"

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
    assert first is second
    assert len(first) == 1
    assert first[0].rule_name == "target"

    runtime.update_document(uri, text_v2, version=2)

    third = runtime.get_rule_link_records_for_document(uri)
    assert third is not first
    assert third == []


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
    assert first is second
    assert len(first) == 1
    assert first[0].rule_name == "shared_rule"

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
    assert definition_first is definition_second

    refs_first = runtime.find_rule_references("shared_rule", current_uri=current_uri)
    refs_second = runtime.find_rule_references("shared_rule", current_uri=current_uri)
    assert refs_first is refs_second
    assert len(refs_first) == 2

    records_first = runtime.find_rule_reference_records("shared_rule", current_uri=current_uri)
    records_second = runtime.find_rule_reference_records("shared_rule", current_uri=current_uri)
    assert records_first == records_second  # Compare by value, not identity (cache returns copies)
    assert {record.role for record in records_first} == {"declaration", "use"}

    status = runtime.get_status()
    cache_stats = status["cache_stats"]
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
