"""More tests for LSP document links and symbols."""

from __future__ import annotations

from pathlib import Path

from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri
from yaraast.lsp.symbols import SymbolsProvider


def test_document_links_include_module_docs_and_local_rule_links(tmp_path: Path) -> None:
    common = tmp_path / "common.yar"
    doc = tmp_path / "doc.yar"
    common.write_text("rule shared_rule { condition: true }\n", encoding="utf-8")
    text = """
import "pe"
include "common.yar"

rule local_rule {
  condition:
    shared_rule and pe.is_pe
}
""".lstrip()
    doc.write_text(text, encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    provider = DocumentLinksProvider(runtime)

    links = provider.get_document_links(text, path_to_uri(doc))
    targets = [link.target for link in links]
    tooltips = [link.tooltip for link in links]

    assert any(target and "modules/pe" in target for target in targets)
    assert any(target and target.endswith("common.yar") for target in targets)
    assert any(tooltip == "Go to rule shared_rule" for tooltip in tooltips)

    pe_link = next(link for link in links if link.tooltip == "Open documentation for pe module")
    include_link = next(link for link in links if link.tooltip == "Open common.yar")
    assert pe_link.range.start.line == 0
    assert pe_link.range.start.character == 8
    assert pe_link.range.end.character == 10
    assert include_link.range.start.line == 1
    assert include_link.range.start.character == 9
    assert include_link.range.end.character == 19


def test_symbols_provider_includes_include_and_condition_block_range(tmp_path: Path) -> None:
    doc = tmp_path / "doc.yar"
    text = """
include "common.yar"

rule local_rule {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    doc.write_text(text, encoding="utf-8")

    runtime = LspRuntime()
    uri = path_to_uri(doc)
    runtime.open_document(uri, text)
    provider = SymbolsProvider(runtime)

    symbols = provider.get_symbols(text, uri)
    names = {symbol.name for symbol in symbols}
    assert 'include "common.yar"' in names

    rule_symbol = next(symbol for symbol in symbols if symbol.name == "local_rule")
    assert rule_symbol.range.start.line == 2
    assert rule_symbol.range.end.line == 9
    assert rule_symbol.selection_range.start.line == 2
    assert rule_symbol.selection_range.start.character == 5
    assert rule_symbol.selection_range.end.character == 15
    condition_symbol = next(child for child in rule_symbol.children if child.name == "condition")
    assert condition_symbol.range.start.line == 7
    assert condition_symbol.range.end.line >= 8
    meta_symbol = next(child for child in rule_symbol.children if child.name == "meta")
    assert meta_symbol.range.start.line == 3
    assert meta_symbol.range.end.line == 4
    assert meta_symbol.selection_range.start.line == 3
    assert meta_symbol.selection_range.start.character == 2
    assert meta_symbol.selection_range.end.character == 6
    meta_child = next(child for child in meta_symbol.children if child.name.startswith("author ="))
    assert meta_child.range.start.line == 4
    assert meta_child.range.start.character == 4
    assert meta_child.range.end.character == 10
    strings_symbol = next(child for child in rule_symbol.children if child.name == "strings")
    assert strings_symbol.range.start.line == 5
    assert strings_symbol.range.end.line == 6
    assert strings_symbol.selection_range.start.line == 5
    assert strings_symbol.selection_range.start.character == 2
    assert strings_symbol.selection_range.end.character == 9
    string_child = next(child for child in strings_symbol.children if child.name == "$a")
    assert string_child.range.start.line == 6


def test_symbols_provider_uses_runtime_records_for_yaral_sections(tmp_path: Path) -> None:
    doc = tmp_path / "login.yar"
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
    doc.write_text(text, encoding="utf-8")

    runtime = LspRuntime()
    runtime.update_config({"YARA": {"dialectMode": "yaral"}})
    uri = path_to_uri(doc)
    runtime.open_document(uri, text)
    provider = SymbolsProvider(runtime)

    symbols = provider.get_symbols(text, uri)
    rule_symbol = next(symbol for symbol in symbols if symbol.name == "login_event")
    child_names = [child.name for child in rule_symbol.children]
    assert "events" in child_names
    assert "match" in child_names
    assert "outcome" in child_names
    assert "condition" in child_names
    events_symbol = next(child for child in rule_symbol.children if child.name == "events")
    match_symbol = next(child for child in rule_symbol.children if child.name == "match")
    assert events_symbol.range.start.line == 1
    assert events_symbol.range.end.line == 2
    assert events_symbol.selection_range.start.line == 1
    assert events_symbol.selection_range.start.character == 2
    assert events_symbol.selection_range.end.character == 8
    assert match_symbol.range.start.line == 3
    assert match_symbol.range.end.line == 4
    assert match_symbol.selection_range.start.line == 3
    assert match_symbol.selection_range.start.character == 2
    assert match_symbol.selection_range.end.character == 7


def test_symbols_provider_uses_runtime_records_for_imports_and_includes_exact_ranges(
    tmp_path: Path,
) -> None:
    doc = tmp_path / "doc.yar"
    text = 'import "pe"\ninclude "common.yar"\nrule sample { condition: true }\n'
    doc.write_text(text, encoding="utf-8")

    runtime = LspRuntime()
    uri = path_to_uri(doc)
    runtime.open_document(uri, text)
    provider = SymbolsProvider(runtime)

    symbols = provider.get_symbols(text, uri)
    import_symbol = next(symbol for symbol in symbols if symbol.name == 'import "pe"')
    include_symbol = next(symbol for symbol in symbols if symbol.name == 'include "common.yar"')

    assert import_symbol.range.start.line == 0
    assert import_symbol.range.start.character == 8
    assert import_symbol.range.end.character == 10
    assert include_symbol.range.start.line == 1
    assert include_symbol.range.start.character == 9
    assert include_symbol.range.end.character == 19


def test_symbols_provider_without_runtime_uses_document_context_fallback() -> None:
    text = 'import "pe"\nrule sample { condition: true }\n'
    provider = SymbolsProvider()

    symbols = provider.get_symbols(text)

    import_symbol = next(symbol for symbol in symbols if symbol.name == 'import "pe"')
    rule_symbol = next(symbol for symbol in symbols if symbol.name == "sample")
    assert import_symbol.range.start.line == 0
    assert import_symbol.range.start.character == 8
    assert import_symbol.range.end.character == 10
    assert rule_symbol.selection_range.start.line == 1


def test_symbols_provider_caches_results_per_document_revision(tmp_path: Path) -> None:
    doc = tmp_path / "doc.yar"
    text_v1 = "rule sample { condition: true }\n"
    text_v2 = 'rule sample { strings: $a = "x" condition: $a }\n'
    doc.write_text(text_v1, encoding="utf-8")

    runtime = LspRuntime()
    uri = path_to_uri(doc)
    runtime.open_document(uri, text_v1, version=1)
    provider = SymbolsProvider(runtime)

    first = provider.get_symbols(text_v1, uri)
    second = provider.get_symbols(text_v1, uri)
    assert first is second

    runtime.update_document(uri, text_v2, version=2)
    third = provider.get_symbols(text_v2, uri)
    assert third is not first
    rule_symbol = next(symbol for symbol in third if symbol.name == "sample")
    assert any(child.name == "strings" for child in (rule_symbol.children or []))
