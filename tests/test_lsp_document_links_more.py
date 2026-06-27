"""Real tests for LSP document links (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any, cast

import pytest

from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.document_types import SymbolRecord, path_to_uri
from yaraast.lsp.runtime import DocumentContext, LspRuntime
from yaraast.lsp.utf16 import utf8_col_to_utf16


@pytest.mark.parametrize("text", [None, 1, b'import "pe"', object()])
def test_document_links_rejects_non_string_text(text: Any) -> None:
    provider = DocumentLinksProvider()

    with pytest.raises(TypeError, match="Document links text must be a string"):
        provider.get_document_links(cast(str, text), "file://test.yar")


@pytest.mark.parametrize("document_uri", [None, 1, b"file://test.yar", object()])
def test_document_links_rejects_non_string_uri(document_uri: Any) -> None:
    provider = DocumentLinksProvider()

    with pytest.raises(TypeError, match="Document links URI must be a string"):
        provider.get_document_links('import "pe"\n', cast(str, document_uri))


def test_document_links_import_and_include(tmp_path: Path) -> None:
    include_path = tmp_path / "inc.yar"
    include_path.write_text("rule inc { condition: true }", encoding="utf-8")

    text = dedent(
        f"""
        import "pe"
        include "{include_path.name}"

        rule main {{
            condition:
                pe.is_pe
        }}
        """,
    ).lstrip()

    doc_path = tmp_path / "main.yar"
    doc_path.write_text(text, encoding="utf-8")

    provider = DocumentLinksProvider()
    links = provider.get_document_links(text, path_to_uri(doc_path))

    assert len(links) >= 2
    targets = {link.target for link in links if link.target is not None}
    assert any("yara.readthedocs.io" in t for t in targets)
    assert any(t.startswith("file://") for t in targets)


def test_document_links_fallback(tmp_path: Path) -> None:
    text = 'import "pe"\ninclude "missing.yar"\n'
    doc_path = tmp_path / "doc.yar"
    doc_path.write_text(text, encoding="utf-8")

    provider = DocumentLinksProvider()
    links = provider._fallback_links(text, path_to_uri(doc_path))

    assert any(link.target and "pe.html" in link.target for link in links)


def test_document_links_fallback_include_range_uses_utf16_columns(tmp_path: Path) -> None:
    include_path = tmp_path / "😀.yar"
    include_path.write_text("rule inc { condition: true }", encoding="utf-8")
    text = 'include "😀.yar"\nrule main { condition: true }\n'
    doc_path = tmp_path / "doc.yar"
    doc_path.write_text(text, encoding="utf-8")

    links = DocumentLinksProvider()._fallback_links(text, path_to_uri(doc_path))

    assert len(links) == 1
    value_start = text.index("😀.yar")
    value_end = value_start + len("😀.yar")
    assert links[0].range.start.character == utf8_col_to_utf16(text.splitlines()[0], value_start)
    assert links[0].range.end.character == utf8_col_to_utf16(text.splitlines()[0], value_end)


def test_document_links_helper_edges(tmp_path: Path) -> None:
    include_path = tmp_path / "inc.yar"
    include_path.write_text("rule inc { condition: true }", encoding="utf-8")

    provider = DocumentLinksProvider()
    text = 'import "pe"\ninclude "inc.yar"\n'

    ast_links = provider.get_document_links(text, str(tmp_path / "doc.yar"))
    assert len(ast_links) == 2

    doc = DocumentContext(str(tmp_path / "doc.yar"), text)
    assert doc.get_include_target_uri("inc.yar") is not None
    assert DocumentContext("file://\0bad", "").get_include_target_uri("missing.yar") is None

    fallback_links = provider._fallback_links(
        'import "unknown"\ninclude "missing.yar"\nimport "pe"\n', path_to_uri(tmp_path / "doc.yar")
    )
    assert len(fallback_links) == 1
    assert "pe.html" in (fallback_links[0].target or "")


def test_include_target_uri_escapes_special_path_characters(tmp_path: Path) -> None:
    include_dir = tmp_path / "include dir"
    include_dir.mkdir()
    include_path = include_dir / "inc file.yar"
    include_path.write_text("rule inc { condition: true }", encoding="utf-8")

    main_path = tmp_path / "main file.yar"
    doc = DocumentContext(
        path_to_uri(main_path),
        'include "include dir/inc file.yar"\nrule main { condition: true }\n',
    )

    target = doc.get_include_target_uri("include dir/inc file.yar")

    assert target is not None
    assert target == include_path.resolve().as_uri()
    assert "%20" in target


def test_include_info_treats_inaccessible_include_paths_as_unresolved(tmp_path: Path) -> None:
    doc = DocumentContext(path_to_uri(tmp_path / "main.yar"), "rule main { condition: true }\n")

    info = doc.get_include_info("a" * 5000)

    assert info["resolved_path"] is None
    assert doc.get_include_target_uri("a" * 5000) is None


def test_include_target_uri_rejects_symlinked_document_parents(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "inc.yar").write_text("rule inc { condition: true }", encoding="utf-8")
    real_doc = outside / "main.yar"
    real_doc.write_text('include "inc.yar"\n', encoding="utf-8")
    link_dir = tmp_path / "linked"
    link_dir.symlink_to(outside, target_is_directory=True)
    doc = DocumentContext((link_dir / "main.yar").as_uri(), real_doc.read_text(encoding="utf-8"))

    assert doc.get_include_target_uri("inc.yar") is None


@pytest.mark.parametrize("include_path", ["", "   ", "\t"])
def test_include_target_uri_rejects_empty_include_paths(
    tmp_path: Path,
    include_path: str,
) -> None:
    doc = DocumentContext(path_to_uri(tmp_path / "main.yar"), "")

    with pytest.raises(ValueError, match="Include path must not be empty"):
        doc.get_include_info(include_path)

    with pytest.raises(ValueError, match="Include path must not be empty"):
        doc.get_include_target_uri(include_path)


@pytest.mark.parametrize("include_path", [None, False, 123, object(), b"inc.yar"])
def test_include_target_uri_rejects_invalid_include_path_types(
    tmp_path: Path,
    include_path: Any,
) -> None:
    doc = DocumentContext(path_to_uri(tmp_path / "main.yar"), "")

    with pytest.raises(TypeError, match="Include path must be a string"):
        doc.get_include_info(cast(str, include_path))

    with pytest.raises(TypeError, match="Include path must be a string"):
        doc.get_include_target_uri(cast(str, include_path))


def test_document_links_parser_fallback_and_error_edges(tmp_path: Path) -> None:
    include_path = tmp_path / "inc.yar"
    include_path.write_text("rule inc { condition: true }", encoding="utf-8")
    provider = DocumentLinksProvider()

    broken_text = 'import "pe"\ninclude "inc.yar"\nrule bad { condition: '
    links = provider.get_document_links(broken_text, path_to_uri(tmp_path / "doc.yar"))
    assert len(links) == 2
    assert DocumentContext("file://\0bad", "").get_include_target_uri("missing.yar") is None


def test_document_links_fallbacks_when_runtime_symbols_are_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    doc_path = tmp_path / "doc.yar"
    include_path = tmp_path / "inc.yar"
    text = 'import "pe"\ninclude "inc.yar"\n'
    include_path.write_text("rule inc { condition: true }\n", encoding="utf-8")
    doc_path.write_text(text, encoding="utf-8")

    monkeypatch.setattr(DocumentContext, "ast", lambda self: None)

    provider = DocumentLinksProvider(LspRuntime())
    links = provider.get_document_links(text, path_to_uri(doc_path))

    assert len(links) == 2
    targets = {link.target for link in links if link.target is not None}
    assert any("pe.html" in target for target in targets)
    assert any(target.startswith("file://") for target in targets)


def test_document_links_keep_runtime_rule_links_when_symbol_scan_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    common = tmp_path / "common.yar"
    user = tmp_path / "user.yar"
    common.write_text("rule shared_rule { condition: true }\n", encoding="utf-8")
    user.write_text('import "pe"\nrule local_rule { condition: shared_rule }\n', encoding="utf-8")

    runtime = LspRuntime()
    runtime.set_workspace_folders([str(tmp_path)])
    text = user.read_text(encoding="utf-8")
    uri = path_to_uri(user)
    runtime.open_document(uri, text)

    original_symbols = DocumentContext.symbols

    def broken_symbols(self: DocumentContext) -> list[SymbolRecord]:
        if self.uri == uri:
            raise RuntimeError("boom")
        return original_symbols(self)

    monkeypatch.setattr(DocumentContext, "symbols", broken_symbols)

    links = DocumentLinksProvider(runtime).get_document_links(text, uri)

    targets = {link.target for link in links if link.target is not None}
    assert any("pe.html" in target for target in targets)
    assert common.as_uri() in targets


def test_document_links_keep_local_rule_links_when_symbol_scan_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    doc_path = tmp_path / "doc.yar"
    text = dedent("""
        rule local_rule {
          condition:
            true
        }

        rule use_local {
          condition:
            local_rule
        }

        rule broken {
          condition:
        """).lstrip()
    doc_path.write_text(text, encoding="utf-8")

    original_symbols = DocumentContext.symbols

    def broken_symbols(self: DocumentContext) -> list[SymbolRecord]:
        if self.uri == path_to_uri(doc_path):
            raise RuntimeError("boom")
        return original_symbols(self)

    monkeypatch.setattr(DocumentContext, "symbols", broken_symbols)

    links = DocumentLinksProvider(LspRuntime()).get_document_links(text, path_to_uri(doc_path))

    local_rule_links = [link for link in links if link.tooltip == "Go to rule local_rule"]
    assert len(local_rule_links) == 1
    assert local_rule_links[0].target == path_to_uri(doc_path)


def test_document_links_without_runtime_include_local_rule_links() -> None:
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

    provider = DocumentLinksProvider()
    links = provider.get_document_links(text, "file://local.yar")

    rule_link = next(link for link in links if link.tooltip == "Go to rule shared_rule")
    assert rule_link.target == "file://local.yar"
    assert rule_link.range.start.line == 7
