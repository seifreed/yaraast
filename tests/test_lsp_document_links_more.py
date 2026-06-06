"""Real tests for LSP document links (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any, cast

import pytest

from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.document_types import path_to_uri
from yaraast.lsp.runtime import DocumentContext
from yaraast.lsp.utf16 import utf8_col_to_utf16


@pytest.mark.parametrize("text", [None, 1, b'import "pe"', object()])
def test_document_links_rejects_non_string_text(text: Any) -> None:
    provider = DocumentLinksProvider()

    with pytest.raises(TypeError, match="Document links text must be a string"):
        provider.get_document_links(cast(str, text), "file://test.yar")


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


def test_document_links_parser_fallback_and_error_edges(tmp_path: Path) -> None:
    include_path = tmp_path / "inc.yar"
    include_path.write_text("rule inc { condition: true }", encoding="utf-8")
    provider = DocumentLinksProvider()

    broken_text = 'import "pe"\ninclude "inc.yar"\nrule bad { condition: '
    links = provider.get_document_links(broken_text, path_to_uri(tmp_path / "doc.yar"))
    assert len(links) == 2
    assert DocumentContext("file://\0bad", "").get_include_target_uri("missing.yar") is None


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
