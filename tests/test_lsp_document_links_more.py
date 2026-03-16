"""Real tests for LSP document links (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.runtime import DocumentContext


def test_document_links_import_and_include(tmp_path) -> None:
    include_path = tmp_path / "inc.yar"
    include_path.write_text("rule inc { condition: true }")

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
    doc_path.write_text(text)

    provider = DocumentLinksProvider()
    links = provider.get_document_links(text, f"file://{doc_path}")

    assert len(links) >= 2
    targets = {link.target for link in links}
    assert any("yara.readthedocs.io" in t for t in targets)
    assert any(t.startswith("file://") for t in targets)


def test_document_links_fallback(tmp_path) -> None:
    text = 'import "pe"\ninclude "missing.yar"\n'
    doc_path = tmp_path / "doc.yar"
    doc_path.write_text(text)

    provider = DocumentLinksProvider()
    links = provider._fallback_links(text, f"file://{doc_path}")

    assert any(link.target and "pe.html" in link.target for link in links)


def test_document_links_helper_edges(tmp_path) -> None:
    include_path = tmp_path / "inc.yar"
    include_path.write_text("rule inc { condition: true }")

    provider = DocumentLinksProvider()
    text = 'import "pe"\ninclude "inc.yar"\n'

    ast_links = provider.get_document_links(text, str(tmp_path / "doc.yar"))
    assert len(ast_links) == 2

    doc = DocumentContext(str(tmp_path / "doc.yar"), text)
    assert doc.get_include_target_uri("inc.yar") is not None
    assert DocumentContext("file://\0bad", "").get_include_target_uri("missing.yar") is None

    fallback_links = provider._fallback_links(
        'import "unknown"\ninclude "missing.yar"\nimport "pe"\n', f"file://{tmp_path / 'doc.yar'}"
    )
    assert len(fallback_links) == 1
    assert "pe.html" in (fallback_links[0].target or "")


def test_document_links_parser_fallback_and_error_edges(tmp_path) -> None:
    include_path = tmp_path / "inc.yar"
    include_path.write_text("rule inc { condition: true }")
    provider = DocumentLinksProvider()

    broken_text = 'import "pe"\ninclude "inc.yar"\nrule bad { condition: '
    links = provider.get_document_links(broken_text, f"file://{tmp_path / 'doc.yar'}")
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
