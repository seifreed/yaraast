"""Extra tests for fluent CLI templates (no mocks)."""

from __future__ import annotations

from click.testing import CliRunner

from yaraast.cli.commands.fluent import fluent


def test_fluent_template_document_and_network(tmp_path) -> None:
    runner = CliRunner()

    out_doc = tmp_path / "doc.yar"
    res_doc = runner.invoke(
        fluent,
        ["template", "doc_rule", "--type", "document", "--tags", "t1,t2", "--output", str(out_doc)],
    )
    assert res_doc.exit_code == 0
    assert out_doc.exists()
    content = out_doc.read_text()
    assert "rule doc_rule" in content
    assert "t1" in content and "t2" in content

    out_net = tmp_path / "net.yar"
    res_net = runner.invoke(
        fluent,
        ["template", "net_rule", "--type", "network", "--output", str(out_net)],
    )
    assert res_net.exit_code == 0
    assert out_net.exists()
