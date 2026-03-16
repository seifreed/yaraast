"""CLI tests for roundtrip commands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.roundtrip import roundtrip


def _sample_rule() -> str:
    return """
// test comment
rule sample_roundtrip {
    strings:
        $a = "abc"
    condition:
        $a
}
"""


def test_roundtrip_serialize_deserialize(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule())

    json_path = tmp_path / "sample.json"
    result = runner.invoke(
        roundtrip,
        ["serialize", str(yara_path), "-f", "json", "-o", str(json_path)],
    )
    assert result.exit_code == 0
    assert json_path.exists()

    out_path = tmp_path / "reconstructed.yar"
    result = runner.invoke(
        roundtrip,
        ["deserialize", str(json_path), "-f", "json", "-o", str(out_path)],
    )
    assert result.exit_code == 0
    assert out_path.exists()
