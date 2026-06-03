"""CLI validation tests using libyara (no mocks)."""

from __future__ import annotations

from pathlib import Path
import tempfile

from click.testing import CliRunner
import pytest

from yaraast.cli.main import cli
from yaraast.libyara import YARA_AVAILABLE


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_validate_roundtrip(tmp_path: Path) -> None:
    rule_text = """
rule test_rule {
    strings:
        $a = "hello"
    condition:
        $a
}
"""
    rule_path = tmp_path / "rule.yar"
    rule_path.write_text(rule_text.strip(), encoding="utf-8")

    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
        f.write(b"hello world")
        data_path = Path(f.name)

    runner = CliRunner()
    try:
        roundtrip_result = runner.invoke(
            cli,
            ["validate", "roundtrip", str(rule_path), "-d", str(data_path)],
        )
        assert roundtrip_result.exit_code == 0
        assert "Round-trip PASSED" in roundtrip_result.output
    finally:
        data_path.unlink(missing_ok=True)
