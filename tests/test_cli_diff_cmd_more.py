from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest

from yaraast.cli.commands.diff_cmd import diff
from yaraast.cli.simple_differ import SimpleASTDiffer


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


def test_diff_cmd_no_changes_summary_and_full_output(tmp_path: Path) -> None:
    runner = CliRunner()
    file_a = tmp_path / "a.yar"
    file_b = tmp_path / "b.yar"
    file_c = tmp_path / "c.yar"

    _write(
        file_a,
        """
rule same_rule {
    condition:
        true
}
""",
    )
    _write(
        file_b,
        """
rule same_rule {
    condition:
        true
}
""",
    )
    _write(
        file_c,
        """
rule same_rule {
    strings:
        $a = "abc"
    condition:
        $a
}
""",
    )

    no_changes = runner.invoke(diff, [str(file_a), str(file_b)])
    assert no_changes.exit_code == 0
    assert "No differences found" in no_changes.output

    summary = runner.invoke(diff, [str(file_a), str(file_c), "--summary"])
    assert summary.exit_code == 0
    assert "Summary" in summary.output or "changes" in summary.output.lower()

    full = runner.invoke(diff, [str(file_a), str(file_c), "--logical-only", "--no-style"])
    assert full.exit_code == 0
    assert (
        "Changed rules" in full.output
        or "Rule Changes" in full.output
        or "same_rule" in full.output
    )


def test_diff_cmd_aborts_on_real_parse_error(tmp_path: Path) -> None:
    runner = CliRunner()
    valid = tmp_path / "valid.yar"
    invalid = tmp_path / "invalid.yar"

    _write(
        valid,
        """
rule ok {
    condition:
        true
}
""",
    )
    _write(invalid, "rule broken { condition: }")

    result = runner.invoke(diff, [str(valid), str(invalid)])
    assert result.exit_code != 0
    assert "Error:" in result.output


def test_diff_cmd_abort_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_a = tmp_path / "a.yar"
    file_b = tmp_path / "b.yar"
    _write(file_a, "rule a { condition: true }")
    _write(file_b, "rule b { condition: true }")
    sentinel = RuntimeError("diff sentinel")

    def fail_diff_files(_self: SimpleASTDiffer, _file_a: Path, _file_b: Path) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(SimpleASTDiffer, "diff_files", fail_diff_files)

    result = CliRunner().invoke(diff, [str(file_a), str(file_b)], standalone_mode=False)

    assert result.exit_code != 0
    assert "diff sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)
