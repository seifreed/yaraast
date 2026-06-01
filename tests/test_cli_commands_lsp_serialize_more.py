"""Real integration tests for CLI lsp/serialize commands (no mocks)."""

from __future__ import annotations

import builtins
from pathlib import Path
from types import ModuleType
from typing import Any

from click.testing import CliRunner
import pytest

import yaraast.cli.commands.lsp as lsp_cmd
import yaraast.cli.commands.serialize as ser_cmd


def _rule(name: str, value: str = "abc") -> str:
    return f"""
rule {name} {{
    strings:
        $a = "{value}"
    condition:
        $a
}}
"""


def test_lsp_help_real() -> None:
    runner = CliRunner()
    result = runner.invoke(lsp_cmd.lsp, ["--help"])
    assert result.exit_code == 0
    assert "--stdio" in result.output
    assert "--tcp" in result.output


def test_serialize_diff_no_changes_real(tmp_path: Path) -> None:
    runner = CliRunner()
    old_file = tmp_path / "old.yar"
    new_file = tmp_path / "new.yar"
    old_file.write_text(_rule("same"), encoding="utf-8")
    new_file.write_text(_rule("same"), encoding="utf-8")

    result = runner.invoke(ser_cmd.serialize, ["diff", str(old_file), str(new_file)])
    assert result.exit_code == 0
    assert "No differences found" in result.output


def test_serialize_diff_patch_and_json_output_real(tmp_path: Path) -> None:
    runner = CliRunner()
    old_file = tmp_path / "old.yar"
    new_file = tmp_path / "new.yar"
    old_file.write_text(_rule("r1", "abc"), encoding="utf-8")
    new_file.write_text(_rule("r1", "xyz"), encoding="utf-8")

    patch_out = tmp_path / "changes.patch"
    result_patch = runner.invoke(
        ser_cmd.serialize,
        ["diff", str(old_file), str(new_file), "--patch", "-o", str(patch_out)],
    )
    assert result_patch.exit_code == 0
    assert patch_out.exists()
    assert patch_out.read_text(encoding="utf-8")

    json_out = tmp_path / "changes.json"
    result_json = runner.invoke(
        ser_cmd.serialize,
        ["diff", str(old_file), str(new_file), "-o", str(json_out), "-f", "json"],
    )
    assert result_json.exit_code == 0
    assert json_out.exists()
    assert json_out.read_text(encoding="utf-8")


def test_serialize_diff_yaml_propagates_internal_yaml_import_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_file = tmp_path / "old.yar"
    new_file = tmp_path / "new.yar"
    old_file.write_text(_rule("r1", "abc"), encoding="utf-8")
    new_file.write_text(_rule("r1", "xyz"), encoding="utf-8")
    yaml_out = tmp_path / "changes.yaml"
    real_import = builtins.__import__

    def fail_internal_yaml_import(
        name: str,
        globals_: dict[str, Any] | None = None,
        locals_: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "yaml":
            raise ImportError("broken yaml internals", name="yaml._broken")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_internal_yaml_import)

    with pytest.raises(ImportError, match="broken yaml internals"):
        CliRunner().invoke(
            ser_cmd.serialize,
            ["diff", str(old_file), str(new_file), "-o", str(yaml_out), "-f", "yaml"],
            catch_exceptions=False,
        )


def test_serialize_import_writes_yara_output_real(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_file = tmp_path / "sample.yar"
    yara_file.write_text(_rule("imported_rule"), encoding="utf-8")
    json_file = tmp_path / "sample.json"
    output_file = tmp_path / "imported.yar"

    export_result = runner.invoke(
        ser_cmd.serialize,
        ["export", str(yara_file), "-o", str(json_file), "-f", "json"],
    )
    assert export_result.exit_code == 0

    import_result = runner.invoke(
        ser_cmd.serialize,
        ["import", str(json_file), "-f", "json", "-o", str(output_file)],
    )

    assert import_result.exit_code == 0
    assert "YARA code written" in import_result.output
    assert output_file.exists()
    assert "rule imported_rule" in output_file.read_text(encoding="utf-8")


def test_serialize_error_paths_real(tmp_path: Path) -> None:
    runner = CliRunner()
    bad = tmp_path / "bad.yar"
    bad.write_text("rule broken { condition:", encoding="utf-8")

    export_result = runner.invoke(ser_cmd.serialize, ["export", str(bad)])
    assert export_result.exit_code != 0

    validate_result = runner.invoke(ser_cmd.serialize, ["validate", str(bad)])
    assert validate_result.exit_code != 0

    info_result = runner.invoke(ser_cmd.serialize, ["info", str(bad)])
    assert info_result.exit_code != 0
