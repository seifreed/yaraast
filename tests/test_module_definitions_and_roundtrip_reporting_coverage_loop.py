"""
Coverage loop for yaraast.types.module_definitions and
yaraast.cli.roundtrip_reporting.

Targets:
  - yaraast/types/module_definitions.py  (lines 894, 902)
  - yaraast/cli/roundtrip_reporting.py   (lines 22-23, 31, 36-39, 50-52,
      62->65, 70->exit, 84-91, 103-109, 122-129, 142, 146->154, 148, 152)

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from yaraast.cli import roundtrip_reporting as rr
from yaraast.types._registry_primitives import AnyType, IntegerType
from yaraast.types.module_definitions import _resolve_type, load_builtin_modules

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Ast:
    """Minimal stand-in that mirrors the duck-typed attributes display helpers read."""

    def __init__(self, rules: int = 1, imports: int = 0, includes: int = 0) -> None:
        self.rules = [object()] * rules
        self.imports = [object()] * imports
        self.includes = [object()] * includes


# ---------------------------------------------------------------------------
# yaraast.types.module_definitions — _resolve_type missing branches
# ---------------------------------------------------------------------------


class TestResolveTypeEdgeCases:
    """Exercise the two uncovered branches of _resolve_type.

    Line 894: non-tuple, non-string spec (e.g. None, int, list) returns AnyType().
    Line 902: tuple with an unrecognised tag returns IntegerType().
    """

    def test_none_spec_returns_any_type(self) -> None:
        """Passing None (not str, not tuple) should hit line 894 and return AnyType."""
        result = _resolve_type(None)

        assert isinstance(result, AnyType)

    def test_integer_spec_returns_any_type(self) -> None:
        """An integer value is neither str nor tuple — hits line 894."""
        result = _resolve_type(42)

        assert isinstance(result, AnyType)

    def test_empty_tuple_returns_any_type(self) -> None:
        """An empty tuple satisfies `not spec` — hits line 894."""
        result = _resolve_type(())

        assert isinstance(result, AnyType)

    def test_unknown_tag_tuple_returns_integer_type(self) -> None:
        """A tuple with an unknown tag falls through to line 902 and returns IntegerType."""
        result = _resolve_type(("unknown_kind", "i"))

        assert isinstance(result, IntegerType)

    def test_unknown_tag_single_element_tuple_returns_integer_type(self) -> None:
        """A single-element tuple with an unrecognised tag hits line 902."""
        result = _resolve_type(("scalar_map",))

        assert isinstance(result, IntegerType)

    def test_known_string_spec_is_not_affected(self) -> None:
        """Confirm that a recognised string spec still resolves correctly (regression)."""
        from yaraast.types._registry_primitives import StringType

        result = _resolve_type("s")

        assert isinstance(result, StringType)

    def test_unknown_string_returns_any_type(self) -> None:
        """An unrecognised single-char string returns AnyType via primitives.get fallback."""
        result = _resolve_type("z")

        assert isinstance(result, AnyType)

    def test_load_builtin_modules_returns_all_expected_modules(self) -> None:
        """load_builtin_modules() is the primary consumer of _resolve_type; smoke-test it."""
        modules = load_builtin_modules()

        expected = {
            "pe",
            "math",
            "elf",
            "hash",
            "dotnet",
            "time",
            "console",
            "string",
            "cuckoo",
            "vt",
        }
        assert expected.issubset(set(modules.keys()))

    def test_resolve_array_type_is_not_broken(self) -> None:
        """The 'array' tag path still resolves correctly after the edge-case changes."""
        from yaraast.types._registry_collections import ArrayType

        result = _resolve_type(("array", "i"))

        assert isinstance(result, ArrayType)

    def test_resolve_dict_type_is_not_broken(self) -> None:
        """The 'dict' tag path resolves correctly."""
        from yaraast.types._registry_collections import DictionaryType

        result = _resolve_type(("dict", "s", "i"))

        assert isinstance(result, DictionaryType)

    def test_resolve_struct_type_is_not_broken(self) -> None:
        """The 'struct' tag path resolves correctly."""
        from yaraast.types._registry_collections import StructType

        result = _resolve_type(("struct", {"name": "s", "size": "i"}))

        assert isinstance(result, StructType)


# ---------------------------------------------------------------------------
# yaraast.cli.roundtrip_reporting — _optional_output_path branches
# ---------------------------------------------------------------------------


class TestOptionalOutputPathInternalBranches:
    """Cover the remaining branches inside _optional_output_path.

    Lines 22-23: fspath() returns a non-str object — second TypeError guard.
    Line 31:     valid, non-directory path returns the Path object.
    """

    def test_valid_file_path_returns_path_object(self, tmp_path: Path) -> None:
        """A path string that points to a non-directory resolves to a Path (line 31)."""
        target = tmp_path / "output.yar"
        # File does not need to exist; _path_exists_and_is_dir returns False for a
        # non-existent path.
        result = rr._optional_output_path(str(target))

        assert result == target

    def test_pathlike_returning_bytes_raises_type_error(self) -> None:
        """A PathLike whose __fspath__ returns bytes triggers the line-22 TypeError."""

        class BytesPathLike:
            def __fspath__(self) -> bytes:
                return b"/tmp/out.yar"

        with pytest.raises(TypeError, match="output path must be a file path"):
            rr._optional_output_path(BytesPathLike())

    def test_null_byte_string_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="output path must not contain null bytes"):
            rr._optional_output_path("\x00broken")


# ---------------------------------------------------------------------------
# yaraast.cli.roundtrip_reporting — _display_test_success (lines 36-39)
# ---------------------------------------------------------------------------


class TestDisplayTestSuccess:
    """Exercise _display_test_success which was entirely uncovered."""

    def test_success_message_contains_all_fields(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_display_test_success prints file path, format, original and reconstructed counts."""
        result: dict[str, Any] = {
            "metadata": {
                "original_rule_count": 3,
                "reconstructed_rule_count": 3,
            }
        }

        rr._display_test_success(Path("sample.yar"), result, "json")

        out = capsys.readouterr().out
        assert "Round-trip test PASSED" in out
        assert "sample.yar" in out
        assert "JSON" in out
        assert "Original rules: 3" in out
        assert "Reconstructed rules: 3" in out

    def test_success_message_formats_uppercase_format(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The format label is always uppercased regardless of input case."""
        result: dict[str, Any] = {
            "metadata": {
                "original_rule_count": 1,
                "reconstructed_rule_count": 1,
            }
        }

        rr._display_test_success(Path("rule.yar"), result, "msgpack")

        out = capsys.readouterr().out
        assert "MSGPACK" in out


# ---------------------------------------------------------------------------
# yaraast.cli.roundtrip_reporting — _display_test_failure verbose branch (lines 50-52)
# ---------------------------------------------------------------------------


class TestDisplayTestFailureVerbose:
    """Cover the verbose path of _display_test_failure."""

    def test_verbose_shows_difference_list(self, capsys: pytest.CaptureFixture[str]) -> None:
        """When verbose=True every difference entry is printed."""
        result: dict[str, Any] = {"differences": ["rule name mismatch", "condition differs"]}

        rr._display_test_failure(Path("bad.yar"), result, verbose=True)

        out = capsys.readouterr().out
        assert "Round-trip test FAILED" in out
        assert "Differences found: 2" in out
        assert "Differences:" in out
        assert "rule name mismatch" in out
        assert "condition differs" in out

    def test_verbose_with_empty_difference_list(self, capsys: pytest.CaptureFixture[str]) -> None:
        """When verbose=True and no differences, the section header still appears."""
        result: dict[str, Any] = {"differences": []}

        rr._display_test_failure(Path("empty.yar"), result, verbose=True)

        out = capsys.readouterr().out
        assert "Differences found: 0" in out
        assert "Differences:" in out


# ---------------------------------------------------------------------------
# yaraast.cli.roundtrip_reporting — _display_verbose_source short-path
# (lines 62->65, 70->exit — no truncation when source <= 10 lines)
# ---------------------------------------------------------------------------


class TestDisplayVerboseSourceShortPath:
    """Cover the no-truncation path of _display_verbose_source."""

    def test_short_sources_do_not_print_truncation_marker(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Sources with <= 10 lines must not emit the truncation ellipsis (lines 62->65, 70->exit)."""
        result: dict[str, Any] = {
            "original_source": "line1\nline2\nline3",
            "reconstructed_source": "lineA\nlineB",
        }

        rr._display_verbose_source(result)

        out = capsys.readouterr().out
        assert "Original source (3 lines)" in out
        assert "Reconstructed source (2 lines)" in out
        assert "... (truncated)" not in out
        assert "line1" in out
        assert "lineA" in out

    def test_single_line_source_does_not_truncate(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A single-line source also avoids the truncation marker."""
        result: dict[str, Any] = {
            "original_source": "rule x { condition: true }",
            "reconstructed_source": "rule x { condition: true }",
        }

        rr._display_verbose_source(result)

        out = capsys.readouterr().out
        assert "... (truncated)" not in out
        assert "rule x { condition: true }" in out

    def test_exactly_ten_lines_does_not_truncate(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Exactly 10 lines sits at the boundary — the loop exhausts all lines without truncation."""
        ten_lines = "\n".join(f"line{i}" for i in range(10))
        result: dict[str, Any] = {
            "original_source": ten_lines,
            "reconstructed_source": ten_lines,
        }

        rr._display_verbose_source(result)

        out = capsys.readouterr().out
        assert "... (truncated)" not in out


# ---------------------------------------------------------------------------
# yaraast.cli.roundtrip_reporting — display_serialize_result with output path
# (lines 84-91)
# ---------------------------------------------------------------------------


class TestDisplaySerializeResultWithOutputPath:
    """Cover the output-path branch of display_serialize_result."""

    def test_with_output_path_prints_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When output is a valid path the summary lines are printed, not raw content."""
        output_file = tmp_path / "result.json"
        ast = _Ast(rules=4)

        rr.display_serialize_result(
            output=str(output_file),
            fmt="json",
            ast=ast,
            preserve_comments=True,
            preserve_formatting=False,
            serialized='{"rules":[]}',
        )

        out = capsys.readouterr().out
        assert "Serialized to" in out
        assert "JSON" in out
        assert "Rules: 4" in out
        assert "Comments preserved: True" in out
        assert "Formatting preserved: False" in out
        assert '{"rules":[]}' not in out

    def test_without_output_path_prints_raw_content(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When output is None the serialized string is printed directly (regression guard)."""
        ast = _Ast(rules=2)

        rr.display_serialize_result(
            output=None,
            fmt="json",
            ast=ast,
            preserve_comments=False,
            preserve_formatting=False,
            serialized='{"rules":["r1","r2"]}',
        )

        out = capsys.readouterr().out
        assert '{"rules":["r1","r2"]}' in out


# ---------------------------------------------------------------------------
# yaraast.cli.roundtrip_reporting — display_deserialize_result with output path
# (lines 103-109)
# ---------------------------------------------------------------------------


class TestDisplayDeserializeResultWithOutputPath:
    """Cover the output-path branch of display_deserialize_result."""

    def test_with_output_path_prints_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When output is a valid path the summary lines are printed."""
        output_file = tmp_path / "out.yar"
        ast = _Ast(rules=2)

        rr.display_deserialize_result(
            output=str(output_file),
            fmt="msgpack",
            ast=ast,
            preserve_formatting=True,
            yara_code="rule foo { condition: true }",
        )

        out = capsys.readouterr().out
        assert "Generated YARA code to" in out
        assert "MSGPACK" in out
        assert "Rules: 2" in out
        assert "Formatting preserved: True" in out
        assert "rule foo" not in out

    def test_without_output_path_prints_yara_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        """When output is None the YARA code is printed directly (regression guard)."""
        ast = _Ast(rules=1)

        rr.display_deserialize_result(
            output=None,
            fmt="json",
            ast=ast,
            preserve_formatting=False,
            yara_code="rule bar { condition: false }",
        )

        out = capsys.readouterr().out
        assert "rule bar { condition: false }" in out


# ---------------------------------------------------------------------------
# yaraast.cli.roundtrip_reporting — display_pretty_result with output path
# (lines 122-129)
# ---------------------------------------------------------------------------


class TestDisplayPrettyResultWithOutputPath:
    """Cover the output-path branch of display_pretty_result."""

    def test_with_output_path_prints_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When output is a valid path the summary lines are printed."""
        output_file = tmp_path / "pretty.yar"
        ast = _Ast(rules=3)

        rr.display_pretty_result(
            output=str(output_file),
            style="compact",
            ast=ast,
            indent_size=4,
            max_line_length=100,
            formatted_code="rule a {condition: true}",
        )

        out = capsys.readouterr().out
        assert "Pretty printed to" in out
        assert "compact" in out
        assert "Rules: 3" in out
        assert "Indent size: 4" in out
        assert "Max line length: 100" in out
        assert "rule a" not in out

    def test_without_output_path_prints_formatted_code(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When output is None the formatted code is printed directly (regression guard)."""
        ast = _Ast(rules=1)

        rr.display_pretty_result(
            output=None,
            style="standard",
            ast=ast,
            indent_size=2,
            max_line_length=80,
            formatted_code="rule x {\n  condition: true\n}",
        )

        out = capsys.readouterr().out
        assert "rule x" in out


# ---------------------------------------------------------------------------
# yaraast.cli.roundtrip_reporting — display_pipeline_result with output path
# and manifest branches (lines 142, 146->154, 148, 152)
# ---------------------------------------------------------------------------


class TestDisplayPipelineResultWithOutputPath:
    """Cover the output-path and manifest branches of display_pipeline_result."""

    def test_with_output_path_no_manifest(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """output_path provided and include_manifest=False: only the YAML path echo (line 142)."""
        output_file = tmp_path / "pipeline.yaml"
        ast = _Ast(rules=2, imports=1, includes=0)

        rr.display_pipeline_result(
            output=str(output_file),
            yaml_content="rules: []",
            include_manifest=False,
            manifest_content=None,
            ast=ast,
        )

        out = capsys.readouterr().out
        assert "Pipeline YAML written to" in out
        assert "rules: []" not in out
        assert "Rules: 2" in out

    def test_with_output_path_and_manifest(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """output_path provided and include_manifest=True: manifest path echo (line 148)."""
        output_file = tmp_path / "pipeline.yaml"
        ast = _Ast(rules=1, imports=0, includes=1)

        rr.display_pipeline_result(
            output=str(output_file),
            yaml_content="rules: []",
            include_manifest=True,
            manifest_content="manifest: {}",
            ast=ast,
        )

        out = capsys.readouterr().out
        assert "Pipeline YAML written to" in out
        assert "manifest.yaml" in out
        assert "Rules: 1" in out

    def test_without_output_path_and_manifest_content(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """output=None with include_manifest=True and content: prints both sections (line 152)."""
        ast = _Ast(rules=3, imports=2, includes=1)

        rr.display_pipeline_result(
            output=None,
            yaml_content="rules:\n- name: r1",
            include_manifest=True,
            manifest_content="- r1",
            ast=ast,
        )

        out = capsys.readouterr().out
        assert "rules:\n- name: r1" in out
        assert "--- Rules Manifest ---" in out
        assert "- r1" in out
        assert "Rules: 3" in out
        assert "Imports: 2" in out
        assert "Includes: 1" in out

    def test_without_output_path_no_manifest(self, capsys: pytest.CaptureFixture[str]) -> None:
        """output=None with include_manifest=False: only yaml_content and statistics printed."""
        ast = _Ast(rules=1, imports=0, includes=0)

        rr.display_pipeline_result(
            output=None,
            yaml_content="pipeline: empty",
            include_manifest=False,
            manifest_content=None,
            ast=ast,
        )

        out = capsys.readouterr().out
        assert "pipeline: empty" in out
        assert "Rules Manifest" not in out
        assert "Rules: 1" in out
