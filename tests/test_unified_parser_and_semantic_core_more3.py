"""Additional real coverage for unified_parser and semantic validator core."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, cast

import pytest

from yaraast.ast.base import Location
from yaraast.types.semantic_validator_core import ValidationError, ValidationResult
from yaraast.unified_parser import UnifiedParser


@pytest.mark.parametrize("text", [None, 123, object()])
def test_unified_parser_rejects_invalid_text_types(text: Any) -> None:
    with pytest.raises(TypeError, match="Parser text must be a string"):
        UnifiedParser(cast(str, text))


@pytest.mark.parametrize("file_path", [None, 123, object()])
def test_unified_parser_parse_file_rejects_invalid_path_types(file_path: Any) -> None:
    with pytest.raises(TypeError, match="YARA file path must be a string or Path"):
        UnifiedParser.parse_file(cast(Any, file_path))


@pytest.mark.parametrize("force_streaming", [None, 1, "true", object()])
def test_unified_parser_parse_file_rejects_invalid_force_streaming_types(
    tmp_path: Path, force_streaming: Any
) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule sample { condition: true }\n", encoding="utf-8")

    with pytest.raises(TypeError, match="force_streaming must be a boolean"):
        UnifiedParser.parse_file(rule_file, force_streaming=cast(bool, force_streaming))


@pytest.mark.parametrize("threshold", [True, "1", object()])
def test_unified_parser_parse_file_rejects_invalid_threshold_types(
    tmp_path: Path, threshold: Any
) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule sample { condition: true }\n", encoding="utf-8")

    with pytest.raises(TypeError, match="streaming_threshold_mb must be a non-negative integer"):
        UnifiedParser.parse_file(rule_file, streaming_threshold_mb=cast(int, threshold))


def test_unified_parser_parse_file_rejects_negative_threshold(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.yar"
    rule_file.write_text("rule sample { condition: true }\n", encoding="utf-8")

    with pytest.raises(ValueError, match="streaming_threshold_mb must be a non-negative integer"):
        UnifiedParser.parse_file(rule_file, streaming_threshold_mb=-1)


def test_validation_error_without_location_and_combine_invalid_result() -> None:
    err = ValidationError("broken")
    assert str(err) == "error: broken"

    left = ValidationResult()
    right = ValidationResult()
    right.add_error("x")
    left.combine(right)
    assert left.is_valid is False
    assert left.total_issues == 1


def test_validation_error_to_dict_with_location_and_suggestion() -> None:
    err = ValidationError(
        "broken",
        location=Location(line=2, column=3, file="sample.yar"),
        suggestion="fix it",
    )
    data = err.to_dict()
    assert data["location"] == {"file": "sample.yar", "line": 2, "column": 3}
    assert data["suggestion"] == "fix it"


@pytest.mark.skipif(sys.platform == "win32", reason="chmod not effective on Windows")
def test_unified_parser_parse_file_permission_and_oserror(tmp_path: Path) -> None:
    restricted_dir = tmp_path / "restricted"
    restricted_dir.mkdir()
    restricted_file = restricted_dir / "r.yar"

    restricted_dir.chmod(0)
    try:
        with pytest.raises(PermissionError, match="Permission denied reading file"):
            UnifiedParser.parse_file(restricted_file)
    finally:
        restricted_dir.chmod(0o755)

    too_long_name = "a" * 5000
    with pytest.raises(OSError, match="Error accessing file"):
        UnifiedParser.parse_file(tmp_path / too_long_name)


def test_unified_parser_parse_yaral_branch() -> None:
    source = """
    rule demo {
        events:
            $e.metadata.event_type = "LOGIN"
        condition:
            #e > 1
    }
    """
    ast = UnifiedParser(source).parse()
    assert len(ast.rules) == 1
