"""Additional real coverage for unified_parser and semantic validator core."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from yaraast.ast.base import Location
from yaraast.types.semantic_validator_core import ValidationError, ValidationResult
from yaraast.unified_parser import UnifiedParser


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
