"""Service helpers for roundtrip CLI (logic without IO)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from yaraast.cli.utils import read_text
from yaraast.codegen.pretty_printer import StylePresets, pretty_print
from yaraast.errors import ValidationError
from yaraast.parser.source import parse_yara_source
from yaraast.serialization.roundtrip_serializer import (
    RoundTripSerializer,
    roundtrip_yara,
    serialize_for_pipeline,
)
from yaraast.shared.numeric_validation import validate_positive_int_setting

_PRETTY_STYLE_PRESETS = {
    "compact": StylePresets.compact,
    "dense": StylePresets.dense,
    "readable": StylePresets.readable,
    "verbose": StylePresets.verbose,
}


def _parse_pipeline_info(pipeline_info: str | None) -> dict[str, Any] | None:
    if pipeline_info is None or pipeline_info == "":
        return None
    if not isinstance(pipeline_info, str):
        raise TypeError("pipeline_info must be a string")
    try:
        parsed = json.loads(pipeline_info)
    except json.JSONDecodeError as exc:
        msg = "pipeline_info must be valid JSON"
        raise ValidationError(msg) from exc
    if not isinstance(parsed, dict):
        msg = "pipeline_info must be a JSON object"
        raise ValidationError(msg)
    return cast(dict[str, Any], parsed)


def _require_bool_option(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def serialize_roundtrip_file(
    input_file: Path, format: str, preserve_comments: bool, preserve_formatting: bool
) -> tuple[Any, str]:
    yara_source = read_text(input_file)
    serializer = RoundTripSerializer(
        preserve_comments=preserve_comments,
        preserve_formatting=preserve_formatting,
    )
    return serializer.parse_and_serialize(
        yara_source,
        source_file=str(input_file),
        format=format,
    )


def deserialize_roundtrip_file(
    input_file: Path,
    format: str,
    preserve_formatting: bool,
) -> tuple[Any, str]:
    serializer = RoundTripSerializer()
    serialized = read_text(input_file)
    return serializer.deserialize_and_generate(
        serialized,
        format=format,
        preserve_original_formatting=preserve_formatting,
    )


def test_roundtrip_file(input_file: Path, format: str) -> dict[str, Any]:
    yara_source = read_text(input_file)
    return roundtrip_yara(yara_source, format=format)


def pretty_print_file(
    input_file: Path,
    style: object,
    indent_size: int,
    max_line_length: int,
    align_strings: object,
    align_meta: object,
    sort_imports: object,
    sort_tags: object,
) -> tuple[Any, str]:
    validate_positive_int_setting(indent_size, "indent_size")
    validate_positive_int_setting(max_line_length, "max_line_length")
    align_strings = _require_bool_option(align_strings, "align_strings")
    align_meta = _require_bool_option(align_meta, "align_meta")
    sort_imports = _require_bool_option(sort_imports, "sort_imports")
    sort_tags = _require_bool_option(sort_tags, "sort_tags")

    yara_source = read_text(input_file)
    ast = parse_yara_source(yara_source)
    if not isinstance(style, str):
        raise TypeError("pretty style must be a string")
    if style not in _PRETTY_STYLE_PRESETS:
        valid = ", ".join(sorted(_PRETTY_STYLE_PRESETS))
        raise ValueError(f"pretty style must be one of: {valid}")
    options = _PRETTY_STYLE_PRESETS[style]()
    options.indent_size = indent_size
    options.max_line_length = max_line_length
    options.align_string_definitions = align_strings
    options.align_meta_values = align_meta
    options.sort_imports = sort_imports
    options.sort_tags = sort_tags
    formatted_code = pretty_print(ast, options)
    return ast, formatted_code


def pipeline_serialize_file(
    input_file: Path,
    pipeline_info: str | None,
) -> tuple[Any, str, dict | None]:
    yara_source = read_text(input_file)
    ast = parse_yara_source(yara_source)
    pipeline_data = _parse_pipeline_info(pipeline_info)
    yaml_content = serialize_for_pipeline(ast, pipeline_data)
    return ast, yaml_content, pipeline_data
