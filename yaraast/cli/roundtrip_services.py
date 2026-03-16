"""Service helpers for roundtrip CLI (logic without IO)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from yaraast.cli.utils import read_text
from yaraast.codegen.pretty_printer import PrettyPrinter, StylePresets
from yaraast.parser.parser import Parser
from yaraast.serialization.roundtrip_serializer import (
    RoundTripSerializer,
    create_rules_manifest,
    roundtrip_yara,
    serialize_for_pipeline,
)


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
    style: str,
    indent_size: int,
    max_line_length: int,
    align_strings: bool,
    align_meta: bool,
    sort_imports: bool,
    sort_tags: bool,
) -> tuple[Any, str]:
    parser = Parser()
    yara_source = read_text(input_file)
    ast = parser.parse(yara_source)
    if style == "compact":
        options = StylePresets.compact()
    elif style == "dense":
        options = StylePresets.dense()
    elif style == "verbose":
        options = StylePresets.verbose()
    else:
        options = StylePresets.readable()
    options.indent_size = indent_size
    options.max_line_length = max_line_length
    options.align_string_definitions = align_strings
    options.align_meta_values = align_meta
    options.sort_imports = sort_imports
    options.sort_tags = sort_tags
    printer = PrettyPrinter(options)
    formatted_code = printer.pretty_print(ast)
    return ast, formatted_code


def pipeline_serialize_file(
    input_file: Path,
    pipeline_info: str | None,
) -> tuple[Any, str, dict | None]:
    parser = Parser()
    yara_source = read_text(input_file)
    ast = parser.parse(yara_source)
    pipeline_data = json.loads(pipeline_info) if pipeline_info else None
    yaml_content = serialize_for_pipeline(ast, pipeline_data)
    return ast, yaml_content, pipeline_data


def build_rules_manifest(ast: Any) -> str:
    return create_rules_manifest(ast)
