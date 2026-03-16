"""Helpers for round-trip serialization."""

from __future__ import annotations

import json
from datetime import datetime

import yaml

from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator
from yaraast.serialization.roundtrip_models import FormattingInfo, RoundTripMetadata


def detect_formatting(source: str) -> FormattingInfo:
    formatting = FormattingInfo()
    lines = source.split("\n")

    if "\r\n" in source:
        formatting.line_endings = "\r\n"
    elif "\r" in source:
        formatting.line_endings = "\r"
    else:
        formatting.line_endings = "\n"

    indent_sizes = []
    for line in lines:
        if line.strip() and line.startswith(" "):
            leading_spaces = len(line) - len(line.lstrip(" "))
            if leading_spaces > 0:
                indent_sizes.append(leading_spaces)
        elif line.strip() and line.startswith("\t"):
            formatting.indent_style = "tabs"

    if indent_sizes:
        from functools import reduce
        from math import gcd

        base_indent = reduce(gcd, indent_sizes)
        formatting.indent_size = base_indent if base_indent > 0 else 4

    if "/*" in source and "*/" in source:
        formatting.comment_style = "block"
    elif "//" in source:
        formatting.comment_style = "line"

    return formatting


def build_roundtrip_metadata(
    yara_source: str,
    source_file: str | None,
    preserve_comments: bool,
    preserve_formatting: bool,
) -> RoundTripMetadata:
    formatting = detect_formatting(yara_source)
    return RoundTripMetadata(
        original_source=yara_source if len(yara_source) < 10000 else None,
        source_file=source_file,
        parsed_at=datetime.now().isoformat(),
        formatting=formatting,
        comments_preserved=preserve_comments,
        formatting_preserved=preserve_formatting,
    )


def serialize_with_roundtrip_metadata(
    serializer,
    ast,
    metadata: RoundTripMetadata,
    format: str,
) -> str:
    if format == "yaml":
        standard_data = yaml.safe_load(serializer.serialize(ast))
    else:
        standard_data = json.loads(serializer.serialize(ast))

    standard_data["roundtrip_metadata"] = metadata.to_dict()

    if format == "yaml":
        return yaml.dump(
            standard_data,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=2,
        )
    return json.dumps(standard_data, indent=2, ensure_ascii=False)


def create_generator(
    metadata: RoundTripMetadata | None,
    preserve_original_formatting: bool,
    preserve_comments: bool,
) -> CommentAwareCodeGenerator:
    if metadata and preserve_original_formatting:
        indent_size = metadata.formatting.indent_size
        preserve_comments = metadata.comments_preserved and preserve_comments
    else:
        indent_size = 4

    return CommentAwareCodeGenerator(
        indent_size=indent_size,
        preserve_comments=preserve_comments,
    )
