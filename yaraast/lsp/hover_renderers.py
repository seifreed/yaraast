"""Formatting helpers for LSP hover content."""

from __future__ import annotations

from typing import Any, cast

from lsprotocol.types import Hover, MarkupContent, MarkupKind, Range


def module_hover(module_name: str, description: str, word_range: Range) -> Hover:
    return Hover(
        contents=MarkupContent(
            kind=MarkupKind.Markdown,
            value=f"**{module_name}** (module)\n\n{description}",
        ),
        range=word_range,
    )


def module_function_hover(member_info: dict[str, Any], word_range: Range) -> Hover:
    module_name = str(member_info["module"])
    member_name = str(member_info["member"])
    params = ", ".join(
        f"{p[0]}: {p[1]}" for p in cast(list[tuple[str, Any]], member_info["parameters"])
    )
    signature = f"{module_name}.{member_name}({params}) -> {member_info['return_type']}"
    value = f"**{member_name}** (function)\n\n```yara\n{signature}\n```"
    if member_info.get("description"):
        value += f"\n\n{member_info['description']}"
    return Hover(contents=MarkupContent(kind=MarkupKind.Markdown, value=value), range=word_range)


def module_field_hover(member_info: dict[str, Any], word_range: Range) -> Hover:
    module_name = str(member_info["module"])
    member_name = str(member_info["member"])
    value = (
        f"**{member_name}** (field)\n\n```yara\n"
        f"{module_name}.{member_name}: {member_info['type']}\n```"
    )
    if member_info.get("description"):
        value += f"\n\n{member_info['description']}"
    return Hover(contents=MarkupContent(kind=MarkupKind.Markdown, value=value), range=word_range)


def string_identifier_hover(
    base_identifier: str,
    string_info: dict[str, Any] | None,
    word_range: Range,
) -> Hover:
    if string_info is None:
        return Hover(
            contents=MarkupContent(
                kind=MarkupKind.Markdown,
                value=f"**{base_identifier}** (string identifier)\n\nString pattern defined in the strings section.",
            ),
            range=word_range,
        )

    doc_value = f"**{base_identifier}** ({string_info['type']})\n\n"
    doc_value += f"```\n{string_info['value']}\n```"
    if string_info["modifiers"]:
        doc_value += f"\n\nModifiers: {', '.join(string_info['modifiers'])}"
    return Hover(
        contents=MarkupContent(kind=MarkupKind.Markdown, value=doc_value), range=word_range
    )


def meta_hover(key: str, meta_value: object, word_range: Range) -> Hover:
    return Hover(
        contents=MarkupContent(
            kind=MarkupKind.Markdown,
            value=f"**{key}** (metadata)\n\n```\n{meta_value}\n```",
        ),
        range=word_range,
    )


def include_hover(include_path: str, resolved_path: str | None, word_range: Range) -> Hover:
    value = f"**{include_path}** (include)"
    if resolved_path is not None:
        value += f"\n\nResolved to:\n```text\n{resolved_path}\n```"
    else:
        value += "\n\nInclude path referenced from the current rule file."
    return Hover(contents=MarkupContent(kind=MarkupKind.Markdown, value=value), range=word_range)


def rule_hover(rule_name: str, rule_info: dict[str, Any], word_range: Range) -> Hover:
    doc_value = f"**{rule_name}** (rule)"
    if rule_info["modifiers"]:
        doc_value += f" [{', '.join(rule_info['modifiers'])}]"
    if rule_info["tags"]:
        doc_value += f"\n\nTags: {', '.join(rule_info['tags'])}"
    if rule_info["meta"]:
        doc_value += "\n\n**Metadata:**\n"
        for key, value in cast(list[tuple[str, Any]], rule_info["meta"]):
            doc_value += f"- {key}: {value}\n"
    if rule_info["strings_count"]:
        doc_value += f"\n\n**Strings:** {rule_info['strings_count']} defined"
    if rule_info["has_events"]:
        doc_value += "\n\n**YARA-L:** events section present"
    if rule_info["has_match"]:
        doc_value += "\n\n**YARA-L:** match section present"
    if rule_info["has_outcome"]:
        doc_value += "\n\n**YARA-L:** outcome section present"
    if rule_info["has_options"]:
        doc_value += "\n\n**YARA-L:** options section present"
    return Hover(
        contents=MarkupContent(kind=MarkupKind.Markdown, value=doc_value), range=word_range
    )


def workspace_rule_hover(
    rule_name: str,
    rule_info: dict[str, Any],
    definition_uri: str,
    word_range: Range,
) -> Hover:
    doc_value = f"**{rule_name}** (rule)\n\n"
    modifiers = rule_info.get("modifiers", [])
    if modifiers:
        doc_value += f"Modifiers: {', '.join(modifiers)}\n\n"
    tags = rule_info.get("tags", [])
    if tags:
        doc_value += f"Tags: {', '.join(tags)}\n\n"
    meta = rule_info.get("meta", [])
    if meta:
        doc_value += "Metadata:\n"
        for key, value in meta[:5]:
            doc_value += f"- `{key}`: `{value}`\n"
        doc_value += "\n"
    doc_value += f"Defined in: `{definition_uri}`"
    return Hover(
        contents=MarkupContent(kind=MarkupKind.Markdown, value=doc_value), range=word_range
    )
