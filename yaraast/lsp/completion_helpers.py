"""Helper utilities for YARA completion providers."""

from __future__ import annotations

from typing import Any

from lsprotocol.types import CompletionItem, CompletionItemKind, InsertTextFormat, Position

from yaraast.lsp.language_services import parse_source
from yaraast.lsp.lsp_docs import BUILTIN_DOCS, KEYWORD_DOCS, MODULE_DOCS
from yaraast.lsp.runtime import LanguageMode

try:
    from yaraast.ast.conditions import ForExpression
except Exception:  # pragma: no cover
    ForExpression = None  # type: ignore[assignment,misc]

try:
    from yaraast.yarax.ast_nodes import WithStatement
except Exception:  # pragma: no cover
    WithStatement = None  # type: ignore[assignment,misc]

KEYWORDS: list[str] = list(KEYWORD_DOCS.keys())
BUILTIN_FUNCTIONS: dict[str, str] = dict(BUILTIN_DOCS)
YARAL_KEYWORDS: list[str] = [
    "rule",
    "meta",
    "events",
    "match",
    "condition",
    "outcome",
    "options",
    "and",
    "or",
    "not",
]
YARAX_KEYWORDS: list[str] = list(dict.fromkeys([*KEYWORDS, "with", "lambda", "match"]))

STRING_MODIFIERS: dict[str, str] = {
    "nocase": "Case-insensitive string matching",
    "wide": "Match wide-character (UTF-16) strings",
    "ascii": "Match ASCII strings",
    "xor": "Match XOR-encoded strings",
    "base64": "Match base64-encoded strings",
    "base64wide": "Match base64-encoded wide strings",
    "fullword": "Match complete words only",
}

MODULE_COMPLETIONS: list[tuple[str, str]] = list(MODULE_DOCS.items())


def analyze_context(text: str, position: Position) -> str:
    """Analyze the context at the current position."""
    lines = text.split("\n")
    if position.line >= len(lines):
        return "general"

    current_line = lines[position.line]
    before_cursor = current_line[: position.character]

    if "import" in before_cursor and '"' in before_cursor:
        return "import"

    if "." in before_cursor:
        parts = before_cursor.rsplit(".", 1)
        if len(parts) == 2:
            return "module_member"

    if "$" in before_cursor and "=" in before_cursor:
        if any(mod in before_cursor for mod in ["nocase", "wide", "ascii", "xor"]):
            return "string_modifier"
        if '"' in before_cursor or "}}" in before_cursor or "/" in before_cursor:
            return "string_modifier"

    for i in range(position.line, -1, -1):
        if i < len(lines):
            line = lines[i].strip()
            if line.startswith("condition:"):
                return "condition"
            if line.startswith("meta:"):
                return "meta"
            if line.startswith("strings:"):
                return "strings"
            if line.startswith("rule "):
                break

    return "general"


def get_current_module(text: str, position: Position) -> str | None:
    """Get the module name before the current position."""
    lines = text.split("\n")
    if position.line >= len(lines):
        return None

    current_line = lines[position.line]
    before_cursor = current_line[: position.character]

    if "." in before_cursor:
        parts = before_cursor.rsplit(".", 1)
        if len(parts) == 2:
            tokens = parts[0].split()
            if tokens:
                module_name = tokens[-1]
                return "".join(c for c in module_name if c.isalnum() or c == "_")

    return None


_SNIPPET_TEMPLATES: dict[str, tuple[str, str]] = {
    "rule": (
        'rule ${1:rule_name} {\n\tmeta:\n\t\t${2:author = "analyst"}\n\tstrings:\n\t\t${3:\\$s = "pattern"}\n\tcondition:\n\t\t${0:any of them}\n}',
        "Create a new YARA rule with meta, strings, and condition",
    ),
    "meta": ("meta:\n\t${0}", "Start a metadata section"),
    "strings": ("strings:\n\t${0}", "Start a strings definition section"),
    "condition": ("condition:\n\t${0:true}", "Start a condition section"),
}


def build_keyword_completions(keywords: list[str]) -> list[CompletionItem]:
    """Build keyword completions with snippet templates for structural keywords."""
    items: list[CompletionItem] = []
    for keyword in keywords:
        snippet = _SNIPPET_TEMPLATES.get(keyword)
        if snippet:
            insert_text, doc = snippet
            items.append(
                CompletionItem(
                    label=keyword,
                    kind=CompletionItemKind.Snippet,
                    detail="YARA template",
                    documentation=doc,
                    insert_text=insert_text,
                    insert_text_format=InsertTextFormat.Snippet,
                )
            )
        items.append(
            CompletionItem(
                label=keyword,
                kind=CompletionItemKind.Keyword,
                detail="YARA keyword",
                insert_text=keyword,
            )
        )
    return items


def build_builtin_function_completions(
    builtin_functions: dict[str, str],
) -> list[CompletionItem]:
    """Build built-in function completions."""
    return [
        CompletionItem(
            label=func_name,
            kind=CompletionItemKind.Function,
            detail="Built-in function",
            documentation=description,
            insert_text=f"{func_name}($0)",
            insert_text_format=InsertTextFormat.Snippet,
        )
        for func_name, description in builtin_functions.items()
    ]


def build_module_completions() -> list[CompletionItem]:
    """Build completions for available YARA modules."""
    return [
        CompletionItem(
            label=module_name,
            kind=CompletionItemKind.Module,
            detail="YARA module",
            documentation=description,
            insert_text=module_name,
        )
        for module_name, description in MODULE_COMPLETIONS
    ]


def build_module_member_completions(
    module_name: str,
    module_def: Any,
    access_chain: str = "",
) -> list[CompletionItem]:
    """Build completions for module members with deep type introspection.

    Supports nested access: pe.sections[0]. resolves to StructType fields.
    """
    from yaraast.types._registry_collections import ArrayType, DictionaryType, StructType

    items: list[CompletionItem] = []
    prefix = f"{module_name}.{access_chain}" if access_chain else module_name

    # If access_chain points to a nested type, resolve it
    if access_chain:
        resolved_type = _resolve_access_chain(module_def, access_chain)
        if resolved_type is not None:
            items.extend(_completions_for_type(prefix, resolved_type))
            return items

    for func_name, func_def in module_def.functions.items():
        params = ", ".join(p[0] for p in func_def.parameters)
        items.append(
            CompletionItem(
                label=func_name,
                kind=CompletionItemKind.Function,
                detail=f"{prefix}.{func_name}({params})",
                documentation=getattr(func_def, "description", None),
                insert_text=f"{func_name}($0)",
                insert_text_format=InsertTextFormat.Snippet,
            )
        )

    fields = getattr(module_def, "fields", None)
    if fields is None:
        fields = getattr(module_def, "attributes", {})
    if fields is None:
        fields = {}
    for field_name, field_def in fields.items():
        kind = CompletionItemKind.Field
        detail_type = str(field_def)
        # Indicate navigable types
        if isinstance(field_def, ArrayType):
            detail_type = f"array[{field_def.element_type}]"
            if isinstance(field_def.element_type, StructType):
                detail_type += " (indexable)"
        elif isinstance(field_def, StructType):
            detail_type = "struct"
            kind = CompletionItemKind.Struct
        elif isinstance(field_def, DictionaryType):
            detail_type = f"dict[{field_def.key_type}, {field_def.value_type}]"
        items.append(
            CompletionItem(
                label=field_name,
                kind=kind,
                detail=f"{prefix}.{field_name}: {detail_type}",
                documentation=getattr(field_def, "description", None),
                insert_text=field_name,
            )
        )

    return items


def _resolve_access_chain(module_def: Any, chain: str) -> Any:
    """Resolve a dotted access chain like 'sections[0]' against module type definitions."""
    from yaraast.types._registry_collections import ArrayType, StructType

    fields = getattr(module_def, "fields", None) or getattr(module_def, "attributes", {}) or {}
    parts = chain.replace("]", "").split(".")
    current_type = None

    for part in parts:
        if not part:
            continue
        # Handle array indexing: sections[0
        field_name = part.split("[")[0] if "[" in part else part

        if current_type is None:
            current_type = fields.get(field_name)
        elif isinstance(current_type, StructType):
            current_type = current_type.fields.get(field_name)
        else:
            return None

        if current_type is None:
            return None

        # If indexed, descend into element type
        if "[" in part and isinstance(current_type, ArrayType):
            current_type = current_type.element_type

    return current_type


def _completions_for_type(prefix: str, type_def: Any) -> list[CompletionItem]:
    """Generate completion items from a resolved type definition."""
    from yaraast.types._registry_collections import StructType

    items: list[CompletionItem] = []
    if isinstance(type_def, StructType):
        for field_name, field_type in type_def.fields.items():
            items.append(
                CompletionItem(
                    label=field_name,
                    kind=CompletionItemKind.Field,
                    detail=f"{prefix}.{field_name}: {field_type}",
                    insert_text=field_name,
                )
            )
    return items


def build_string_modifier_completions(
    string_modifiers: dict[str, str],
) -> list[CompletionItem]:
    """Build string modifier completions."""
    return [
        CompletionItem(
            label=modifier,
            kind=CompletionItemKind.Property,
            detail="String modifier",
            documentation=description,
            insert_text=modifier,
        )
        for modifier, description in string_modifiers.items()
    ]


def build_condition_completions(text: str, keywords: list[str]) -> list[CompletionItem]:
    """Build completions relevant to condition context."""
    items: list[CompletionItem] = []

    try:
        ast = parse_source(text)
        if not ast:
            raise ValueError("Failed to parse")

        for rule in ast.rules:
            for string_def in rule.strings:
                identifier = string_def.identifier
                items.append(
                    CompletionItem(
                        label=identifier,
                        kind=CompletionItemKind.Variable,
                        detail="String identifier",
                        insert_text=identifier,
                    )
                )

                if identifier.startswith("$"):
                    base_name = identifier[1:]
                    items.extend(
                        [
                            CompletionItem(
                                label=f"#{base_name}",
                                kind=CompletionItemKind.Variable,
                                detail="String count",
                                insert_text=f"#{base_name}",
                            ),
                            CompletionItem(
                                label=f"@{base_name}",
                                kind=CompletionItemKind.Variable,
                                detail="String offset",
                                insert_text=f"@{base_name}",
                            ),
                            CompletionItem(
                                label=f"!{base_name}",
                                kind=CompletionItemKind.Variable,
                                detail="String length",
                                insert_text=f"!{base_name}",
                            ),
                        ]
                    )
    except Exception:
        pass

    # Also extract loop variables from for-expressions in condition
    try:
        if ast:
            for rule in ast.rules:
                if rule.condition is not None:
                    for var_name in _extract_loop_variables(rule.condition):
                        items.append(
                            CompletionItem(
                                label=var_name,
                                kind=CompletionItemKind.Variable,
                                detail="Loop variable",
                                insert_text=var_name,
                            )
                        )
    except Exception:
        pass

    items.extend(build_keyword_completions(keywords))
    return items


def _extract_loop_variables(node: Any) -> list[str]:
    """Recursively walk an AST condition and extract variables from for-loops and with-declarations."""
    variables: list[str] = []
    if node is None:
        return variables
    if ForExpression is not None and isinstance(node, ForExpression) and node.variable:
        variables.append(node.variable)
    if WithStatement is not None and isinstance(node, WithStatement):
        for decl in node.declarations:
            if hasattr(decl, "identifier") and decl.identifier:
                variables.append(decl.identifier)
    # Recurse into child nodes
    children_method = getattr(node, "children", None)
    if callable(children_method):
        try:
            for child in children_method():
                variables.extend(_extract_loop_variables(child))
        except Exception:
            pass
    return variables


def get_keywords_for_mode(language_mode: LanguageMode) -> list[str]:
    """Return keyword set appropriate for the active language mode."""
    if language_mode is LanguageMode.YARA_L:
        return YARAL_KEYWORDS
    if language_mode is LanguageMode.YARA_X:
        return YARAX_KEYWORDS
    return KEYWORDS
