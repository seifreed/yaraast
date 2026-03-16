from __future__ import annotations

"""Central re-export module for LSP document query helpers."""

from .document_query_lookup import (
    get_dotted_symbol_at_position,
    get_include_info,
    get_include_target_uri,
    get_meta_value,
    get_module_member_info,
    get_string_definition_info,
    get_string_definition_node,
)
from .document_query_references import (
    build_string_rename_edits,
    find_rule_definition,
    find_string_reference_records,
    find_string_references,
    get_local_rule_link_records,
    rename_rule_edits,
    rule_occurrences,
    rule_reference_records,
)
from .document_query_resolution import resolve_symbol

__all__ = [
    "build_string_rename_edits",
    "find_rule_definition",
    "find_string_reference_records",
    "find_string_references",
    "get_dotted_symbol_at_position",
    "get_include_info",
    "get_include_target_uri",
    "get_local_rule_link_records",
    "get_meta_value",
    "get_module_member_info",
    "get_string_definition_info",
    "get_string_definition_node",
    "rename_rule_edits",
    "resolve_symbol",
    "rule_occurrences",
    "rule_reference_records",
]
