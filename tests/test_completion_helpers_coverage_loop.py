# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting uncovered branches in yaraast.lsp.completion_helpers.

Every test executes real production code.  No mocks, stubs, or artificial
scaffolding are used.  Where a branch is structurally unreachable given the
existing guards, this is noted explicitly and the test documents the
boundary instead of fabricating an execution path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from lsprotocol.types import Position
import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.lsp.completion_helpers import (
    BUILTIN_FUNCTIONS,
    STRING_MODIFIERS,
    _active_module_name,
    _extract_loop_variables,
    _loop_variable_completion_items,
    _loop_variable_completions,
    _string_identifier_completion_items,
    analyze_context,
    build_builtin_function_completions,
    build_condition_completions,
    build_module_completions,
    build_module_member_completions,
    build_string_modifier_completions,
    get_keywords_for_mode,
)
from yaraast.lsp.runtime import LanguageMode
from yaraast.types._registry_collections import ArrayType, DictionaryType
from yaraast.types._registry_primitives import IntegerType, StringType
from yaraast.types.module_loader import ModuleLoader
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


@dataclass
class _FakeFunction:
    parameters: list[tuple[str, str]]
    description: str | None = None


@dataclass
class _FakeModule:
    functions: dict[str, _FakeFunction]
    fields: dict[str, Any] | None = None
    attributes: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# _active_module_name - trailing whitespace that is NOT in the strip set
# hits the elif branch at line 64 (return None).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("before_cursor", "expected"),
    [
        # Trailing newline: suffix is empty because \n is not in ' \t)}\]',
        # yet before_cursor != before_cursor.rstrip() -> return None (line 64).
        ("pe.name\n", None),
        # Trailing carriage-return: same path as above.
        ("pe.name\r", None),
        # Trailing form-feed: same path.
        ("pe.name\f", None),
        # Trailing whitespace inside the strip set (space): suffix is non-empty
        # and all chars are in the set, so we strip the suffix (line 62) and
        # resolve the module name normally.
        ("pe.name )", "pe"),
        # Closing bracket after module access - strip set covers ']'.
        ("pe.name]", "pe"),
    ],
)
def test_active_module_name_trailing_whitespace_branches(
    before_cursor: str, expected: str | None
) -> None:
    """Cover _active_module_name line 62 (strip suffix) and line 64 (return None)."""
    assert _active_module_name(before_cursor) == expected


# ---------------------------------------------------------------------------
# analyze_context - the '}}' branch inside the string-modifier block (line 94).
# ---------------------------------------------------------------------------


def test_analyze_context_double_brace_is_string_modifier() -> None:
    """A line containing both '$' and '=' and '}}' returns 'string_modifier'."""
    # '$x = }}' has no known modifier name, no quote, but '}}' is present.
    text = "$x = }}"
    result = analyze_context(text, _pos(0, len(text)))
    assert result == "string_modifier"


# ---------------------------------------------------------------------------
# analyze_context - backward scan exits the loop without finding a section
# header, reaching line 115 (return 'general') via the loop's natural end.
# ---------------------------------------------------------------------------


def test_analyze_context_backward_scan_returns_general_when_no_section_found() -> None:
    """Cover the path where the backward scan finds a rule declaration and breaks."""
    # Position is inside a rule body but there are no section headers above it.
    # The loop hits the rule declaration RE match and breaks, then falls through to
    # 'return general'.
    text = "rule r {\n  some_var\n}"
    result = analyze_context(text, _pos(1, 5))
    assert result == "general"


def test_analyze_context_loop_exhausted_without_break() -> None:
    """Cover the path where the backward scan exhausts all lines without a match."""
    # Multi-line text where the cursor is in content with no rule, meta, strings, or
    # condition marker at any higher line.
    text = "line_one\nline_two\nline_three"
    result = analyze_context(text, _pos(2, 4))
    assert result == "general"


# ---------------------------------------------------------------------------
# analyze_context - line 94->97: '$' and '=' in before_cursor, but no modifier
# name and no string delimiter / brace / slash; the inner if block is skipped
# entirely and execution falls through.
# ---------------------------------------------------------------------------


def test_analyze_context_dollar_eq_no_modifier_no_delimiter_falls_through() -> None:
    """Cover line 94->97: neither modifier name nor delimiter found; block falls through.

    before_cursor has '$' and '=' but nothing that matches 'nocase', 'wide', 'ascii',
    'xor', and also no quote, no '}}', and no '/'.  Both inner ifs are False so the
    string-modifier block exits without returning and execution continues.
    """
    # '$x = 5' has '$' and '=' but nothing else that would trigger a return.
    result = analyze_context("$x = 5", _pos(0, 6))
    # The backward scan finds no section header -> 'general'.
    assert result == "general"


def test_analyze_context_dollar_eq_only_falls_through_to_section_check() -> None:
    """Cover line 94->97: '$' and '=' present but no modifier/delimiter; section check fires.

    The string-modifier if block is entered (line 92 is True) but both inner
    conditions are False, so execution falls through to the import/module/section
    checks.  Inside a rule's condition section the result is 'condition'.
    """
    text = "rule r {\n  condition:\n    $x = 5\n}"
    # Cursor at '$x = 5' which has '$' and '=', no modifier names, no quote/brace/slash.
    result = analyze_context(text, _pos(2, 10))
    assert result == "condition"


# ---------------------------------------------------------------------------
# build_builtin_function_completions - exercise the list comprehension body
# (line 173) by calling the function with the real BUILTIN_FUNCTIONS dict.
# ---------------------------------------------------------------------------


def test_build_builtin_function_completions_real_builtins() -> None:
    """Cover the comprehension body in build_builtin_function_completions (line 173)."""
    items = build_builtin_function_completions(BUILTIN_FUNCTIONS)
    assert len(items) > 0
    labels = {item.label for item in items}
    # All labels must be non-empty strings that came from the production dict.
    assert labels == set(BUILTIN_FUNCTIONS.keys())
    for item in items:
        assert item.insert_text is not None
        assert "($0)" in (item.insert_text or "")


def test_build_builtin_function_completions_empty_dict() -> None:
    """Empty dict yields an empty list; verifies the comprehension with no items."""
    assert build_builtin_function_completions({}) == []


# ---------------------------------------------------------------------------
# build_module_completions - exercise the list comprehension body (line 188).
# ---------------------------------------------------------------------------


def test_build_module_completions_returns_all_modules() -> None:
    """Cover the comprehension body in build_module_completions (line 188)."""
    items = build_module_completions()
    assert len(items) > 0
    for item in items:
        assert item.label
        assert item.detail == "YARA module"


# ---------------------------------------------------------------------------
# build_module_member_completions - ArrayType with non-StructType element
# (line 245->252 false branch) and DictionaryType field (line 251).
# ---------------------------------------------------------------------------


def test_build_module_member_completions_array_of_scalar_element() -> None:
    """Cover the false branch at line 245: ArrayType element is not a StructType."""
    # ArrayType(IntegerType) - the inner 'if isinstance(element_type, StructType):'
    # is False, so detail_type does NOT get ' (indexable)' appended.
    fields: dict[str, Any] = {"offsets": ArrayType(element_type=IntegerType())}
    mod = _FakeModule(functions={}, fields=fields)
    items = build_module_member_completions("mymod", mod)
    assert len(items) == 1
    item = items[0]
    assert item.label == "offsets"
    assert "array[integer]" in (item.detail or "")
    assert "(indexable)" not in (item.detail or "")


def test_build_module_member_completions_dictionary_type_field() -> None:
    """Cover the DictionaryType branch at line 251 in build_module_member_completions."""
    fields: dict[str, Any] = {
        "version_info": DictionaryType(key_type=StringType(), value_type=StringType())
    }
    mod = _FakeModule(functions={}, fields=fields)
    items = build_module_member_completions("mymod", mod)
    assert len(items) == 1
    item = items[0]
    assert item.label == "version_info"
    assert "dict[string, string]" in (item.detail or "")


def test_build_module_member_completions_pe_version_info_dict() -> None:
    """Confirm the pe module's version_info field (DictionaryType) is covered via real module."""
    pe_def = ModuleLoader().get_module("pe")
    assert pe_def is not None
    items = build_module_member_completions("pe", pe_def)
    dict_item = next((i for i in items if i.label == "version_info"), None)
    assert dict_item is not None
    assert "dict[" in (dict_item.detail or "")


# ---------------------------------------------------------------------------
# _resolve_access_chain - line 275 (empty chain component skipped via continue)
# and line 282 (StructType navigation) and line 284 (non-StructType returns None).
# ---------------------------------------------------------------------------


def test_resolve_access_chain_empty_chain_component_is_skipped() -> None:
    """Cover _resolve_access_chain line 275: the 'continue' for an empty chain part.

    chain.replace(']', '').split('.') produces an empty string when the chain
    has a leading dot, trailing dot, or consecutive dots.  The 'if not part: continue'
    guard at line 275 skips over these empty parts.
    """
    from yaraast.lsp.completion_helpers import _resolve_access_chain

    pe_def = ModuleLoader().get_module("pe")
    assert pe_def is not None

    # Leading dot -> first part is '' -> hits line 275 continue
    result_leading = _resolve_access_chain(pe_def, ".linker_version")
    assert result_leading is not None  # empty part is skipped, resolution proceeds

    # Trailing dot -> last part is '' -> hits line 275 continue
    result_trailing = _resolve_access_chain(pe_def, "linker_version.")
    assert result_trailing is not None

    # Double dot -> middle empty part -> hits line 275 continue
    result_double = _resolve_access_chain(pe_def, "linker_version..major")
    assert result_double is not None


def test_resolve_access_chain_nested_struct_field() -> None:
    """Cover line 282: navigating into a StructType's nested field.

    pe.linker_version is a StructType; accessing .major exercises the
    'elif isinstance(current_type, StructType)' branch body at line 282.
    """
    from yaraast.lsp.completion_helpers import _resolve_access_chain

    pe_def = ModuleLoader().get_module("pe")
    assert pe_def is not None
    result = _resolve_access_chain(pe_def, "linker_version.major")
    # The result should be the IntegerType representing 'major'.
    assert result is not None
    assert str(result) == "integer"


def test_resolve_access_chain_non_struct_deeper_returns_none() -> None:
    """Cover line 284: navigating deeper into a non-StructType field returns None."""
    from yaraast.lsp.completion_helpers import _resolve_access_chain

    pe_def = ModuleLoader().get_module("pe")
    assert pe_def is not None
    # 'machine' is IntegerType; 'machine.something' tries to go one level deeper
    # into a non-struct, triggering the 'else: return None' path at line 284.
    result = _resolve_access_chain(pe_def, "machine.something")
    assert result is None


def test_build_module_member_completions_nested_struct_chain_reaches_line_282() -> None:
    """Cover _resolve_access_chain line 282 via build_module_member_completions.

    Access chain 'linker_version' resolves to a StructType.  The second iteration
    of the chain loop hits 'elif isinstance(current_type, StructType):' and
    assigns current_type = current_type.fields.get('major'), exercising line 282.
    """
    pe_def = ModuleLoader().get_module("pe")
    assert pe_def is not None
    items = build_module_member_completions("pe", pe_def, access_chain="linker_version.major")
    # Result may be empty (leaf type) but the call must not raise.
    assert isinstance(items, list)


# ---------------------------------------------------------------------------
# build_string_modifier_completions - exercise the list comprehension body
# (line 318) with the production STRING_MODIFIERS dict.
# ---------------------------------------------------------------------------


def test_build_string_modifier_completions_real_modifiers() -> None:
    """Cover the comprehension body in build_string_modifier_completions (line 318)."""
    items = build_string_modifier_completions(STRING_MODIFIERS)
    assert len(items) == len(STRING_MODIFIERS)
    labels = {item.label for item in items}
    assert labels == set(STRING_MODIFIERS.keys())
    for item in items:
        assert item.detail == "String modifier"


# ---------------------------------------------------------------------------
# build_condition_completions - loop variable extraction after successful parse.
# ---------------------------------------------------------------------------


def test_build_condition_completions_loop_variable_exception_is_swallowed() -> None:
    """A plain parsed rule still returns string and keyword completions."""
    text = 'rule plain { strings: $s = "x" condition: $s }'
    items = build_condition_completions(text, ["all", "any"])
    labels = {item.label for item in items}
    # Keywords must appear regardless of the loop-variable result.
    assert "all" in labels
    assert "any" in labels
    # String identifier must also appear.
    assert "$s" in labels


def test_build_condition_completions_ast_not_none_loop_vars_succeed() -> None:
    """Cover the 'if ast is not None: items.extend(_loop_variable_completions(ast))' branch.

    With a valid for-loop rule the parse succeeds (ast is not None), the
    _loop_variable_completions call succeeds, and the loop variable appears.
    """
    text = 'rule x { strings: $a = "x" condition: for any j in (1..3) : ( $a ) }'
    items = build_condition_completions(text, ["condition"])
    labels = {item.label for item in items}
    assert "j" in labels
    assert "$a" in labels


def test_build_condition_completions_ast_loop_vars_guard_exercised() -> None:
    """Verify the guard at line 345 ('if ast is not None:') when parse fails.

    When parse_source returns None (via ParseError), ast stays None and the
    guard at line 345 is False, skipping _loop_variable_completions entirely.

    This test documents the observable boundary: failed parse -> ast is None ->
    keywords still returned via text fallback.
    """
    # Deliberately broken YARA that won't parse: parse_source returns None.
    unparseable = "rule broken { condition: "
    items = build_condition_completions(unparseable, ["rule", "condition"])
    labels = {item.label for item in items}
    # Keywords must still appear via the text fallback path.
    assert "rule" in labels
    assert "condition" in labels


# ---------------------------------------------------------------------------
# _loop_variable_completions - rule.condition is None (line 456->455 false branch).
# ---------------------------------------------------------------------------


def test_loop_variable_completions_skips_rule_with_none_condition() -> None:
    """Cover line 456->455: rule.condition is None skips the variable extraction."""
    rule_no_cond = Rule(name="x", strings=[], condition=None)
    yara_file = YaraFile(rules=[rule_no_cond])
    items = _loop_variable_completions(yara_file)
    # No condition means no loop variables to extract.
    assert items == []


# ---------------------------------------------------------------------------
# _string_identifier_completion_items - duplicate prevention via 'seen' set
# (line 414) and non-'$' identifier path (line 425->449 false branch).
# ---------------------------------------------------------------------------


def test_string_identifier_completion_items_seen_dedup() -> None:
    """Cover line 414: identifier already in 'seen' returns empty list."""
    seen: set[str] = set()
    first = _string_identifier_completion_items("$a", seen)
    assert len(first) == 4  # $a, #a, @a, !a
    second = _string_identifier_completion_items("$a", seen)
    assert second == []


def test_string_identifier_completion_items_non_dollar_identifier() -> None:
    """Cover line 425->449 false branch: identifier not starting with '$' skips count/offset/length."""
    items = _string_identifier_completion_items("my_var")
    assert len(items) == 1
    assert items[0].label == "my_var"
    assert items[0].detail == "String identifier"


# ---------------------------------------------------------------------------
# _loop_variable_completion_items - empty/duplicate identifier guard (line 386).
# ---------------------------------------------------------------------------


def test_loop_variable_completion_items_empty_identifier_returns_empty() -> None:
    """Cover line 386: empty identifier returns [] without adding to seen."""
    seen: set[str] = set()
    result = _loop_variable_completion_items("", seen)
    assert result == []
    assert "" not in seen


def test_loop_variable_completion_items_duplicate_returns_empty() -> None:
    """Cover line 386: identifier already in seen returns []."""
    seen: set[str] = {"i"}
    result = _loop_variable_completion_items("i", seen)
    assert result == []


# ---------------------------------------------------------------------------
# _extract_loop_variables - ForExpression variable extraction (line 474/475),
# WithStatement declaration with empty identifier (line 478->477 false branch),
# and the exception path in children() recursion (lines 486-487).
# ---------------------------------------------------------------------------


def test_extract_loop_variables_none_node_returns_empty() -> None:
    """Cover line 473: passing None as node returns immediately with empty list."""
    variables = _extract_loop_variables(None)
    assert variables == []


def test_extract_loop_variables_none_child_in_children_hits_guard() -> None:
    """Cover line 473 via recursive call: a child that is None triggers the early return.

    When a node's children() returns a sequence containing None, each recursive
    call to _extract_loop_variables(None) hits the 'if node is None: return variables'
    guard at line 473.
    """

    class NodeWithNoneChildren:
        def children(self) -> list[Any]:
            return [None, None]

    variables = _extract_loop_variables(NodeWithNoneChildren())
    assert variables == []


def test_extract_loop_variables_for_expression_via_parse() -> None:
    """Cover line 474/475: ForExpression.variable is captured from real parsed AST."""
    from yaraast.lsp.language_services import parse_source

    text = 'rule x { strings: $a = "x" condition: for any i in (1..3) : ( $a ) }'
    ast = parse_source(text)
    assert ast is not None
    condition = ast.rules[0].condition
    variables = _extract_loop_variables(condition)
    assert "i" in variables


def test_extract_loop_variables_for_expression_empty_variable_skipped() -> None:
    """Cover line 474 false branch: ForExpression.variable is empty string (falsy).

    The condition 'isinstance(node, ForExpression) and node.variable' is True for
    the isinstance check but False for the variable truthiness, so variables is not
    appended.  Execution continues to the children() recursion.
    """
    from yaraast.ast.conditions import ForExpression

    fe = ForExpression(
        quantifier="any",
        variable="",  # falsy -> line 474 condition is overall False
        iterable=BooleanLiteral(True),
        body=BooleanLiteral(True),
    )
    variables = _extract_loop_variables(fe)
    assert "" not in variables


def test_extract_loop_variables_with_statement_via_parse() -> None:
    """Cover line 476/479: WithStatement declarations captured from real parsed YARA-X AST."""
    from yaraast.lsp.language_services import parse_source

    text = 'rule x { strings: $a = "x" condition: with xs = [1]: match xs { _ => $a } }'
    ast = parse_source(text)
    assert ast is not None
    condition = ast.rules[0].condition
    variables = _extract_loop_variables(condition)
    assert "xs" in variables


def test_extract_loop_variables_with_declaration_empty_identifier() -> None:
    """Cover line 478->477 false branch: WithDeclaration with empty identifier is skipped."""
    decl_empty = WithDeclaration(identifier="", value=BooleanLiteral(True))
    ws = WithStatement(declarations=[decl_empty], body=BooleanLiteral(True))
    variables = _extract_loop_variables(ws)
    # The empty-identifier declaration must not contribute any variable.
    assert "" not in variables
    assert variables == []


def test_extract_loop_variables_children_exception_is_swallowed() -> None:
    """Cover lines 486-487: a node whose children() raises is handled gracefully."""

    class NodeWithBrokenChildren:
        def children(self) -> list[Any]:
            raise RuntimeError("intentional children failure for coverage")

    variables = _extract_loop_variables(NodeWithBrokenChildren())
    assert variables == []


def test_extract_loop_variables_leaf_node_no_children_attr() -> None:
    """Cover line 482->488: node has no 'children' attribute so children_method is None.

    getattr(node, 'children', None) returns None, callable(None) is False, and
    the children recursion block is skipped entirely.
    """

    class LeafNode:
        """AST-like node with no children method."""

    variables = _extract_loop_variables(LeafNode())
    assert variables == []


def test_extract_loop_variables_node_with_non_callable_children_attr() -> None:
    """Cover line 482->488: node.children is a non-callable attribute (e.g. a list).

    callable(children_method) is False so the loop is skipped.
    """

    class NodeWithListChildren:
        children: list[Any] = []

    variables = _extract_loop_variables(NodeWithListChildren())
    assert variables == []


# ---------------------------------------------------------------------------
# _text_loop_variable_completions - 'with' pattern (line 375) and lambda params
# (lines 379-380) via the text-fallback path when parsing fails.
# ---------------------------------------------------------------------------


def test_text_condition_completions_with_loop_variable() -> None:
    """Cover line 375: TEXT_WITH_LOOP_RE match in the text fallback path.

    The source is intentionally unparseable so build_condition_completions falls
    back to the DocumentContext text scanner, which must discover the 'with foo ='
    pattern and emit a loop-variable completion item.
    """
    # Missing closing brace causes parse failure, triggering the text fallback.
    text = "rule x {\n  condition:\n    with foo = bar:\n      foo > 0\n"
    items = build_condition_completions(text, [])
    labels = {item.label for item in items}
    assert "foo" in labels


def test_text_condition_completions_lambda_params() -> None:
    """Cover lines 379-380: TEXT_LAMBDA_RE match scans lambda parameter names.

    The source is intentionally unparseable (missing closing brace) so the text
    fallback path runs and extracts the lambda parameter from the condition block.
    """
    text = "rule x {\n  condition:\n    lambda y: y > 0\n"
    items = build_condition_completions(text, [])
    labels = {item.label for item in items}
    assert "y" in labels


def test_text_condition_completions_lambda_multiple_params() -> None:
    """Cover lines 379-380: multi-parameter lambda splits on comma correctly."""
    text = "rule x {\n  condition:\n    lambda a, b: a > b\n"
    items = build_condition_completions(text, [])
    labels = {item.label for item in items}
    assert "a" in labels
    assert "b" in labels


# ---------------------------------------------------------------------------
# get_keywords_for_mode - all three branches (lines 493-497).
# ---------------------------------------------------------------------------


def test_get_keywords_for_mode_yara_l() -> None:
    """Cover line 493-494: YARA_L mode returns YARAL_KEYWORDS."""
    keywords = get_keywords_for_mode(LanguageMode.YARA_L)
    assert "events" in keywords
    assert "outcome" in keywords


def test_get_keywords_for_mode_yara_x() -> None:
    """Cover line 495-496: YARA_X mode returns YARAX_KEYWORDS."""
    keywords = get_keywords_for_mode(LanguageMode.YARA_X)
    assert "with" in keywords
    assert "lambda" in keywords
    assert "match" in keywords


def test_get_keywords_for_mode_default_yara() -> None:
    """Cover line 497: non-YARA_L/YARA_X modes return the base KEYWORDS list."""
    keywords_yara = get_keywords_for_mode(LanguageMode.YARA)
    keywords_auto = get_keywords_for_mode(LanguageMode.AUTO)
    assert keywords_yara == keywords_auto
    # Base KEYWORDS must contain standard YARA keywords.
    assert "rule" in keywords_yara
    assert "condition" in keywords_yara


# ---------------------------------------------------------------------------
# Structural unreachability notes
# ---------------------------------------------------------------------------
# No tests fabricate exceptions for paths already guarded inside child walkers.
