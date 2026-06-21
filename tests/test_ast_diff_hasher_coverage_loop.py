# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering remaining uncovered lines in ast_diff_hasher.py.

Each test exercises a specific uncovered line or branch through the real public
API of AstHasher and its helper functions.  No mocks or stubs are used.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.extern import ExternImport, ExternRuleReference
from yaraast.ast.strings import HexByte
from yaraast.serialization.ast_diff_hasher import (
    AstHasher,
    _meta_value_repr,
    _optional_string_attr,
    _required_string_attr,
    _validate_real_expression,
    _validate_real_hex_token,
)

# ---------------------------------------------------------------------------
# _meta_value_repr — bool branch (line 22)
# ---------------------------------------------------------------------------


def test_meta_value_repr_bool_true() -> None:
    """Line 22: bool True produces a type-prefixed representation."""
    result = _meta_value_repr(True)
    assert result == "bool:True"


def test_meta_value_repr_bool_false() -> None:
    """Line 22: bool False produces a type-prefixed representation."""
    result = _meta_value_repr(False)
    assert result == "bool:False"


# ---------------------------------------------------------------------------
# _meta_value_repr — float branch (line 26)
# ---------------------------------------------------------------------------


def test_meta_value_repr_float() -> None:
    """Line 26: float value produces a type-prefixed representation."""
    result = _meta_value_repr(3.14)
    assert result == "float:3.14"


# ---------------------------------------------------------------------------
# _meta_value_repr — str branch (line 28)
# ---------------------------------------------------------------------------


def test_meta_value_repr_string() -> None:
    """Line 28: str value produces a type-prefixed representation."""
    result = _meta_value_repr("hello")
    assert result == "str:hello"


# ---------------------------------------------------------------------------
# _meta_value_repr — fallback for unknown type (line 29)
# ---------------------------------------------------------------------------


def test_meta_value_repr_fallback_for_unknown_type() -> None:
    """Line 29: an unrecognised type uses the class name as prefix."""
    result = _meta_value_repr([1, 2, 3])
    assert result == "list:[1, 2, 3]"


# ---------------------------------------------------------------------------
# _validate_real_hex_token — False branch of callable check (branch 35->exit)
# ---------------------------------------------------------------------------


def test_validate_real_hex_token_non_callable_validate_structure_is_silently_skipped() -> None:
    """Branch 35->exit: when validate_structure exists but is not callable, it is skipped.

    We use object.__new__ to bypass the dataclass constructor and assign a
    non-callable value to validate_structure so the branch fires.
    """
    node = HexByte.__new__(HexByte)
    node.validate_structure = "not_a_function"  # type: ignore[assignment]
    node.value = 0x00
    # Should complete without error — the non-callable branch silently exits
    _validate_real_hex_token(node)


# ---------------------------------------------------------------------------
# _validate_real_expression — False branch of callable check (branch 42->exit)
# ---------------------------------------------------------------------------


def test_validate_real_expression_non_callable_validate_structure_is_silently_skipped() -> None:
    """Branch 42->exit: when validate_structure is not callable, it is skipped."""
    node = BooleanLiteral.__new__(BooleanLiteral)
    node.validate_structure = "not_a_function"  # type: ignore[assignment]
    node.value = True
    _validate_real_expression(node)


# ---------------------------------------------------------------------------
# visit_yara_file — True branch of isinstance check (branch 65->67 False side)
# ---------------------------------------------------------------------------


def test_visit_yara_file_with_non_yara_file_skips_validate_structure() -> None:
    """Branch 65->False (to line 67): when node is not a YaraFile instance,
    validate_structure is skipped and hashing proceeds from imports_hash.

    A SimpleNamespace with the same attributes as YaraFile satisfies the
    attribute access without being an instance of YaraFile.
    """
    hasher = AstHasher()
    fake = SimpleNamespace(
        imports=[],
        includes=[],
        rules=[],
        extern_rules=[],
        extern_imports=[],
        pragmas=[],
        namespaces=[],
    )
    result = hasher.visit_yara_file(fake)  # type: ignore[arg-type]
    assert result.startswith("YaraFile(")


# ---------------------------------------------------------------------------
# visit_rule — False branch of isinstance check (branch 96->98 False side)
# ---------------------------------------------------------------------------


def test_visit_rule_with_non_rule_node_skips_validate_structure() -> None:
    """Branch 96->False (to line 98): when node is not a Rule instance,
    validate_structure is skipped and hashing proceeds directly to name lookup.
    """
    hasher = AstHasher()
    fake = SimpleNamespace(
        name="fake_rule",
        modifiers=[],
        tags=[],
        meta=[],
        strings=[],
        condition=None,
        pragmas=[],
    )
    result = hasher.visit_rule(fake)
    assert result.startswith("Rule(fake_rule,")


# ---------------------------------------------------------------------------
# visit_pragma — False branch of isinstance(node, Pragma) check (branch 631->633)
# ---------------------------------------------------------------------------


def test_visit_pragma_with_non_pragma_instance_having_pragma_type_skips_validate() -> None:
    """Branch 631->633: a node that has 'pragma_type' but is NOT a Pragma instance
    skips validate_structure and goes directly to args hashing at line 633.

    SimpleNamespace with the required fields exercises the False branch.
    """
    hasher = AstHasher()

    fake_pragma_type = SimpleNamespace(value="custom")
    fake_scope = SimpleNamespace(value="file")
    fake = SimpleNamespace(
        pragma_type=fake_pragma_type,
        name="mypragma",
        arguments=[],
        scope=fake_scope,
        # No macro_name, macro_value, condition, or parameters
    )
    result = hasher.visit_pragma(fake)
    assert "Pragma(custom,mypragma" in result


# ---------------------------------------------------------------------------
# _required_string_attr — TypeError branch (lines 658-659)
# ---------------------------------------------------------------------------


def test_required_string_attr_raises_type_error_when_value_is_not_string() -> None:
    """Lines 658-659: when the attribute value is not a str, TypeError is raised."""
    node = SimpleNamespace(myfield=42)
    with pytest.raises(TypeError, match="MyField must be a string"):
        _required_string_attr(node, "myfield", "MyField")


# ---------------------------------------------------------------------------
# _optional_string_attr — TypeError branch (lines 668-669)
# ---------------------------------------------------------------------------


def test_optional_string_attr_raises_type_error_when_value_is_non_string_non_none() -> None:
    """Lines 668-669: when the attribute exists, is not None, and is not a str,
    TypeError is raised.
    """
    node = SimpleNamespace(alias=99)
    with pytest.raises(TypeError, match="MyAlias must be a string"):
        _optional_string_attr(node, "alias", "MyAlias")


# ---------------------------------------------------------------------------
# _hash_value — list/tuple branch (line 426) and set/frozenset branch (line 428)
# ---------------------------------------------------------------------------


def test_hash_value_with_list_of_ast_nodes() -> None:
    """Line 426: a list of AST nodes is hashed as a bracketed pipe-separated string."""
    hasher = AstHasher()
    nodes = [IntegerLiteral(value=1), IntegerLiteral(value=2)]
    result = hasher._hash_value(nodes)
    assert result == "[Int(1)|Int(2)]"


def test_hash_value_with_tuple_of_scalars() -> None:
    """Line 426: a tuple falls into the same list|tuple branch."""
    hasher = AstHasher()
    result = hasher._hash_value((10, 20))
    assert result == "[10|20]"


def test_hash_value_with_frozenset() -> None:
    """Line 428: a frozenset is hashed in sorted order."""
    hasher = AstHasher()
    result = hasher._hash_value(frozenset({"alpha", "beta", "gamma"}))
    assert result == "[alpha|beta|gamma]"


def test_hash_value_with_set() -> None:
    """Line 428: a plain set follows the same frozenset branch."""
    hasher = AstHasher()
    result = hasher._hash_value({"z", "a"})
    assert result == "[a|z]"


# ---------------------------------------------------------------------------
# _hash_string_set — list/tuple/set/frozenset fallback branch (line 441)
# ---------------------------------------------------------------------------


def test_hash_string_set_with_non_string_set_list() -> None:
    """Line 441: when _string_set_items returns None for a list, _hash_value is used.

    A list containing an IntegerLiteral cannot be mapped to string-set items
    so _string_set_container_items returns None, falling through to line 441.
    """
    hasher = AstHasher()
    elements = [IntegerLiteral(value=99)]
    result = hasher._hash_string_set(elements)
    assert result == "[Int(99)]"


# ---------------------------------------------------------------------------
# _string_set_items — single non-container item returns [item] (line 463)
# ---------------------------------------------------------------------------


def test_string_set_items_with_single_string_wildcard_returns_list() -> None:
    """Line 463: a single non-container StringWildcard returns a one-element list."""
    hasher = AstHasher()
    wildcard = StringWildcard(pattern="them")
    result = hasher._string_set_items(wildcard)
    assert result == ["them"]


# ---------------------------------------------------------------------------
# _string_set_item — Identifier with non-string name raises TypeError (lines 480-481)
# ---------------------------------------------------------------------------


def test_string_set_item_identifier_non_string_name_raises_type_error() -> None:
    """Lines 480-481: Identifier with non-string name raises TypeError.

    The dataclass type annotation is bypassed via object construction so the
    runtime check on line 479 fires and raises TypeError at line 481.
    """
    node = Identifier.__new__(Identifier)
    node.name = 42  # type: ignore[assignment]
    with pytest.raises(TypeError, match="String reference must be a string"):
        AstHasher._string_set_item(node)


# ---------------------------------------------------------------------------
# _string_set_item — Identifier "them" and "$..." branches
# ---------------------------------------------------------------------------


def test_string_set_item_identifier_them() -> None:
    """Identifier named 'them' is treated as a valid string-set item."""
    result = AstHasher._string_set_item(Identifier(name="them"))
    assert result == "them"


def test_string_set_item_identifier_dollar_prefix() -> None:
    """Identifier starting with '$' is treated as a valid string-set item."""
    result = AstHasher._string_set_item(Identifier(name="$foo"))
    assert result == "$foo"


# ---------------------------------------------------------------------------
# _string_set_item — Identifier not "them" and not "$" prefix returns None (line 484)
# ---------------------------------------------------------------------------


def test_string_set_item_identifier_plain_name_returns_none() -> None:
    """Line 484: an Identifier with an unrelated name falls through to return None."""
    result = AstHasher._string_set_item(Identifier(name="ordinary_var"))
    assert result is None


# ---------------------------------------------------------------------------
# _string_set_item — StringIdentifier with non-string name raises TypeError (lines 487-488)
# ---------------------------------------------------------------------------


def test_string_set_item_string_identifier_non_string_name_raises_type_error() -> None:
    """Lines 487-488: StringIdentifier with non-string name raises TypeError."""
    node = StringIdentifier.__new__(StringIdentifier)
    node.name = 99  # type: ignore[assignment]
    with pytest.raises(TypeError, match="String reference must be a string"):
        AstHasher._string_set_item(node)


def test_string_set_item_string_identifier() -> None:
    """StringIdentifier with valid name is returned as a raw string-set item."""
    result = AstHasher._string_set_item(StringIdentifier(name="$bar"))
    assert result == "$bar"


# ---------------------------------------------------------------------------
# _string_set_item — StringWildcard with non-string pattern raises TypeError (lines 492-493)
# ---------------------------------------------------------------------------


def test_string_set_item_string_wildcard_non_string_pattern_raises_type_error() -> None:
    """Lines 492-493: StringWildcard with non-string pattern raises TypeError."""
    node = StringWildcard.__new__(StringWildcard)
    node.pattern = 77  # type: ignore[assignment]
    with pytest.raises(TypeError, match="String reference must be a string"):
        AstHasher._string_set_item(node)


def test_string_set_item_string_wildcard_them_pattern() -> None:
    """StringWildcard with pattern not starting with '$' is returned directly."""
    result = AstHasher._string_set_item(StringWildcard(pattern="them"))
    assert result == "them"


# ---------------------------------------------------------------------------
# _string_set_item — StringLiteral with non-string value raises TypeError (lines 499-500)
# ---------------------------------------------------------------------------


def test_string_set_item_string_literal_non_string_value_raises_type_error() -> None:
    """Lines 499-500: StringLiteral with non-string value raises TypeError."""
    node = StringLiteral.__new__(StringLiteral)
    node.value = 55  # type: ignore[assignment]
    with pytest.raises(TypeError, match="String reference must be a string"):
        AstHasher._string_set_item(node)


def test_string_set_item_string_literal() -> None:
    """StringLiteral value is wrapped with a '$' prefix via _raw_string_set_item."""
    result = AstHasher._string_set_item(StringLiteral(value="sig"))
    assert result == "$sig"


# ---------------------------------------------------------------------------
# visit_extern_import — module_path branch (else side when 'module' attr absent)
# ---------------------------------------------------------------------------


def test_visit_extern_import_uses_module_path_when_module_attr_absent() -> None:
    """The else branch: ExternImport has 'module_path', not 'module'."""
    hasher = AstHasher()
    ext_import = ExternImport(module_path="rules/common")
    assert not hasattr(ext_import, "module")
    result = hasher.visit_extern_import(ext_import)
    assert result == "ExternImport(rules/common,None,)"


# ---------------------------------------------------------------------------
# visit_extern_rule_reference — rule_name branch (else side when 'name' attr absent)
# ---------------------------------------------------------------------------


def test_visit_extern_rule_reference_uses_rule_name_when_name_attr_absent() -> None:
    """The else branch: ExternRuleReference has 'rule_name', not 'name'."""
    hasher = AstHasher()
    ref = ExternRuleReference(rule_name="DetectMalware")
    assert not hasattr(ref, "name")
    result = hasher.visit_extern_rule_reference(ref)
    assert result == "ExternRuleRef(DetectMalware,None)"


# ---------------------------------------------------------------------------
# visit_in_rule_pragma — position is None branch
# ---------------------------------------------------------------------------


def test_visit_in_rule_pragma_without_position_attribute() -> None:
    """When the node has no 'position' attr, _optional_string_attr returns None
    and the no-position branch produces 'InRulePragma(...)' without a position.
    """
    hasher = AstHasher()
    fake_node = SimpleNamespace(pragma="")
    result = hasher.visit_in_rule_pragma(fake_node)
    assert result == "InRulePragma()"


def test_visit_in_rule_pragma_with_explicit_none_position() -> None:
    """When position is explicitly None, the no-position branch runs."""
    hasher = AstHasher()
    fake_node = SimpleNamespace(pragma="", position=None)
    result = hasher.visit_in_rule_pragma(fake_node)
    assert result == "InRulePragma()"


# ---------------------------------------------------------------------------
# Integration: hash_ast exercising the YaraFile path end-to-end
# ---------------------------------------------------------------------------


def test_hash_ast_produces_deterministic_hex_digest() -> None:
    """hash_ast returns a 16-character hex digest that is stable across calls."""
    hasher = AstHasher()
    yara_file = YaraFile()
    result1 = hasher.hash_ast(yara_file)
    result2 = hasher.hash_ast(yara_file)
    assert result1 == result2
    assert len(result1) == 16
    assert all(c in "0123456789abcdef" for c in result1)
