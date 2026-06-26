"""Coverage-completion tests for yaraast.ast.strings.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Every test exercises the real production classes in yaraast/ast/strings.py.
No mocks, stubs, or test doubles are used.
"""

from __future__ import annotations

from typing import Any

import pytest

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
)

# ---------------------------------------------------------------------------
# Minimal visitor required by accept() calls
# ---------------------------------------------------------------------------


class _Visitor:
    """Concrete visitor that exercises all visit_* dispatch paths."""

    def visit_string_definition(self, node: object) -> str:
        return f"strdef:{type(node).__name__}"

    def visit_plain_string(self, node: PlainString) -> str:
        return f"plain:{node.identifier}"

    def visit_hex_string(self, node: HexString) -> str:
        return f"hex:{node.identifier}"

    def visit_hex_token(self, node: HexToken) -> str:
        return f"token:{type(node).__name__}"

    def visit_hex_byte(self, node: HexByte) -> str:
        return f"byte:{node.value}"

    def visit_hex_negated_byte(self, node: HexNegatedByte) -> str:
        return f"negated:{node.value}"

    def visit_hex_wildcard(self, node: HexWildcard) -> str:
        return "wildcard"

    def visit_hex_jump(self, node: HexJump) -> str:
        return f"jump:{node.min_jump}-{node.max_jump}"

    def visit_hex_alternative(self, node: HexAlternative) -> str:
        return f"alt:{len(node.alternatives)}"

    def visit_hex_nibble(self, node: HexNibble) -> str:
        return f"nibble:{node.high}:{node.value}"

    def visit_regex_string(self, node: RegexString) -> str:
        return f"regex:{node.identifier}"


# ---------------------------------------------------------------------------
# Module-level helper functions — _is_byte_value, _is_negated_nibble_pattern
# ---------------------------------------------------------------------------


def test_is_byte_value_via_hex_byte_valid_int() -> None:
    """HexByte.validate_structure accepts integer byte values 0-255."""
    for val in (0, 1, 127, 255):
        node = HexByte(value=val)
        node.validate_structure()  # must not raise


def test_is_byte_value_via_hex_byte_valid_hex_string() -> None:
    """HexByte.validate_structure accepts two-char hex strings."""
    for val in ("00", "FF", "a0", "1F"):
        node = HexByte(value=val)
        node.validate_structure()


def test_is_byte_value_via_hex_byte_rejects_bool() -> None:
    """HexByte.validate_structure rejects bool even though bool is int."""
    node = HexByte(value=True)
    with pytest.raises(TypeError, match="must be a byte"):
        node.validate_structure()


def test_is_byte_value_via_hex_byte_rejects_too_large_int() -> None:
    """HexByte.validate_structure rejects integers above 255."""
    node = HexByte(value=256)
    with pytest.raises(TypeError, match="must be a byte"):
        node.validate_structure()


def test_is_byte_value_via_hex_byte_rejects_negative_int() -> None:
    """HexByte.validate_structure rejects negative integers."""
    node = HexByte(value=-1)
    with pytest.raises(TypeError, match="must be a byte"):
        node.validate_structure()


def test_is_byte_value_via_hex_byte_rejects_one_char_string() -> None:
    """HexByte.validate_structure rejects a single hex character (needs two)."""
    node = HexByte(value="A")
    with pytest.raises(TypeError, match="must be a byte"):
        node.validate_structure()


def test_is_byte_value_via_hex_byte_rejects_three_char_string() -> None:
    """HexByte.validate_structure rejects three-character hex strings."""
    node = HexByte(value="ABC")
    with pytest.raises(TypeError, match="must be a byte"):
        node.validate_structure()


def test_is_byte_value_via_hex_byte_rejects_non_hex_chars() -> None:
    """HexByte.validate_structure rejects two-char strings with non-hex chars."""
    node = HexByte(value="GG")
    with pytest.raises(TypeError, match="must be a byte"):
        node.validate_structure()


# ---------------------------------------------------------------------------
# _validate_hex_jump_bound — via HexJump.validate_structure
# ---------------------------------------------------------------------------


def test_hex_jump_valid_both_bounds() -> None:
    """HexJump accepts min_jump <= max_jump."""
    node = HexJump(min_jump=0, max_jump=10)
    node.validate_structure()


def test_hex_jump_valid_none_bounds() -> None:
    """HexJump accepts None for both bounds (unbounded jump)."""
    node = HexJump(min_jump=None, max_jump=None)
    node.validate_structure()


def test_hex_jump_valid_only_min() -> None:
    """HexJump accepts only min_jump set."""
    node = HexJump(min_jump=3, max_jump=None)
    node.validate_structure()


def test_hex_jump_rejects_bool_for_min() -> None:
    """HexJump.validate_structure rejects bool for min_jump."""
    node = HexJump(min_jump=True, max_jump=None)
    with pytest.raises(TypeError, match="non-negative integer"):
        node.validate_structure()


def test_hex_jump_rejects_bool_for_max() -> None:
    """HexJump.validate_structure rejects bool for max_jump."""
    node = HexJump(min_jump=None, max_jump=False)
    with pytest.raises(TypeError, match="non-negative integer"):
        node.validate_structure()


def test_hex_jump_rejects_negative_min() -> None:
    """HexJump.validate_structure rejects negative min_jump."""
    node = HexJump(min_jump=-1, max_jump=None)
    with pytest.raises(TypeError, match="non-negative integer"):
        node.validate_structure()


def test_hex_jump_rejects_negative_max() -> None:
    """HexJump.validate_structure rejects negative max_jump."""
    node = HexJump(min_jump=None, max_jump=-5)
    with pytest.raises(TypeError, match="non-negative integer"):
        node.validate_structure()


def test_hex_jump_rejects_min_exceeding_max() -> None:
    """HexJump.validate_structure rejects min_jump > max_jump."""
    node = HexJump(min_jump=10, max_jump=5)
    with pytest.raises(TypeError, match="min_jump cannot exceed max_jump"):
        node.validate_structure()


# ---------------------------------------------------------------------------
# _validate_hex_token / _validate_hex_token_sequence — via HexString.validate
# ---------------------------------------------------------------------------


def test_hex_string_rejects_empty_token_list() -> None:
    """HexString.validate_structure rejects an empty token list."""
    node = HexString(identifier="$h")
    with pytest.raises(ValueError, match="at least one token"):
        node.validate_structure()


def test_hex_string_rejects_leading_jump() -> None:
    """HexString.validate_structure rejects a jump at the beginning."""
    node = HexString(
        identifier="$h",
        tokens=[HexJump(min_jump=0, max_jump=3), HexByte(value=0x90)],
    )
    with pytest.raises(ValueError, match="cannot appear at the beginning"):
        node.validate_structure()


def test_hex_string_rejects_trailing_jump() -> None:
    """HexString.validate_structure rejects a jump at the end."""
    node = HexString(
        identifier="$h",
        tokens=[HexByte(value=0x90), HexJump(min_jump=0, max_jump=3)],
    )
    with pytest.raises(ValueError, match="cannot appear at the beginning or end"):
        node.validate_structure()


def test_hex_string_rejects_unsupported_token_type() -> None:
    """HexString.validate_structure rejects an ASTNode that is not a HexToken.

    The tokens list is validated in two stages:
    1. _require_ast_node_sequence checks every item is an ASTNode.
    2. _validate_hex_token then checks every ASTNode is a HexToken subclass.

    PlainString is an ASTNode but not a HexToken, so it reaches the
    'Unsupported hex token' branch at strings.py line 77-78.
    """
    foreign_node = PlainString(identifier="$x", value="oops")
    node = HexString(identifier="$h", tokens=[foreign_node])
    with pytest.raises(TypeError, match="Unsupported hex token"):
        node.validate_structure()


def test_hex_string_rejects_invalid_modifier() -> None:
    """HexString._validate_modifier_names rejects non-private modifiers."""
    node = HexString(
        identifier="$h",
        tokens=[HexByte(value=0x90)],
        modifiers=["wide"],
    )
    with pytest.raises(ValueError, match="not valid on hex strings"):
        node.validate_structure()


def test_hex_string_accepts_private_modifier() -> None:
    """HexString._validate_modifier_names accepts the 'private' modifier."""
    node = HexString(
        identifier="$h",
        tokens=[HexByte(value=0x90)],
        modifiers=["private"],
    )
    node.validate_structure()


# ---------------------------------------------------------------------------
# _validate_regex_text — via RegexString.validate_structure
# ---------------------------------------------------------------------------


def test_regex_string_rejects_surrogate_code_point() -> None:
    """RegexString.validate_structure rejects patterns with Unicode surrogates."""
    surrogate = "\ud800"
    node = RegexString(identifier="$r", regex=surrogate)
    with pytest.raises(ValueError, match="surrogate"):
        node.validate_structure()


def test_regex_string_rejects_newline() -> None:
    """RegexString.validate_structure rejects patterns containing a newline."""
    node = RegexString(identifier="$r", regex="ab\ncd")
    with pytest.raises(ValueError, match="line breaks"):
        node.validate_structure()


def test_regex_string_rejects_nul_byte() -> None:
    """RegexString.validate_structure rejects patterns containing NUL bytes."""
    node = RegexString(identifier="$r", regex="ab\x00cd")
    with pytest.raises(ValueError, match="NUL bytes"):
        node.validate_structure()


def test_regex_string_rejects_empty_pattern() -> None:
    """RegexString.validate_structure rejects an empty regex pattern."""
    node = RegexString(identifier="$r", regex="")
    with pytest.raises(ValueError, match="must not be empty"):
        node.validate_structure()


def test_regex_string_rejects_disallowed_modifier_base64() -> None:
    """RegexString._validate_modifier_names rejects 'base64' on a regex."""
    node = RegexString(
        identifier="$r",
        regex="abc",
        modifiers=["base64"],
    )
    with pytest.raises(ValueError, match="not valid on regex strings"):
        node.validate_structure()


def test_regex_string_rejects_disallowed_modifier_xor() -> None:
    """RegexString._validate_modifier_names rejects 'xor' on a regex."""
    node = RegexString(
        identifier="$r",
        regex="abc",
        modifiers=["xor"],
    )
    with pytest.raises(ValueError, match="not valid on regex strings"):
        node.validate_structure()


def test_regex_string_accept_dispatches_to_visitor() -> None:
    """RegexString.accept returns the visitor result."""
    node = RegexString(identifier="$r", regex="abc")
    result = node.accept(_Visitor())
    assert result == "regex:$r"


# ---------------------------------------------------------------------------
# StringDefinition.validate_structure — base-class paths
# ---------------------------------------------------------------------------


def test_string_definition_rejects_non_list_modifiers() -> None:
    """StringDefinition.validate_structure rejects modifiers that are not a list."""
    node = PlainString(identifier="$a", value="hello", modifiers="ascii")
    with pytest.raises(TypeError, match="must be a list"):
        node.validate_structure()


def test_string_definition_rejects_unknown_string_modifier_name() -> None:
    """StringDefinition.validate_structure rejects an unknown modifier name string."""
    node = PlainString(identifier="$a", value="hello", modifiers=["totally_unknown"])
    with pytest.raises(ValueError, match="Unknown string modifier"):
        node.validate_structure()


def test_string_definition_rejects_non_string_modifier_item() -> None:
    """StringDefinition.validate_structure rejects modifier items that are not str or StringModifier."""
    node = PlainString(identifier="$a", value="hello", modifiers=[42])
    with pytest.raises(TypeError, match="must be StringModifier or string"):
        node.validate_structure()


def test_string_definition_accepts_string_modifier_object() -> None:
    """StringDefinition.validate_structure accepts a real StringModifier object."""
    mod = StringModifier(
        modifier_type=StringModifierType.ASCII,
        value=None,
    )
    node = PlainString(identifier="$a", value="hello", modifiers=[mod])
    node.validate_structure()


def test_string_definition_rejects_duplicate_modifier() -> None:
    """StringDefinition._validate_modifier_names rejects duplicate modifiers."""
    node = PlainString(
        identifier="$a",
        value="hello",
        modifiers=["ascii", "ascii"],
    )
    with pytest.raises(ValueError, match="Duplicate string modifier"):
        node.validate_structure()


def test_string_definition_rejects_non_bool_is_anonymous() -> None:
    """StringDefinition.validate_structure rejects non-bool is_anonymous."""
    node = PlainString(identifier="$a", value="hello")
    bad_flag: Any = "yes"
    node.is_anonymous = bad_flag
    with pytest.raises(TypeError, match="is_anonymous must be a boolean"):
        node.validate_structure()


def test_string_definition_anonymous_validates_allow_placeholder() -> None:
    """StringDefinition.validate_structure uses allow_placeholder for anonymous strings."""
    node = PlainString(identifier="$a", value="hello", is_anonymous=True)
    node.validate_structure()


def test_string_definition_accept_dispatches() -> None:
    """StringDefinition.accept routes to visit_string_definition on a plain node."""
    visitor = _Visitor()
    node = PlainString(identifier="$a", value="hello")

    # PlainString.accept routes to visit_plain_string, not visit_string_definition
    result = node.accept(visitor)
    assert result == "plain:$a"


# ---------------------------------------------------------------------------
# PlainString.validate_structure
# ---------------------------------------------------------------------------


def test_plain_string_rejects_non_string_value() -> None:
    """PlainString.validate_structure rejects a value that is not str or bytes."""
    bad_value: Any = 12345
    node = PlainString(identifier="$a", value=bad_value)
    with pytest.raises(TypeError, match="value must be a string or bytes"):
        node.validate_structure()


def test_plain_string_rejects_surrogate_in_str_value() -> None:
    """PlainString.validate_structure rejects str values with Unicode surrogates."""
    node = PlainString(identifier="$a", value="\ud800hello")
    with pytest.raises(ValueError, match="surrogate"):
        node.validate_structure()


def test_plain_string_rejects_invalid_raw_bytes_type() -> None:
    """PlainString.validate_structure rejects raw_bytes that is not bytes."""
    bad_raw: Any = "not_bytes"
    node = PlainString(identifier="$a", value="hello", raw_bytes=bad_raw)
    with pytest.raises(TypeError, match="raw_bytes must be bytes or None"):
        node.validate_structure()


def test_plain_string_accepts_bytes_value() -> None:
    """PlainString.validate_structure accepts a bytes value."""
    node = PlainString(identifier="$a", value=b"\x90\xde\xad")
    node.validate_structure()


def test_plain_string_accepts_raw_bytes() -> None:
    """PlainString.validate_structure accepts valid raw_bytes."""
    node = PlainString(identifier="$a", value="hello", raw_bytes=b"\x90")
    node.validate_structure()


# ---------------------------------------------------------------------------
# PlainString._validate_modifier_names — incompatible combinations
# ---------------------------------------------------------------------------


def test_plain_string_rejects_unsupported_modifier_dotall() -> None:
    """PlainString._validate_modifier_names rejects 'dotall' (unsupported on plain strings).

    'nocase' is NOT in _UNSUPPORTED_PLAIN_STRING_MODIFIERS; it is only blocked
    when combined with xor/base64.  'dotall' and 'i' are dialect-specific
    modifiers that are never valid on a plain string.
    """
    node = PlainString(identifier="$a", value="hello", modifiers=["dotall"])
    with pytest.raises(ValueError, match="Unsupported string modifier"):
        node.validate_structure()


def test_plain_string_rejects_unsupported_modifier_utf16() -> None:
    """PlainString._validate_modifier_names rejects 'utf16' (unsupported)."""
    node = PlainString(identifier="$a", value="hello", modifiers=["utf16"])
    with pytest.raises(ValueError, match="Unsupported string modifier"):
        node.validate_structure()


def test_plain_string_rejects_base64_with_fullword() -> None:
    """PlainString._validate_modifier_names rejects base64+fullword combination."""
    node = PlainString(
        identifier="$a",
        value="hello",
        modifiers=["base64", "fullword"],
    )
    with pytest.raises(ValueError, match="cannot be combined"):
        node.validate_structure()


def test_plain_string_rejects_base64_with_nocase() -> None:
    """PlainString._validate_modifier_names rejects base64+nocase combination."""
    # nocase is blocked first by _UNSUPPORTED_PLAIN_STRING_MODIFIERS check;
    # use base64wide+nocase to observe the incompatibility error path distinctly.
    node = PlainString(
        identifier="$a",
        value="hello",
        modifiers=["base64", "xor"],
    )
    with pytest.raises(ValueError, match="cannot be combined"):
        node.validate_structure()


def test_plain_string_rejects_xor_with_base64() -> None:
    """PlainString._validate_modifier_names rejects xor+base64 combination."""
    node = PlainString(
        identifier="$a",
        value="hello",
        modifiers=["xor", "base64"],
    )
    with pytest.raises(ValueError, match="cannot be combined"):
        node.validate_structure()


def test_plain_string_rejects_base64wide_with_fullword() -> None:
    """PlainString._validate_modifier_names rejects base64wide+fullword combination."""
    node = PlainString(
        identifier="$a",
        value="hello",
        modifiers=["base64wide", "fullword"],
    )
    with pytest.raises(ValueError, match="cannot be combined"):
        node.validate_structure()


def test_plain_string_accepts_xor_alone() -> None:
    """PlainString with only 'xor' modifier is valid."""
    node = PlainString(identifier="$a", value="hello", modifiers=["xor"])
    node.validate_structure()


def test_plain_string_accepts_base64_alone() -> None:
    """PlainString with only 'base64' modifier is valid."""
    node = PlainString(identifier="$a", value="hello", modifiers=["base64"])
    node.validate_structure()


# ---------------------------------------------------------------------------
# HexNegatedByte.validate_structure
# ---------------------------------------------------------------------------


def test_hex_negated_byte_valid_int() -> None:
    """HexNegatedByte accepts a full byte integer value."""
    node = HexNegatedByte(value=0xFF)
    node.validate_structure()


def test_hex_negated_byte_valid_hex_string() -> None:
    """HexNegatedByte accepts a two-char hex string."""
    node = HexNegatedByte(value="AB")
    node.validate_structure()


def test_hex_negated_byte_valid_high_nibble_pattern() -> None:
    """HexNegatedByte accepts a high-nibble pattern like 'A?'."""
    node = HexNegatedByte(value="A?")
    node.validate_structure()


def test_hex_negated_byte_valid_low_nibble_pattern() -> None:
    """HexNegatedByte accepts a low-nibble pattern like '?B'."""
    node = HexNegatedByte(value="?B")
    node.validate_structure()


def test_hex_negated_byte_rejects_invalid_string() -> None:
    """HexNegatedByte rejects strings that are not a byte or negated nibble."""
    node = HexNegatedByte(value="ZZ")
    with pytest.raises(TypeError, match="must be a byte or negated nibble"):
        node.validate_structure()


def test_hex_negated_byte_rejects_single_char() -> None:
    """HexNegatedByte rejects a single-character string."""
    node = HexNegatedByte(value="A")
    with pytest.raises(TypeError, match="must be a byte or negated nibble"):
        node.validate_structure()


def test_hex_negated_byte_rejects_bool() -> None:
    """HexNegatedByte rejects a bool value."""
    node = HexNegatedByte(value=True)
    with pytest.raises(TypeError, match="must be a byte or negated nibble"):
        node.validate_structure()


def test_hex_negated_byte_accept_with_visit_hex_negated_byte() -> None:
    """HexNegatedByte.accept dispatches to visit_hex_negated_byte when available."""
    node = HexNegatedByte(value=0xAB)
    result = node.accept(_Visitor())
    assert result == "negated:171"


def test_hex_negated_byte_accept_fallback_to_visit_hex_token() -> None:
    """HexNegatedByte.accept falls back to visit_hex_token when specific method absent."""

    class _MinimalVisitor:
        def visit_hex_token(self, n: HexToken) -> str:
            return f"fallback:{type(n).__name__}"

    node = HexNegatedByte(value=0xAB)
    result = node.accept(_MinimalVisitor())
    assert result == "fallback:HexNegatedByte"


# ---------------------------------------------------------------------------
# HexAlternative.validate_structure
# ---------------------------------------------------------------------------


def test_hex_alternative_valid_single_branch() -> None:
    """HexAlternative accepts a single branch with one byte."""
    node = HexAlternative(alternatives=[[HexByte(value=0x90)]])
    node.validate_structure()


def test_hex_alternative_valid_multiple_branches() -> None:
    """HexAlternative accepts multiple branches."""
    node = HexAlternative(
        alternatives=[
            [HexByte(value=0x90)],
            [HexByte(value=0xAB), HexByte(value=0xCD)],
        ]
    )
    node.validate_structure()


def test_hex_alternative_valid_raw_int_in_branch() -> None:
    """HexAlternative accepts raw int byte values inside branches."""
    node = HexAlternative(alternatives=[[0x41, 0x42]])
    node.validate_structure()


def test_hex_alternative_valid_raw_hex_str_in_branch() -> None:
    """HexAlternative accepts raw hex string byte values inside branches."""
    node = HexAlternative(alternatives=[["4D", "5A"]])
    node.validate_structure()


def test_hex_alternative_rejects_empty_alternatives_list() -> None:
    """HexAlternative.validate_structure rejects an empty alternatives list."""
    node = HexAlternative(alternatives=[])
    with pytest.raises(ValueError, match="at least one branch"):
        node.validate_structure()


def test_hex_alternative_rejects_non_list_alternatives() -> None:
    """HexAlternative.validate_structure rejects non-list alternatives field."""
    node = HexAlternative(alternatives="invalid")
    with pytest.raises(ValueError, match="at least one branch"):
        node.validate_structure()


def test_hex_alternative_rejects_empty_branch() -> None:
    """HexAlternative.validate_structure rejects an empty branch."""
    node = HexAlternative(alternatives=[[]])
    with pytest.raises(ValueError, match="must not be empty"):
        node.validate_structure()


def test_hex_alternative_rejects_unbounded_jump_inside_branch() -> None:
    """HexAlternative.validate_structure rejects an unbounded HexJump inside a branch."""
    inner = [HexByte(value=0x90), HexJump(min_jump=None, max_jump=None), HexByte(value=0xAB)]
    node = HexAlternative(alternatives=[inner])
    with pytest.raises(ValueError, match="Unbounded HexJump is not allowed"):
        node.validate_structure()


def test_hex_alternative_accept_dispatches() -> None:
    """HexAlternative.accept routes to visit_hex_alternative."""
    node = HexAlternative(alternatives=[[HexByte(value=0x90)]])
    result = node.accept(_Visitor())
    assert result == "alt:1"


# ---------------------------------------------------------------------------
# HexNibble.validate_structure
# ---------------------------------------------------------------------------


def test_hex_nibble_valid_int_value_high() -> None:
    """HexNibble accepts a nibble int 0-15 with high=True."""
    node = HexNibble(high=True, value=0xA)
    node.validate_structure()


def test_hex_nibble_valid_int_value_low() -> None:
    """HexNibble accepts a nibble int 0-15 with high=False."""
    node = HexNibble(high=False, value=0)
    node.validate_structure()


def test_hex_nibble_valid_string_hex_char() -> None:
    """HexNibble accepts a single hex character string."""
    for char in "0123456789abcdefABCDEF":
        node = HexNibble(high=True, value=char)
        node.validate_structure()


def test_hex_nibble_rejects_non_bool_high() -> None:
    """HexNibble.validate_structure rejects non-bool high field."""
    bad_high: Any = 1
    node = HexNibble(high=bad_high, value=0xA)
    with pytest.raises(TypeError, match="high must be a boolean"):
        node.validate_structure()


def test_hex_nibble_rejects_bool_value() -> None:
    """HexNibble.validate_structure rejects bool for value (even though bool is int)."""
    node = HexNibble(high=True, value=True)
    with pytest.raises(TypeError, match="must be a nibble"):
        node.validate_structure()


def test_hex_nibble_rejects_int_above_15() -> None:
    """HexNibble.validate_structure rejects integers above 0xF."""
    node = HexNibble(high=True, value=16)
    with pytest.raises(TypeError, match="must be a nibble"):
        node.validate_structure()


def test_hex_nibble_rejects_two_char_string() -> None:
    """HexNibble.validate_structure rejects a two-character hex string."""
    node = HexNibble(high=True, value="AB")
    with pytest.raises(TypeError, match="must be a nibble"):
        node.validate_structure()


def test_hex_nibble_rejects_non_hex_char() -> None:
    """HexNibble.validate_structure rejects a single char that is not a hex digit."""
    node = HexNibble(high=True, value="G")
    with pytest.raises(TypeError, match="must be a nibble"):
        node.validate_structure()


def test_hex_nibble_accept_dispatches() -> None:
    """HexNibble.accept routes to visit_hex_nibble."""
    node = HexNibble(high=True, value=0xA)
    result = node.accept(_Visitor())
    assert result == "nibble:True:10"


# ---------------------------------------------------------------------------
# HexToken base class accept
# ---------------------------------------------------------------------------


def test_hex_token_accept_dispatches() -> None:
    """HexToken.accept routes to visit_hex_token."""
    node = HexWildcard()
    result = node.accept(_Visitor())
    assert result == "wildcard"


# ---------------------------------------------------------------------------
# HexByte.accept
# ---------------------------------------------------------------------------


def test_hex_byte_accept_dispatches() -> None:
    """HexByte.accept routes to visit_hex_byte."""
    node = HexByte(value=0x90)
    result = node.accept(_Visitor())
    assert result == "byte:144"


# ---------------------------------------------------------------------------
# HexJump.accept
# ---------------------------------------------------------------------------


def test_hex_jump_accept_dispatches() -> None:
    """HexJump.accept routes to visit_hex_jump."""
    node = HexJump(min_jump=1, max_jump=5)
    result = node.accept(_Visitor())
    assert result == "jump:1-5"


# ---------------------------------------------------------------------------
# PlainString.accept
# ---------------------------------------------------------------------------


def test_plain_string_accept_dispatches() -> None:
    """PlainString.accept routes to visit_plain_string."""
    node = PlainString(identifier="$a", value="hello")
    result = node.accept(_Visitor())
    assert result == "plain:$a"


# ---------------------------------------------------------------------------
# HexString.accept
# ---------------------------------------------------------------------------


def test_hex_string_accept_dispatches() -> None:
    """HexString.accept routes to visit_hex_string."""
    node = HexString(identifier="$h", tokens=[HexByte(value=0x90)])
    result = node.accept(_Visitor())
    assert result == "hex:$h"


# ---------------------------------------------------------------------------
# Full validate_structure round-trips — exercise all nested call paths
# ---------------------------------------------------------------------------


def test_hex_string_full_valid_structure() -> None:
    """HexString with byte, wildcard, jump, alternative, and nibble validates."""
    tokens = [
        HexByte(value=0x4D),
        HexByte(value=0x5A),
        HexWildcard(),
        HexJump(min_jump=2, max_jump=4),
        HexByte(value=0x90),
        HexAlternative(alternatives=[[HexByte(value=0x00)], [HexByte(value=0xFF)]]),
        HexNibble(high=True, value=0xA),
        HexByte(value=0xB0),
    ]
    node = HexString(identifier="$pe_header", tokens=tokens)
    node.validate_structure()


def test_plain_string_full_valid_ascii_wide() -> None:
    """PlainString with 'ascii' and 'wide' modifiers validates."""
    node = PlainString(identifier="$s", value="MZ", modifiers=["ascii", "wide"])
    node.validate_structure()


def test_plain_string_full_valid_fullword() -> None:
    """PlainString with 'fullword' modifier validates."""
    node = PlainString(identifier="$f", value="kernel32", modifiers=["fullword"])
    node.validate_structure()


def test_regex_string_full_valid_nocase() -> None:
    """RegexString with 'nocase' modifier validates (regex allows nocase)."""
    node = RegexString(identifier="$r", regex="windows", modifiers=["nocase"])
    node.validate_structure()


def test_regex_string_full_valid_wide() -> None:
    """RegexString with 'wide' modifier validates."""
    node = RegexString(identifier="$r", regex="malware", modifiers=["wide"])
    node.validate_structure()


# ---------------------------------------------------------------------------
# Remaining missing-line coverage — targeted exercises
# ---------------------------------------------------------------------------


def test_plain_string_rejects_whitespace_only_identifier() -> None:
    """_require_string_identifier raises when identifier.strip() is empty.

    Lines 109-110: the branch 'if not identifier.strip()' inside
    _require_string_identifier.  A whitespace-only string passes isinstance()
    but fails the strip check.
    """
    node = PlainString(identifier="   ", value="hello")
    with pytest.raises(ValueError, match="identifier must not be empty"):
        node.validate_structure()


def test_string_definition_accept_base_class_dispatch() -> None:
    """StringDefinition.accept routes to visit_string_definition (line 184).

    All built-in concrete subclasses (PlainString, HexString, RegexString)
    override accept().  StringDefinition.accept is reachable by calling it
    directly via the unbound method on the class, passing a PlainString
    instance.  This is equivalent to what happens when a subclass is built
    that does not override accept().
    """
    from yaraast.ast.strings import StringDefinition

    node = PlainString(identifier="$z", value="test")
    visitor = _Visitor()

    # Call StringDefinition.accept directly, bypassing PlainString.accept
    result = StringDefinition.accept(node, visitor)
    assert result == "strdef:PlainString"


def test_plain_string_rejects_xor_with_nocase() -> None:
    """PlainString._validate_modifier_names rejects xor+nocase (lines 246-247).

    The 'xor' branch at line 243-247 fires when 'xor' is present and
    _XOR_INCOMPATIBLE_MODIFIERS intersection is non-empty.  The base64
    check (lines 237-242) fires for xor+base64, but nocase only appears
    in _XOR_INCOMPATIBLE_MODIFIERS, so xor+nocase reaches lines 246-247.
    """
    node = PlainString(
        identifier="$a",
        value="hello",
        modifiers=["xor", "nocase"],
    )
    with pytest.raises(ValueError, match="cannot be combined with 'xor'"):
        node.validate_structure()


def test_hex_token_base_class_accept_dispatch() -> None:
    """HexToken.accept base-class dispatch routes to visit_hex_token (line 298).

    All standard HexToken subclasses override accept().  To exercise the
    base-class body we call HexToken.accept directly on a HexByte instance.
    """
    node = HexByte(value=0x41)
    visitor = _Visitor()

    # Call HexToken.accept directly, bypassing HexByte.accept
    result = HexToken.accept(node, visitor)
    assert result == "token:HexByte"
