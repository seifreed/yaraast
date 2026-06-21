# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering missing lines in json_serialize_visitors.py.

Each test exercises a real production code path identified by coverage analysis.
No mocks, stubs, or artificial scaffolding are used.

NOTE — lines 210-216 (_serialize_ast_value body):
    _serialize_ast_value is defined in json_serialize_visitors.py but is never
    called from json_serializer.py or any other production caller outside its own
    recursive body.  It is dead production code unreachable from the public
    JsonSerializer API.  Those lines are excluded from this file; reaching them
    would require calling the untyped private helper directly, which violates the
    project's mypy gate (no-untyped-call errors cannot be suppressed).
"""

from __future__ import annotations

import base64
from enum import Enum
import json as _json
from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment
from yaraast.ast.expressions import Identifier as _Identifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexNegatedByte,
    HexNibble,
    HexString,
)
from yaraast.errors import SerializationError
from yaraast.serialization import json_serialize_visitors as visitors
from yaraast.serialization.json_serializer import JsonSerializer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serializer() -> JsonSerializer:
    return JsonSerializer()


# ---------------------------------------------------------------------------
# _serialize_pragma_parameter_value — integer branch (line 99)
# ---------------------------------------------------------------------------


def test_pragma_parameter_value_returns_integer() -> None:
    """Integer values must pass through the integer branch and be returned as-is."""
    result = visitors._serialize_pragma_parameter_value(42)
    assert result == 42
    assert isinstance(result, int)


def test_pragma_parameter_value_returns_zero_integer() -> None:
    """Zero is a valid integer pragma value."""
    result = visitors._serialize_pragma_parameter_value(0)
    assert result == 0


# ---------------------------------------------------------------------------
# _serialize_meta_entry_value — integer branch (line 119)
# ---------------------------------------------------------------------------


def test_meta_entry_value_returns_integer() -> None:
    """Integer meta entry values must be returned unchanged."""
    result = visitors._serialize_meta_entry_value(7)
    assert result == 7
    assert isinstance(result, int)


def test_meta_entry_value_returns_negative_integer() -> None:
    """Negative integers are valid meta entry values."""
    result = visitors._serialize_meta_entry_value(-3)
    assert result == -3


# ---------------------------------------------------------------------------
# _serialize_hex_negated_value — two-char hex string (line 164) and
# negated nibble pattern (lines 165->167)
# ---------------------------------------------------------------------------


def test_hex_negated_value_accepts_two_char_hex_string() -> None:
    """A two-character uppercase hex string is a valid negated byte value."""
    result = visitors._serialize_hex_negated_value("AF")
    assert result == "AF"


def test_hex_negated_value_accepts_two_char_lowercase_hex_string() -> None:
    """A two-character lowercase hex string is a valid negated byte value."""
    result = visitors._serialize_hex_negated_value("ab")
    assert result == "ab"


def test_hex_negated_value_accepts_negated_nibble_high() -> None:
    """A '?X' pattern (negated high nibble) is valid and must be returned."""
    result = visitors._serialize_hex_negated_value("?A")
    assert result == "?A"


def test_hex_negated_value_accepts_negated_nibble_low() -> None:
    """An 'X?' pattern (negated low nibble) is valid and must be returned."""
    result = visitors._serialize_hex_negated_value("F?")
    assert result == "F?"


def test_hex_negated_value_rejects_invalid_string() -> None:
    """A string that is neither a two-char hex nor a nibble pattern must fail."""
    with pytest.raises(SerializationError, match="HexNegatedByte"):
        visitors._serialize_hex_negated_value("ZZ")


# ---------------------------------------------------------------------------
# _serialize_hex_nibble_value — str branch returning value (line 204)
# ---------------------------------------------------------------------------


def test_hex_nibble_value_accepts_single_char_hex_string() -> None:
    """A single hex character is a valid nibble string value."""
    result = visitors._serialize_hex_nibble_value("A")
    assert result == "A"


def test_hex_nibble_value_accepts_single_lowercase_char() -> None:
    """A single lowercase hex character is accepted."""
    result = visitors._serialize_hex_nibble_value("f")
    assert result == "f"


def test_hex_nibble_value_rejects_invalid_char() -> None:
    """A non-hex character must be rejected."""
    with pytest.raises(SerializationError, match="HexNibble"):
        visitors._serialize_hex_nibble_value("Z")


# ---------------------------------------------------------------------------
# _serialize_expression_list — non-list/tuple input raises error (lines 244-245)
# ---------------------------------------------------------------------------


def test_serialize_expression_list_rejects_non_list() -> None:
    """Passing a non-list to _serialize_expression_list must raise SerializationError."""
    serializer = _serializer()
    with pytest.raises(SerializationError, match="must be a list of AST expressions"):
        visitors._serialize_expression_list(
            serializer, cast(Any, "not a list"), "SetExpression elements"
        )


def test_serialize_expression_list_rejects_dict() -> None:
    """A dict is not a valid expression list."""
    serializer = _serializer()
    with pytest.raises(SerializationError, match="must be a list of AST expressions"):
        visitors._serialize_expression_list(
            serializer, cast(Any, {"key": "val"}), "TupleExpression"
        )


# ---------------------------------------------------------------------------
# _serialize_string_set — frozenset empty error (lines 293-294)
# ---------------------------------------------------------------------------


def test_serialize_string_set_rejects_empty_frozenset() -> None:
    """An empty frozenset string_set must raise SerializationError."""
    serializer = _serializer()
    with pytest.raises(SerializationError, match="must contain values"):
        visitors._serialize_string_set(serializer, frozenset(), "OfExpression")


def test_serialize_string_set_accepts_nonempty_frozenset() -> None:
    """A non-empty frozenset of string identifiers must be serialized as a sorted list."""
    serializer = _serializer()
    result = visitors._serialize_string_set(serializer, frozenset({"$b", "$a"}), "OfExpression")
    assert isinstance(result, list)
    assert len(result) == 2
    assert "$a" in result
    assert "$b" in result


# ---------------------------------------------------------------------------
# _serialize_string_or_expression — str with validate_string_reference (line 317)
# ---------------------------------------------------------------------------


def test_serialize_string_or_expression_validates_string_reference() -> None:
    """When validate_string_reference=True, a valid $id must pass through validated."""
    serializer = _serializer()
    result = visitors._serialize_string_or_expression(
        serializer, "$s1", "AtExpression string_id", validate_string_reference=True
    )
    assert result == "$s1"


def test_serialize_string_or_expression_returns_plain_string_when_no_validation() -> None:
    """When validate_string_reference=False (default), a string is returned as-is."""
    serializer = _serializer()
    result = visitors._serialize_string_or_expression(serializer, "$foo", "DictionaryAccess key")
    assert result == "$foo"


# ---------------------------------------------------------------------------
# _serialize_plain_string_value — surrogate character error (lines 366-367)
# and non-str/non-bytes error (lines 362-364)
# ---------------------------------------------------------------------------


def test_serialize_plain_string_value_rejects_lone_surrogate() -> None:
    """A string containing a lone surrogate (U+D800..U+DFFF) must raise SerializationError."""
    data: dict[str, Any] = {}
    with pytest.raises(SerializationError, match="UTF-8 encodable"):
        visitors._serialize_plain_string_value(data, "\ud800")


def test_serialize_plain_string_value_rejects_high_surrogate() -> None:
    """High surrogate U+DFFF is also rejected as non-UTF-8-encodable."""
    data: dict[str, Any] = {}
    with pytest.raises(SerializationError, match="UTF-8 encodable"):
        visitors._serialize_plain_string_value(data, "\udfff")


def test_serialize_plain_string_value_rejects_integer() -> None:
    """An integer is neither str nor bytes; must raise SerializationError.

    cast(Any, ...) is used so that mypy sees an Any-typed argument, allowing
    the deliberately invalid runtime type to reach the production guard without
    requiring an inline suppression comment.
    """
    data: dict[str, Any] = {}
    with pytest.raises(SerializationError, match="must be a string or bytes"):
        visitors._serialize_plain_string_value(data, cast(Any, 42))


def test_serialize_plain_string_value_accepts_valid_string() -> None:
    """A valid UTF-8 string must be stored in data['value']."""
    data: dict[str, Any] = {}
    visitors._serialize_plain_string_value(data, "hello")
    assert data["value"] == "hello"
    assert "value_encoding" not in data


def test_serialize_plain_string_value_accepts_bytes() -> None:
    """Bytes must be base64-encoded and stored with value_encoding='base64'."""
    data: dict[str, Any] = {}
    payload = b"\x4d\x5a\x90"
    visitors._serialize_plain_string_value(data, payload)
    assert data["value_encoding"] == "base64"
    assert base64.b64decode(data["value"]) == payload


# ---------------------------------------------------------------------------
# _serialize_plain_string_raw_bytes — non-bytes error (lines 375-376)
# ---------------------------------------------------------------------------


def test_serialize_plain_string_raw_bytes_rejects_string() -> None:
    """A str passed as raw_bytes must raise SerializationError."""
    data: dict[str, Any] = {}
    with pytest.raises(SerializationError, match="raw_bytes must be bytes or None"):
        visitors._serialize_plain_string_raw_bytes(data, cast(Any, "not bytes"))


def test_serialize_plain_string_raw_bytes_rejects_integer() -> None:
    """An integer passed as raw_bytes must raise SerializationError."""
    data: dict[str, Any] = {}
    with pytest.raises(SerializationError, match="raw_bytes must be bytes or None"):
        visitors._serialize_plain_string_raw_bytes(data, cast(Any, 0))


def test_serialize_plain_string_raw_bytes_accepts_none() -> None:
    """None raw_bytes must produce no effect on data."""
    data: dict[str, Any] = {}
    visitors._serialize_plain_string_raw_bytes(data, None)
    assert "raw_value" not in data


# ---------------------------------------------------------------------------
# _serialize_dynamic_node_metadata — all branches (lines 393->396, 398-399,
# 401, 410-413)
# ---------------------------------------------------------------------------


class _MetaWithLocation:
    """Non-AST meta-like object carrying a location but no leading/trailing comments."""

    key: str = "author"
    value: str = "test"
    location: Location = Location(line=1, column=1)
    leading_comments: list[Comment] = []
    trailing_comment: None = None


class _MetaWithLeadingComments:
    """Non-AST meta-like object carrying leading comments."""

    key: str = "description"
    value: str = "sample"
    location: None = None
    leading_comments: list[Comment]
    trailing_comment: None = None

    def __init__(self) -> None:
        self.leading_comments = [Comment(text="// a comment")]


class _MetaWithBadLeadingComments:
    """Non-AST meta-like object with non-list leading_comments."""

    key: str = "description"
    value: str = "bad"
    location: None = None
    leading_comments: str = "not a list"
    trailing_comment: None = None


class _MetaWithTrailingComment:
    """Non-AST meta-like object carrying a trailing comment."""

    key: str = "version"
    value: str = "1.0"
    location: None = None
    leading_comments: list[Comment] = []
    trailing_comment: Comment = Comment(text="// trailing")


class _MetaWithBadTrailingComment:
    """Non-AST meta-like object with an invalid trailing_comment type."""

    key: str = "version"
    value: str = "1.0"
    location: None = None
    leading_comments: list[Comment] = []
    trailing_comment: str = "not a comment"


def test_dynamic_node_metadata_serializes_location() -> None:
    """A valid Location on a non-accept object must appear in the serialized dict."""
    serializer = _serializer()
    data: dict[str, Any] = {"type": "Meta", "key": "author", "value": "test"}
    obj = _MetaWithLocation()
    result = visitors._serialize_dynamic_node_metadata(serializer, obj, data)
    assert "location" in result
    assert result["location"]["line"] == 1
    assert result["location"]["column"] == 1


def test_dynamic_node_metadata_serializes_leading_comments() -> None:
    """A non-empty leading_comments list must be serialized and included."""
    serializer = _serializer()
    data: dict[str, Any] = {"type": "Meta", "key": "description", "value": "sample"}
    obj = _MetaWithLeadingComments()
    result = visitors._serialize_dynamic_node_metadata(serializer, obj, data)
    assert "leading_comments" in result
    assert len(result["leading_comments"]) == 1
    assert result["leading_comments"][0]["type"] == "Comment"


def test_dynamic_node_metadata_rejects_non_list_leading_comments() -> None:
    """A non-list leading_comments attribute must raise SerializationError."""
    serializer = _serializer()
    data: dict[str, Any] = {"type": "Meta", "key": "description", "value": "bad"}
    obj = _MetaWithBadLeadingComments()
    with pytest.raises(SerializationError, match="leading_comments must be a list"):
        visitors._serialize_dynamic_node_metadata(serializer, obj, data)


def test_dynamic_node_metadata_serializes_trailing_comment() -> None:
    """A valid trailing Comment must be serialized and included in the result."""
    serializer = _serializer()
    data: dict[str, Any] = {"type": "Meta", "key": "version", "value": "1.0"}
    obj = _MetaWithTrailingComment()
    result = visitors._serialize_dynamic_node_metadata(serializer, obj, data)
    assert "trailing_comment" in result
    assert result["trailing_comment"]["type"] == "Comment"


def test_dynamic_node_metadata_rejects_bad_trailing_comment() -> None:
    """A trailing_comment that is not a Comment or CommentGroup must raise."""
    serializer = _serializer()
    data: dict[str, Any] = {"type": "Meta", "key": "version", "value": "1.0"}
    obj = _MetaWithBadTrailingComment()
    with pytest.raises(SerializationError, match="trailing_comment must be a Comment"):
        visitors._serialize_dynamic_node_metadata(serializer, obj, data)


def test_serialize_meta_entry_dispatches_to_dynamic_metadata_path() -> None:
    """_serialize_meta_entry must route objects without accept() through dynamic metadata."""
    serializer = _serializer()
    obj = _MetaWithLocation()
    result = visitors._serialize_meta_entry(serializer, obj)
    assert result["type"] == "Meta"
    assert "location" in result
    assert result["location"]["line"] == 1


# ---------------------------------------------------------------------------
# _serialize_enum_value — non-str enum object branch (line 446)
# ---------------------------------------------------------------------------


class _SampleScope(Enum):
    """Minimal enum simulating a scope value with a .value string."""

    PUBLIC = "public"
    PRIVATE = "private"


def test_serialize_enum_value_from_enum_object() -> None:
    """An Enum instance must have its .value extracted and returned as a string."""
    result = visitors._serialize_enum_value(_SampleScope.PUBLIC, "scope")
    assert result == "public"


def test_serialize_enum_value_from_enum_private() -> None:
    """Private scope enum must return the string 'private'."""
    result = visitors._serialize_enum_value(_SampleScope.PRIVATE, "scope")
    assert result == "private"


def test_serialize_enum_value_from_plain_string() -> None:
    """A plain non-empty string must be returned as-is from the str branch."""
    result = visitors._serialize_enum_value("public", "scope")
    assert result == "public"


# ---------------------------------------------------------------------------
# _validate_hex_token_sequence — empty branch inside nested alternative
# (lines 668-669)
# ---------------------------------------------------------------------------


def test_validate_hex_token_sequence_rejects_empty_nested_branch() -> None:
    """An HexAlternative whose nested alternative branch is empty must raise."""
    inner_alt = HexAlternative(alternatives=[[HexByte(0x90)], []])
    tokens = [HexByte(0x4D), inner_alt, HexByte(0x5A)]
    with pytest.raises(SerializationError, match="must not be empty"):
        visitors._validate_hex_token_sequence(tokens, "hex string", inside_alternative=False)


def test_validate_hex_token_sequence_accepts_valid_nested_alternative() -> None:
    """A valid nested HexAlternative with non-empty branches must not raise."""
    inner_alt = HexAlternative(alternatives=[[HexByte(0x90)], [HexByte(0x91)]])
    tokens = [HexByte(0x4D), inner_alt, HexByte(0x5A)]
    visitors._validate_hex_token_sequence(tokens, "hex string", inside_alternative=False)


# ---------------------------------------------------------------------------
# Integration: HexNegatedByte and HexNibble round-trip through JsonSerializer
# ---------------------------------------------------------------------------


def test_hex_negated_byte_with_nibble_pattern_round_trips() -> None:
    """A HexNegatedByte holding a nibble pattern (?A) must serialize without error."""
    serializer = _serializer()
    neg = HexNegatedByte(value="?A")
    hex_str = HexString(
        identifier="$h",
        tokens=[HexByte(0x4D), neg, HexByte(0x5A)],
        modifiers=[],
    )
    rule = Rule(name="r", strings=[hex_str])
    out = serializer.serialize(YaraFile(rules=[rule]))
    doc = _json.loads(out)
    tokens = doc["ast"]["rules"][0]["strings"][0]["tokens"]
    negated_token = next(t for t in tokens if t["type"] == "HexNegatedByte")
    assert negated_token["value"] == "?A"


def test_hex_nibble_with_char_value_round_trips() -> None:
    """A HexNibble holding a char value ('F') must serialize without error."""
    serializer = _serializer()
    nib = HexNibble(high=True, value="F")
    hex_str = HexString(
        identifier="$n",
        tokens=[HexByte(0x4D), nib, HexByte(0x5A)],
        modifiers=[],
    )
    rule = Rule(name="r2", strings=[hex_str])
    out = serializer.serialize(YaraFile(rules=[rule]))
    doc = _json.loads(out)
    tokens = doc["ast"]["rules"][0]["strings"][0]["tokens"]
    nibble_token = next(t for t in tokens if t["type"] == "HexNibble")
    assert nibble_token["value"] == "F"
    assert nibble_token["high"] is True


# ---------------------------------------------------------------------------
# Identifier serialization via JsonSerializer — exercises accept() path
# that _serialize_ast_value would cover if it had callers
# ---------------------------------------------------------------------------


def test_identifier_serializes_via_public_api() -> None:
    """An Identifier node serialized through JsonSerializer produces valid JSON."""
    serializer = _serializer()
    node = _Identifier(name="pe")
    result = serializer.visit(node)
    assert isinstance(result, dict)
    assert result["type"] == "Identifier"
    assert result["name"] == "pe"
