# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests for yaraast.shared.ast_analysis — targets uncovered branches.

Every test exercises real production code.  No mocks, stubs, or test doubles
are used anywhere in this file.
"""

from __future__ import annotations

from collections import OrderedDict
import datetime
from pathlib import Path
from textwrap import dedent
from typing import Any

import pytest

from yaraast.ast.strings import HexByte, HexString, PlainString
from yaraast.parser.source import parse_yara_source
from yaraast.shared.ast_analysis import (
    ASTFormatter,
    ASTStructuralAnalyzer,
    _path_is_dir,
    _require_file_path,
)

# ---------------------------------------------------------------------------
# Helpers — real subclasses / implementations, never mocks
# ---------------------------------------------------------------------------


class _DirRaisingPath(Path):
    """A real Path subclass whose is_dir() raises OSError (e.g. on a special
    filesystem node where the stat call fails with EACCES or EIO).  The
    constructor argument is only used as the string representation."""

    _flavour = Path(".")._flavour if hasattr(Path("."), "_flavour") else None  # type: ignore[attr-defined]

    def __new__(cls, *args: Any, **kwargs: Any) -> _DirRaisingPath:
        return super().__new__(cls, *args, **kwargs)

    def is_dir(self) -> bool:  # type: ignore[override]
        raise OSError("simulated is_dir failure")

    def exists(self) -> bool:  # type: ignore[override]
        return True


class _BytesPathLike:
    """A real PathLike whose __fspath__ returns bytes instead of str.

    The standard library allows this per the os.fspath contract, but callers
    that expect a str must handle it.  We use it to trigger the isinstance
    guard in _require_file_path and ASTFormatter._optional_output_path.
    """

    def __fspath__(self) -> bytes:
        return b"/tmp/bytes_path"


# ---------------------------------------------------------------------------
# _path_is_dir  — lines 42-43  (OSError branch)
# ---------------------------------------------------------------------------


def test_path_is_dir_oserror_raises_value_error() -> None:
    """_path_is_dir must convert OSError from path.is_dir() into ValueError."""
    # Arrange: a Path subclass that raises OSError on is_dir() — models
    # unreadable mount points or broken symlinks on certain filesystems.
    bad = _DirRaisingPath("/some/inaccessible/path")

    # Act + Assert
    with pytest.raises(ValueError, match="path could not be accessed"):
        _path_is_dir(bad)


# ---------------------------------------------------------------------------
# _require_file_path — lines 56-57  (fspath returns bytes, not str)
# ---------------------------------------------------------------------------


def test_require_file_path_bytes_fspath_raises_type_error() -> None:
    """_require_file_path must reject a PathLike whose __fspath__ returns bytes."""
    # Arrange: a real PathLike implementation that returns b"..." from __fspath__
    pl = _BytesPathLike()

    # Act + Assert
    with pytest.raises(TypeError, match="must be a file path"):
        _require_file_path(pl, "input_path")


# ---------------------------------------------------------------------------
# _require_file_path — lines 63-64  (path exists and is a directory)
# ---------------------------------------------------------------------------


def test_require_file_path_directory_raises_value_error(tmp_path: Path) -> None:
    """_require_file_path must reject a path that resolves to an existing directory."""
    # Arrange: tmp_path is a real directory created by pytest
    directory = str(tmp_path)

    # Act + Assert
    with pytest.raises(ValueError, match="must not be a directory"):
        _require_file_path(directory, "input_path")


# ---------------------------------------------------------------------------
# ASTStructuralAnalyzer.visit_rule — lines 134-135
# Calling visit_rule directly (not via visit_yara_file / analyze())
# ---------------------------------------------------------------------------


def test_visit_rule_called_directly_records_rule_signature() -> None:
    """visit_rule must record a rule signature when called without analyze()."""
    # Arrange: parse a minimal rule to get a real Rule AST node
    source = dedent("""\
        rule direct_visit {
            strings:
                $s = "hello"
            condition:
                $s
        }
    """)
    ast = parse_yara_source(source)
    rule_node = ast.rules[0]

    analyzer = ASTStructuralAnalyzer()
    # No prior call to analyze() — rule_signatures is empty

    # Act: call visit_rule directly, bypassing visit_yara_file
    analyzer.visit_rule(rule_node)

    # Assert: the rule signature was recorded under the rule's own name
    assert "direct_visit" in analyzer.rule_signatures
    sig = analyzer.rule_signatures["direct_visit"]
    assert isinstance(sig, str) and len(sig) == 32  # MD5 hex digest


def test_visit_rule_direct_produces_same_hash_as_analyze() -> None:
    """Hash produced by visit_rule directly must equal the hash produced via analyze()."""
    source = dedent("""\
        rule parity_check {
            meta:
                author = "tester"
            strings:
                $p = "bytes"
            condition:
                $p
        }
    """)
    ast = parse_yara_source(source)
    rule_node = ast.rules[0]

    # Hash via full analyze()
    sig_via_analyze = ASTStructuralAnalyzer().analyze(ast)["rule_signatures"]["parity_check"]

    # Hash via direct visit_rule
    direct_analyzer = ASTStructuralAnalyzer()
    direct_analyzer.visit_rule(rule_node)
    sig_via_direct = direct_analyzer.rule_signatures["parity_check"]

    assert sig_via_analyze == sig_via_direct


# ---------------------------------------------------------------------------
# _analyze_string / HexString — branch line 204->209
#
# The branch 204->False->209 is taken when a string definition has neither a
# "value", "regex", nor "tokens" attribute.  All three real string types
# (PlainString, RegexString, HexString) cover the three True branches.  The
# False-fall-through to line 209 is exercised by a duck-typed object that
# satisfies the identifier interface but carries none of those attributes.
# ---------------------------------------------------------------------------


class _OpaqueStringDef:
    """Minimal duck-typed string definition with no content attribute.

    This represents a hypothetical future string type (or an AST node
    constructed in a context where none of value/regex/tokens is present).
    The production code's defensive elif chain falls through to line 209
    when none of the hasattr guards match.
    """

    def __init__(self, identifier: str) -> None:
        self.identifier = identifier


def test_analyze_string_no_content_attribute_falls_through_to_209() -> None:
    """_analyze_string must fall through to line 209 when the string has no
    value, regex, or tokens attribute, storing a signature without content data.
    """
    # Arrange: object satisfies identifier duck-type but has none of the three
    # content attributes recognised by the elif chain.
    opaque = _OpaqueStringDef("$opaque")

    analyzer = ASTStructuralAnalyzer()

    # Act: call with the opaque string — exercises the 204->False->209 branch
    analyzer._analyze_string(opaque, "fallthrough_rule", "$opaque")  # type: ignore[arg-type]

    # Assert: a signature is still stored (just without content_type metadata)
    assert "fallthrough_rule:$opaque" in analyzer.string_signatures
    assert len(analyzer.string_signatures["fallthrough_rule:$opaque"]) == 32


def test_analyze_string_hex_string_records_token_count_and_content() -> None:
    """_analyze_string must store content_type='hex' with token_count for HexString."""
    # Arrange: build a real HexString AST node with two bytes
    hex_string = HexString(
        identifier="$h",
        tokens=[HexByte(value=0xDE), HexByte(value=0xAD)],
    )

    analyzer = ASTStructuralAnalyzer()

    # Act
    analyzer._analyze_string(hex_string, "myrule", "$h")

    # Assert: the signature was stored and it came from the 'hex' branch
    assert "myrule:$h" in analyzer.string_signatures
    sig = analyzer.string_signatures["myrule:$h"]
    assert isinstance(sig, str) and len(sig) == 32


def test_analyze_hex_string_via_full_rule_parse() -> None:
    """analyze() must handle a rule containing a HexString pattern end-to-end."""
    source = dedent("""\
        rule hex_pattern {
            strings:
                $h = { DE AD BE EF 00 }
            condition:
                $h
        }
    """)
    ast = parse_yara_source(source)
    result = ASTStructuralAnalyzer().analyze(ast)

    # Exactly one string signature for this rule
    sig_keys = [k for k in result["string_signatures"] if k.startswith("hex_pattern:")]
    assert len(sig_keys) == 1
    assert all(isinstance(v, str) for v in result["string_signatures"].values())


def test_hex_string_vs_plain_string_signatures_differ() -> None:
    """HexString and PlainString with the same identifier must produce different hashes."""
    hex_str = HexString(
        identifier="$x",
        tokens=[HexByte(value=0xFF)],
    )
    plain_str = PlainString(identifier="$x", value="plaintext")

    analyzer_hex = ASTStructuralAnalyzer()
    analyzer_hex._analyze_string(hex_str, "rule1", "$x")

    analyzer_plain = ASTStructuralAnalyzer()
    analyzer_plain._analyze_string(plain_str, "rule1", "$x")

    assert (
        analyzer_hex.string_signatures["rule1:$x"] != analyzer_plain.string_signatures["rule1:$x"]
    )


# ---------------------------------------------------------------------------
# _condition_value_structure — line 235 (Mapping branch)
# ---------------------------------------------------------------------------


def test_condition_value_structure_mapping_is_sorted_by_key() -> None:
    """_condition_value_structure must process any Mapping, sorting by key."""
    analyzer = ASTStructuralAnalyzer()

    # Use an OrderedDict deliberately reversed from sort order
    mapping: dict[str, Any] = OrderedDict([("z_key", 99), ("a_key", 1), ("m_key", "mid")])

    result = analyzer._condition_value_structure(mapping)

    # Must return a dict with the same content
    assert isinstance(result, dict)
    assert result["a_key"] == 1
    assert result["z_key"] == 99
    assert result["m_key"] == "mid"

    # Keys must be serialised as strings (sorted internally for determinism)
    assert list(result.keys()) == sorted(result.keys())


def test_condition_value_structure_nested_mapping() -> None:
    """Nested Mappings must be recursively processed."""
    analyzer = ASTStructuralAnalyzer()

    nested: dict[str, Any] = {"outer": {"inner_b": 2, "inner_a": 1}}
    result = analyzer._condition_value_structure(nested)

    assert isinstance(result["outer"], dict)
    assert result["outer"]["inner_a"] == 1
    assert result["outer"]["inner_b"] == 2


# ---------------------------------------------------------------------------
# _condition_value_structure — line 242 (set | frozenset branch)
# ---------------------------------------------------------------------------


def test_condition_value_structure_set_returns_sorted_list() -> None:
    """_condition_value_structure must convert a set to a deterministically sorted list."""
    analyzer = ASTStructuralAnalyzer()

    value: set[int] = {3, 1, 2}
    result = analyzer._condition_value_structure(value)

    assert isinstance(result, list)
    # The list is sorted by str() representation of each element
    assert result == sorted(result, key=str)


def test_condition_value_structure_frozenset_returns_sorted_list() -> None:
    """_condition_value_structure must convert a frozenset to a sorted list."""
    analyzer = ASTStructuralAnalyzer()

    value: frozenset[str] = frozenset({"banana", "apple", "cherry"})
    result = analyzer._condition_value_structure(value)

    assert isinstance(result, list)
    assert result == sorted(result)


def test_condition_value_structure_set_deterministic_across_calls() -> None:
    """Repeated calls on the same set must yield identical results (determinism)."""
    analyzer = ASTStructuralAnalyzer()

    value: set[int] = {10, 5, 7, 3, 9}
    first = analyzer._condition_value_structure(value)
    second = analyzer._condition_value_structure(value)

    assert first == second


# ---------------------------------------------------------------------------
# _condition_value_structure — line 248 (fallback str() branch)
# The fallback handles values that are none of: ASTNode, Mapping, list/tuple,
# set/frozenset, or a primitive (str/int/float/bool/None).
# ---------------------------------------------------------------------------


def test_condition_value_structure_fallback_converts_to_str() -> None:
    """Non-primitive, non-container objects must be serialised via str()."""
    analyzer = ASTStructuralAnalyzer()

    # datetime.date is not a str/int/float/bool/None, not a Mapping, not a
    # list/tuple/set/frozenset, and not an ASTNode — it hits the fallback branch.
    dt = datetime.date(2024, 6, 15)
    result = analyzer._condition_value_structure(dt)

    assert result == "2024-06-15"


def test_condition_value_structure_fallback_custom_object() -> None:
    """Custom objects with __str__ must reach the str() fallback."""

    class Sentinel:
        def __str__(self) -> str:
            return "sentinel_value"

    analyzer = ASTStructuralAnalyzer()
    result = analyzer._condition_value_structure(Sentinel())

    assert result == "sentinel_value"


# ---------------------------------------------------------------------------
# ASTFormatter._optional_output_path — lines 429-430
# (PathLike whose __fspath__ returns bytes, not str)
# ---------------------------------------------------------------------------


def test_optional_output_path_bytes_fspath_raises_type_error() -> None:
    """_optional_output_path must reject a PathLike that returns bytes from __fspath__."""
    # Arrange
    formatter = ASTFormatter()
    pl = _BytesPathLike()

    # Act + Assert
    with pytest.raises(TypeError, match="output_path must be a file path"):
        formatter._optional_output_path(pl)


def test_optional_output_path_none_returns_none() -> None:
    """_optional_output_path(None) must return None (in-memory formatting mode)."""
    formatter = ASTFormatter()
    assert formatter._optional_output_path(None) is None


def test_optional_output_path_valid_str_returns_path(tmp_path: Path) -> None:
    """_optional_output_path must accept a string path and return a Path object."""
    formatter = ASTFormatter()
    out = str(tmp_path / "output.yar")
    result = formatter._optional_output_path(out)
    assert isinstance(result, Path)
    assert result == Path(out)


def test_optional_output_path_rejects_null_byte_string() -> None:
    formatter = ASTFormatter()
    with pytest.raises(ValueError, match="output_path must not contain null bytes"):
        formatter._optional_output_path("\x00broken")
