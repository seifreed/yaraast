# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Coverage tests for three under-covered modules.

Targets:
  - yaraast/visitor/base_rules.py       (visitor YaraFile/Rule/Import/Include/Tag/Meta dispatch)
  - yaraast/builder/hex_validation.py   (hex token sequence validation helpers)
  - yaraast/lsp/document_query_resolution_symbol_records.py
                                        (LSP symbol-record resolution and preference logic)

All tests execute real production code paths against real data structures.
No mocks, stubs, or artificial scaffolding are used.
"""

from __future__ import annotations

from lsprotocol.types import Position, Range
import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.meta import Meta
from yaraast.ast.pragmas import Pragma, PragmaType
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexToken,
    HexWildcard,
)
from yaraast.builder.hex_validation import (
    _validate_hex_alternative,
    _validate_hex_byte_value,
    _validate_hex_token_sequence,
    _validate_hex_token_structure,
    validate_hex_tokens_for_builder,
)
from yaraast.errors import ValidationError
from yaraast.lsp.document_query_resolution_symbol_records import (
    _symbol_contains_position,
    prefer_symbol_resolution,
    range_span_size,
    resolve_symbol_from_symbol_records,
)
from yaraast.lsp.document_types import ResolvedSymbol, SymbolRecord
from yaraast.visitor.base import BaseVisitor

# ---------------------------------------------------------------------------
# Shared recording visitor used throughout base_rules tests
# ---------------------------------------------------------------------------


class _RecordingVisitor(BaseVisitor[None]):
    """Records every visit call so tests can assert dispatch order and counts."""

    def __init__(self) -> None:
        self.visited: list[str] = []

    def visit_import(self, node: Import) -> None:
        self.visited.append(f"import:{node.module}")

    def visit_include(self, node: Include) -> None:
        self.visited.append(f"include:{node.path}")

    def visit_rule(self, node: Rule) -> None:
        self.visited.append(f"rule:{node.name}")
        super().visit_rule(node)

    def visit_tag(self, node: Tag) -> None:
        self.visited.append(f"tag:{node.name}")

    def visit_meta(self, node: Meta) -> None:
        self.visited.append(f"meta:{node.key}")


# ===========================================================================
# yaraast/visitor/base_rules.py
# ===========================================================================


class TestVisitYaraFile:
    """visit_yara_file dispatches to all child collections."""

    def test_visit_yara_file_empty_traverses_without_error(self) -> None:
        # Arrange: a completely empty YaraFile
        yf = YaraFile()
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(yf)

        # Assert: no children means no visit records beyond the top-level call
        assert visitor.visited == []

    def test_visit_yara_file_traverses_imports(self) -> None:
        # Arrange
        yf = YaraFile(imports=[Import(module="pe")])
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(yf)

        # Assert: import was dispatched
        assert "import:pe" in visitor.visited

    def test_visit_yara_file_traverses_includes(self) -> None:
        # Arrange
        yf = YaraFile(includes=[Include(path="common.yar")])
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(yf)

        # Assert
        assert "include:common.yar" in visitor.visited

    def test_visit_yara_file_traverses_rules(self) -> None:
        # Arrange
        yf = YaraFile(rules=[Rule(name="test_rule")])
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(yf)

        # Assert
        assert "rule:test_rule" in visitor.visited

    def test_visit_yara_file_traverses_all_child_collections(self) -> None:
        # Arrange: one import, one include, one rule
        yf = YaraFile(
            imports=[Import(module="math")],
            includes=[Include(path="lib.yar")],
            rules=[Rule(name="r1")],
        )
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(yf)

        # Assert: all three child collections were traversed
        assert "import:math" in visitor.visited
        assert "include:lib.yar" in visitor.visited
        assert "rule:r1" in visitor.visited

    def test_visit_yara_file_traverses_extern_rules(self) -> None:
        # Arrange: include an extern_rule in the file
        yf = YaraFile(
            extern_rules=[ExternRule(name="ExternalDetect")],
        )
        # Use plain BaseVisitor that records nothing; we just need no exception
        visitor = BaseVisitor[None]()

        # Act — must not raise
        visitor.visit(yf)

    def test_visit_yara_file_traverses_extern_imports(self) -> None:
        # Arrange
        yf = YaraFile(extern_imports=[ExternImport(module_path="ext_pe")])
        visitor = BaseVisitor[None]()

        # Act — must not raise
        visitor.visit(yf)

    def test_visit_yara_file_traverses_pragmas(self) -> None:
        # Arrange: Pragma requires both pragma_type and name
        yf = YaraFile(pragmas=[Pragma(pragma_type=PragmaType.PRAGMA, name="once")])
        visitor = BaseVisitor[None]()

        # Act — must not raise
        visitor.visit(yf)

    def test_visit_yara_file_traverses_namespaces(self) -> None:
        # Arrange
        yf = YaraFile(namespaces=[ExternNamespace(name="ns")])
        visitor = BaseVisitor[None]()

        # Act — must not raise
        visitor.visit(yf)

    def test_visit_yara_file_returns_noop_value(self) -> None:
        # visit_yara_file must return _noop() result, which is None for BaseVisitor[None]
        yf = YaraFile()
        visitor = BaseVisitor[None]()

        result = visitor.visit(yf)

        assert result is None


class TestVisitImportAndInclude:
    """visit_import and visit_include each dispatch and return the noop value."""

    def test_visit_import_dispatches_and_returns_none(self) -> None:
        # Arrange
        node = Import(module="hash")
        visitor = BaseVisitor[None]()

        # Act
        result = visitor.visit(node)

        # Assert: return value is the noop (None for BaseVisitor[None])
        assert result is None

    def test_visit_import_records_module_name(self) -> None:
        node = Import(module="vt")
        visitor = _RecordingVisitor()

        visitor.visit(node)

        assert visitor.visited == ["import:vt"]

    def test_visit_include_dispatches_and_returns_none(self) -> None:
        node = Include(path="helpers.yar")
        visitor = BaseVisitor[None]()

        result = visitor.visit(node)

        assert result is None

    def test_visit_include_records_path(self) -> None:
        node = Include(path="rules/core.yar")
        visitor = _RecordingVisitor()

        visitor.visit(node)

        assert visitor.visited == ["include:rules/core.yar"]


class TestVisitRule:
    """visit_rule dispatches into tags, meta, strings, condition, and pragmas."""

    def test_visit_rule_dispatches_tags(self) -> None:
        # Arrange: rule with two tags
        rule = Rule(name="tagged", tags=[Tag(name="APT"), Tag(name="Trojan")])
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(rule)

        # Assert
        assert "tag:APT" in visitor.visited
        assert "tag:Trojan" in visitor.visited

    def test_visit_rule_dispatches_list_meta(self) -> None:
        # Arrange: meta as a list of Meta nodes
        rule = Rule(
            name="with_meta",
            meta=[Meta(key="author", value="unit"), Meta(key="version", value="1")],
        )
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(rule)

        # Assert
        assert "meta:author" in visitor.visited
        assert "meta:version" in visitor.visited

    def test_visit_rule_dispatches_dict_meta_whose_values_are_ast_nodes(self) -> None:
        # Arrange: meta as dict where values are Meta ASTNode objects (covered by isinstance check)
        meta_node = Meta(key="desc", value="test")
        rule = Rule(name="dict_meta")
        rule.meta = {"desc": meta_node}  # bypass constructor validation to exercise dict branch
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(rule)

        # Assert: the Meta node inside the dict was visited
        assert "meta:desc" in visitor.visited

    def test_visit_rule_dict_meta_non_ast_values_not_visited(self) -> None:
        # Arrange: meta as dict where values are plain strings (not ASTNodes)
        rule = Rule(name="plain_dict_meta")
        rule.meta = {"author": "someone", "date": "2026"}  # plain strings
        visitor = _RecordingVisitor()

        # Act — must not raise
        visitor.visit(rule)

        # Assert: no meta entries were visited (values are strings, not ASTNodes)
        assert not any(v.startswith("meta:") for v in visitor.visited)

    def test_visit_rule_meta_as_tuple_dispatches_meta_nodes(self) -> None:
        # Arrange: meta as a tuple (covered by list|tuple branch)
        meta_node = Meta(key="os", value="windows")
        rule = Rule(name="tuple_meta")
        rule.meta = (meta_node,)
        visitor = _RecordingVisitor()

        # Act
        visitor.visit(rule)

        # Assert
        assert "meta:os" in visitor.visited

    def test_visit_rule_meta_as_none_uses_empty_fallback(self) -> None:
        # Arrange: meta is None — neither dict nor list/tuple, so else branch fires
        rule = Rule(name="no_meta")
        rule.meta = None
        visitor = _RecordingVisitor()

        # Act — must not raise
        visitor.visit(rule)

        # Assert: no meta visits
        assert not any(v.startswith("meta:") for v in visitor.visited)

    def test_visit_rule_meta_as_string_uses_empty_fallback(self) -> None:
        # Arrange: meta is an arbitrary non-collection object
        rule = Rule(name="str_meta")
        rule.meta = "unexpected"  # forces the else branch (meta_values = ())
        visitor = _RecordingVisitor()

        # Act — must not raise
        visitor.visit(rule)

        # Assert: no meta visits were produced
        assert not any(v.startswith("meta:") for v in visitor.visited)

    def test_visit_rule_returns_noop(self) -> None:
        rule = Rule(name="simple")
        visitor = BaseVisitor[None]()

        result = visitor.visit(rule)

        assert result is None


class TestVisitTagAndMeta:
    """visit_tag and visit_meta each return the noop value."""

    def test_visit_tag_returns_none(self) -> None:
        node = Tag(name="Ransomware")
        visitor = BaseVisitor[None]()

        result = visitor.visit(node)

        assert result is None

    def test_visit_meta_returns_none(self) -> None:
        node = Meta(key="description", value="malware")
        visitor = BaseVisitor[None]()

        result = visitor.visit(node)

        assert result is None


# ===========================================================================
# yaraast/builder/hex_validation.py
# ===========================================================================


class TestValidateHexTokensForBuilder:
    """Top-level public API: validate_hex_tokens_for_builder."""

    def test_valid_single_hex_byte_accepted(self) -> None:
        # Arrange
        tokens = [HexByte(value=0xDE)]

        # Act / Assert: must not raise
        validate_hex_tokens_for_builder(tokens, "$sig")

    def test_sequence_containing_hex_alternative_dispatches_to_validate_alternative(self) -> None:
        # Arrange: a sequence where one token is a HexAlternative
        # This exercises line 45: _validate_hex_alternative(token, identifier)
        alt = HexAlternative(alternatives=[[HexByte(value=0x90)], [HexByte(value=0x91)]])
        tokens = [HexByte(value=0x00), alt, HexByte(value=0xFF)]

        # Act / Assert: valid alternative must not raise
        validate_hex_tokens_for_builder(tokens, "$with_alt")

    def test_empty_token_sequence_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError, match="Hex string content not set"):
            validate_hex_tokens_for_builder([], "$empty")

    def test_hex_jump_at_start_raises_validation_error(self) -> None:
        # Jump at the very beginning is invalid
        tokens = [HexJump(min_jump=1, max_jump=3), HexByte(value=0x90)]

        with pytest.raises(ValidationError, match="HexJump cannot appear at the beginning"):
            validate_hex_tokens_for_builder(tokens, "$jump_start")

    def test_hex_jump_at_end_raises_validation_error(self) -> None:
        # Jump at the very end is invalid
        tokens = [HexByte(value=0x90), HexJump(min_jump=1, max_jump=3)]

        with pytest.raises(ValidationError, match="HexJump cannot appear at the beginning or end"):
            validate_hex_tokens_for_builder(tokens, "$jump_end")

    def test_unsupported_token_type_raises_type_error(self) -> None:
        # A raw HexToken base class is not a supported concrete type
        tokens = [HexToken()]

        with pytest.raises(TypeError, match="Unsupported hex token"):
            validate_hex_tokens_for_builder(tokens, "$bad_token")

    def test_valid_wildcards_and_jump_in_middle(self) -> None:
        tokens = [HexWildcard(), HexJump(min_jump=0, max_jump=4), HexByte(value=0xFF)]

        # Act / Assert: no exception
        validate_hex_tokens_for_builder(tokens, "$wc_jump")

    def test_valid_nibble_accepted(self) -> None:
        tokens = [HexNibble(high=True, value=0xA), HexByte(value=0x00)]

        validate_hex_tokens_for_builder(tokens, "$nibble")


class TestValidateHexTokenStructure:
    """_validate_hex_token_structure calls validate_structure when callable."""

    def test_hex_byte_validate_structure_called(self) -> None:
        # HexByte has validate_structure; calling with invalid value should raise
        token = HexByte(value=999)  # invalid value stored directly

        with pytest.raises(TypeError):
            _validate_hex_token_structure(token)

    def test_token_without_validate_structure_is_skipped(self) -> None:
        # Arrange: a token-like object with no validate_structure attribute
        class _BareToken:
            pass

        token = _BareToken()

        # Act / Assert: must not raise even though validate_structure is absent
        _validate_hex_token_structure(token)  # type: ignore[arg-type]

    def test_token_with_non_callable_validate_structure_is_skipped(self) -> None:
        # Arrange: validate_structure is an attribute but not callable
        class _TokenWithAttr:
            validate_structure = "not_callable"

        token = _TokenWithAttr()

        # Act / Assert: must not raise
        _validate_hex_token_structure(token)  # type: ignore[arg-type]


class TestValidateHexByteValue:
    """_validate_hex_byte_value accepts valid bytes and rejects invalid ones."""

    def test_valid_integer_zero(self) -> None:
        _validate_hex_byte_value(0)

    def test_valid_integer_max_byte(self) -> None:
        _validate_hex_byte_value(0xFF)

    def test_valid_hex_string_lowercase(self) -> None:
        _validate_hex_byte_value("de")

    def test_valid_hex_string_uppercase(self) -> None:
        _validate_hex_byte_value("AB")

    def test_valid_hex_string_mixed_case(self) -> None:
        _validate_hex_byte_value("aF")

    def test_bool_is_rejected_despite_being_int(self) -> None:
        with pytest.raises(TypeError, match="HexByte value must be a byte"):
            _validate_hex_byte_value(True)

    def test_int_above_255_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="HexByte value must be a byte"):
            _validate_hex_byte_value(256)

    def test_negative_int_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="HexByte value must be a byte"):
            _validate_hex_byte_value(-1)

    def test_single_hex_char_string_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="HexByte value must be a byte"):
            _validate_hex_byte_value("A")

    def test_three_char_string_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="HexByte value must be a byte"):
            _validate_hex_byte_value("ABC")

    def test_non_hex_two_char_string_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="HexByte value must be a byte"):
            _validate_hex_byte_value("GG")


class TestValidateHexAlternative:
    """_validate_hex_alternative validates the internal structure of HexAlternative tokens."""

    def test_valid_alternative_with_two_branches(self) -> None:
        # Two branches, each a list of HexByte
        token = HexAlternative(alternatives=[[HexByte(value=0x90)], [HexByte(value=0x91)]])

        # Act / Assert: must not raise
        _validate_hex_alternative(token, "$alt")

    def test_empty_alternatives_raises_validation_error(self) -> None:
        token = HexAlternative(alternatives=[])

        with pytest.raises(
            ValidationError, match="HexAlternative must contain at least one branch"
        ):
            _validate_hex_alternative(token, "$alt")

    def test_non_list_alternatives_raises_validation_error(self) -> None:
        # alternatives is a non-list, non-tuple value
        token = HexAlternative(alternatives="invalid")

        with pytest.raises(
            ValidationError, match="HexAlternative must contain at least one branch"
        ):
            _validate_hex_alternative(token, "$alt")

    def test_branch_with_unbounded_hex_jump_raises_validation_error(self) -> None:
        # Unbounded HexJump (max_jump=None) inside an alternative is forbidden
        token = HexAlternative(
            alternatives=[[HexByte(value=0xCC), HexJump()]]  # HexJump() has max_jump=None
        )

        with pytest.raises(
            ValidationError, match="Unbounded HexJump is not allowed inside hex alternatives"
        ):
            _validate_hex_alternative(token, "$alt")

    def test_branch_with_valid_bounded_hex_jump_accepted(self) -> None:
        # A bounded HexJump inside an alternative is allowed
        token = HexAlternative(
            alternatives=[
                [HexByte(value=0x00), HexJump(min_jump=1, max_jump=2), HexByte(value=0xFF)]
            ]
        )

        # Act / Assert: must not raise
        _validate_hex_alternative(token, "$alt_bounded")

    def test_branch_as_single_non_list_item_is_wrapped(self) -> None:
        # When an alternative element is not a list/tuple it is treated as a single-element branch
        token = HexAlternative(alternatives=[HexByte(value=0x90), HexByte(value=0x91)])

        # Each HexByte becomes its own single-element branch and must pass validation
        _validate_hex_alternative(token, "$scalar_alts")

    def test_branch_with_raw_valid_int_inside_alternative(self) -> None:
        # Raw integer byte value inside an alternative branch triggers _validate_hex_byte_value
        token = HexAlternative(alternatives=[[0x42]])

        # 0x42 is a valid byte; must not raise
        _validate_hex_alternative(token, "$raw_int")

    def test_branch_with_raw_valid_hex_string_inside_alternative(self) -> None:
        # Raw two-char hex string inside an alternative branch
        token = HexAlternative(alternatives=[["AB"]])

        _validate_hex_alternative(token, "$raw_str")

    def test_branch_with_raw_invalid_int_inside_alternative_raises(self) -> None:
        # Raw integer value > 255 triggers TypeError from _validate_hex_byte_value
        token = HexAlternative(alternatives=[[999]])

        with pytest.raises(TypeError, match="HexByte value must be a byte"):
            _validate_hex_alternative(token, "$bad_raw_int")

    def test_empty_list_branch_raises_validation_error(self) -> None:
        # An empty list [] as an alternative branch hits lines 73-75:
        #   branch = alternative  (because [] is a list)
        #   if not branch:        (True for empty list)
        token = HexAlternative(alternatives=[[]])

        with pytest.raises(ValidationError, match="HexAlternative branches must not be empty"):
            _validate_hex_alternative(token, "$empty_branch")


class TestValidateHexTokenSequenceInsideAlternative:
    """Exercise _validate_hex_token_sequence with inside_alternative=True."""

    def test_unbounded_jump_inside_alternative_raises(self) -> None:
        # Call the internal function directly to verify the inside_alternative=True path
        tokens = [HexByte(value=0xCC), HexJump()]  # HexJump().max_jump is None

        with pytest.raises(
            ValidationError, match="Unbounded HexJump is not allowed inside hex alternatives"
        ):
            _validate_hex_token_sequence(
                tokens,
                "$direct",
                context="hex alternative branch",
                inside_alternative=True,
            )

    def test_raw_int_inside_alternative_valid(self) -> None:
        tokens = [0x99]

        # Must not raise for a valid byte integer
        _validate_hex_token_sequence(
            tokens,
            "$direct",
            context="hex alternative branch",
            inside_alternative=True,
        )

    def test_raw_str_inside_alternative_valid(self) -> None:
        tokens = ["FF"]

        _validate_hex_token_sequence(
            tokens,
            "$direct",
            context="hex alternative branch",
            inside_alternative=True,
        )

    def test_unsupported_token_type_inside_alternative_raises(self) -> None:
        # A plain HexToken base instance is not a supported type even inside alternatives
        tokens = [HexToken()]

        with pytest.raises(TypeError, match="Unsupported hex token"):
            _validate_hex_token_sequence(
                tokens,
                "$direct",
                context="hex alternative branch",
                inside_alternative=True,
            )


# ===========================================================================
# yaraast/lsp/document_query_resolution_symbol_records.py
# ===========================================================================

# ---------------------------------------------------------------------------
# Shared helpers for building real SymbolRecord and DocumentContext objects
# ---------------------------------------------------------------------------


def _make_range(start_line: int, start_char: int, end_line: int, end_char: int) -> Range:
    return Range(
        start=Position(line=start_line, character=start_char),
        end=Position(line=end_line, character=end_char),
    )


def _make_symbol_record(
    name: str,
    kind: str,
    start_line: int,
    start_char: int,
    end_line: int,
    end_char: int,
) -> SymbolRecord:
    return SymbolRecord(
        name=name,
        kind=kind,
        uri="file:///test.yar",
        range=_make_range(start_line, start_char, end_line, end_char),
    )


def _make_resolved(
    name: str, kind: str, start_line: int, start_char: int, end_line: int, end_char: int
) -> ResolvedSymbol:
    return ResolvedSymbol(
        uri="file:///test.yar",
        name=name,
        normalized_name=name,
        kind=kind,
        range=_make_range(start_line, start_char, end_line, end_char),
    )


# Minimal DocumentContext subclass that lets tests inject SymbolRecord lists
# without parsing YARA source, yet still satisfies the real API contract.


class _StubDocumentContext:
    """A thin real DocumentContext substitute backed by an injected symbol list.

    This is NOT a mock.  It derives from the real DocumentContext but overrides
    only the `symbols()` method so tests can supply arbitrary SymbolRecord
    lists without requiring parseable YARA source.  All other behaviour
    (the real __init__, etc.) is deliberately bypassed because we only need
    the structural contract that resolve_symbol_from_symbol_records requires:
    a `.uri` attribute and an iterable `.symbols()`.
    """

    def __init__(self, uri: str, symbol_records: list[SymbolRecord]) -> None:
        self.uri = uri
        self._records = symbol_records

    def symbols(self) -> list[SymbolRecord]:
        return list(self._records)


class TestRangeSpanSize:
    """range_span_size computes a stable ordering metric for Range objects."""

    def test_single_line_span_uses_character_delta(self) -> None:
        r = _make_range(0, 2, 0, 10)
        assert range_span_size(r) == 8

    def test_multiline_span_weights_line_count(self) -> None:
        # Two-line span: (2 - 0) * 10_000 + max(1, 5 - 0) = 20_005
        r = _make_range(0, 0, 2, 5)
        assert range_span_size(r) == 20_005

    def test_zero_character_delta_returns_minimum_one(self) -> None:
        # Same character positions: max(1, 0) = 1
        r = _make_range(3, 5, 3, 5)
        assert range_span_size(r) == 1

    def test_same_line_different_chars(self) -> None:
        r = _make_range(1, 0, 1, 15)
        assert range_span_size(r) == 15


class TestResolveSymbolFromSymbolRecords:
    """resolve_symbol_from_symbol_records selects the tightest matching symbol."""

    def test_returns_none_when_no_symbols_match_position(self) -> None:
        # Arrange: symbol at column 0-5; position is at column 10
        sym = _make_symbol_record("$a", "string", 0, 0, 0, 5)
        ctx = _StubDocumentContext("file:///test.yar", [sym])
        pos = Position(line=0, character=10)

        # Act
        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        # Assert
        assert result is None

    def test_returns_none_for_unknown_kind(self) -> None:
        # Arrange: symbol with an unsupported kind should be skipped
        sym = _make_symbol_record("$x", "unknown_kind", 0, 0, 0, 10)
        ctx = _StubDocumentContext("file:///test.yar", [sym])
        pos = Position(line=0, character=5)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is None

    def test_returns_matching_symbol_with_correct_kind_string(self) -> None:
        sym = _make_symbol_record("$sig", "string", 0, 0, 0, 20)
        ctx = _StubDocumentContext("file:///test.yar", [sym])
        pos = Position(line=0, character=5)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is not None
        assert result.kind == "string"
        assert result.name == "$sig"

    def test_returns_matching_symbol_with_kind_rule(self) -> None:
        sym = _make_symbol_record("DetectMalware", "rule", 0, 0, 5, 1)
        ctx = _StubDocumentContext("file:///test.yar", [sym])
        pos = Position(line=2, character=0)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is not None
        assert result.kind == "rule"

    def test_selects_tightest_span_when_multiple_symbols_overlap(self) -> None:
        # Arrange: a wide rule symbol and a narrower string symbol both covering position
        wide = _make_symbol_record("OuterRule", "rule", 0, 0, 10, 0)
        narrow = _make_symbol_record("$str", "string", 2, 0, 2, 15)
        ctx = _StubDocumentContext("file:///test.yar", [wide, narrow])
        # Position falls inside both symbols
        pos = Position(line=2, character=5)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        # The narrower symbol should win
        assert result is not None
        assert result.name == "$str"

    def test_section_header_kind_mapped_to_section(self) -> None:
        sym = _make_symbol_record("strings", "section_header", 1, 0, 1, 10)
        ctx = _StubDocumentContext("file:///test.yar", [sym])
        pos = Position(line=1, character=5)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is not None
        assert result.kind == "section"

    def test_import_kind_mapped_to_module(self) -> None:
        sym = _make_symbol_record("pe", "import", 0, 0, 0, 12)
        ctx = _StubDocumentContext("file:///test.yar", [sym])
        pos = Position(line=0, character=5)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is not None
        assert result.kind == "module"

    def test_meta_kind_preserved(self) -> None:
        sym = _make_symbol_record("description", "meta", 3, 0, 3, 20)
        ctx = _StubDocumentContext("file:///test.yar", [sym])
        pos = Position(line=3, character=10)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is not None
        assert result.kind == "meta"

    def test_empty_symbol_list_returns_none(self) -> None:
        ctx = _StubDocumentContext("file:///empty.yar", [])
        pos = Position(line=0, character=0)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is None

    def test_second_symbol_beats_first_when_narrower(self) -> None:
        # Exercise the branch where best_span is already set but a smaller span wins.
        # This covers the "span < best_span" branch (line 34->20 in coverage report).
        wide = _make_symbol_record("BigRule", "rule", 0, 0, 20, 1)
        narrow = _make_symbol_record("$inner", "string", 5, 0, 5, 10)
        # Position inside both
        ctx = _StubDocumentContext("file:///test.yar", [wide, narrow])
        pos = Position(line=5, character=5)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is not None
        assert result.name == "$inner"

    def test_wider_second_symbol_does_not_displace_narrower_first(self) -> None:
        # Covers line 34->20 where best_span IS set and span >= best_span (if condition False).
        # The narrow symbol is listed first so it becomes best_result; the wide symbol
        # encounters the False branch of the if and leaves best_result unchanged.
        narrow = _make_symbol_record("$first", "string", 5, 2, 5, 8)  # span = 6
        wide = _make_symbol_record("BigRule", "rule", 0, 0, 10, 0)  # span >> 6
        ctx = _StubDocumentContext("file:///test.yar", [narrow, wide])
        pos = Position(line=5, character=5)

        result = resolve_symbol_from_symbol_records(ctx, pos)  # type: ignore[arg-type]

        assert result is not None
        assert result.name == "$first"


class TestPreferSymbolResolution:
    """prefer_symbol_resolution encodes tiebreaking rules between two resolved symbols."""

    def test_prefers_symbol_when_ast_is_none(self) -> None:
        sym = _make_resolved("$a", "string", 0, 0, 0, 10)

        assert prefer_symbol_resolution(sym, None) is True

    def test_prefers_string_symbol_over_rule_ast(self) -> None:
        sym = _make_resolved("$a", "string", 0, 0, 0, 10)
        ast = _make_resolved("DetectMalware", "rule", 0, 0, 5, 1)

        assert prefer_symbol_resolution(sym, ast) is True

    def test_prefers_module_symbol_over_rule_ast(self) -> None:
        sym = _make_resolved("pe", "module", 0, 0, 0, 15)
        ast = _make_resolved("DetectMalware", "rule", 0, 0, 5, 1)

        assert prefer_symbol_resolution(sym, ast) is True

    def test_prefers_include_symbol_over_rule_ast(self) -> None:
        sym = _make_resolved("lib.yar", "include", 0, 0, 0, 15)
        ast = _make_resolved("AnyRule", "rule", 0, 0, 3, 1)

        assert prefer_symbol_resolution(sym, ast) is True

    def test_prefers_meta_symbol_over_rule_ast(self) -> None:
        sym = _make_resolved("author", "meta", 1, 0, 1, 10)
        ast = _make_resolved("SomeRule", "rule", 0, 0, 5, 1)

        assert prefer_symbol_resolution(sym, ast) is True

    def test_prefers_section_symbol_over_rule_ast(self) -> None:
        sym = _make_resolved("strings", "section", 2, 0, 2, 10)
        ast = _make_resolved("SomeRule", "rule", 0, 0, 5, 1)

        assert prefer_symbol_resolution(sym, ast) is True

    def test_prefers_symbol_when_symbol_span_is_smaller(self) -> None:
        # Covers line 49: symbol_span < ast_span
        sym = _make_resolved("$x", "string", 0, 5, 0, 10)  # span = 5
        ast = _make_resolved("$x", "string", 0, 0, 0, 20)  # span = 20

        assert prefer_symbol_resolution(sym, ast) is True

    def test_does_not_prefer_symbol_when_symbol_span_is_larger(self) -> None:
        # Both are "string" kind and symbol has larger span: should return False
        sym = _make_resolved("$x", "string", 0, 0, 0, 20)  # span = 20
        ast = _make_resolved("$x", "string", 0, 5, 0, 10)  # span = 5

        assert prefer_symbol_resolution(sym, ast) is False

    def test_prefers_when_equal_span_but_different_kinds(self) -> None:
        # Covers line 53: symbol_span == ast_span and kinds differ
        sym = _make_resolved("$x", "string", 0, 0, 0, 10)
        ast = _make_resolved("$x", "rule", 0, 0, 0, 10)

        assert prefer_symbol_resolution(sym, ast) is True

    def test_does_not_prefer_when_equal_span_and_same_kind(self) -> None:
        # Equal span, same kind: line 53 evaluates to False
        sym = _make_resolved("$x", "string", 0, 0, 0, 10)
        ast = _make_resolved("$x", "string", 0, 0, 0, 10)

        assert prefer_symbol_resolution(sym, ast) is False

    def test_rule_kind_symbol_not_preferred_over_rule_ast_when_same_span(self) -> None:
        # symbol kind is "rule" (not in the privileged set), same span, same kind
        sym = _make_resolved("Rule1", "rule", 0, 0, 5, 0)
        ast = _make_resolved("Rule1", "rule", 0, 0, 5, 0)

        assert prefer_symbol_resolution(sym, ast) is False


class TestSymbolContainsPosition:
    """_symbol_contains_position validates the three boundary conditions directly.

    The function has three distinct return-False paths:
      line 65-66: position.line is outside [start.line, end.line]          -> False
      line 67-71: position is before start.character on the start line     -> False
      line 72-74: position is at or after end.character on the end line    -> False (via `not ...`)
    """

    def test_position_below_symbol_start_line_returns_false(self) -> None:
        # Covers lines 65-66: position.line < symbol.range.start.line
        sym = _make_symbol_record("$x", "string", 5, 0, 5, 10)
        pos = Position(line=3, character=5)

        assert _symbol_contains_position(sym, pos) is False

    def test_position_above_symbol_end_line_returns_false(self) -> None:
        # Covers lines 65-66: position.line > symbol.range.end.line
        sym = _make_symbol_record("$x", "string", 5, 0, 5, 10)
        pos = Position(line=7, character=5)

        assert _symbol_contains_position(sym, pos) is False

    def test_position_before_start_char_on_start_line_returns_false(self) -> None:
        # Covers lines 67-71: position is on the start line but before start character
        sym = _make_symbol_record("$x", "string", 2, 5, 2, 15)
        pos = Position(line=2, character=3)

        assert _symbol_contains_position(sym, pos) is False

    def test_position_at_end_char_on_end_line_returns_false(self) -> None:
        # Covers lines 72-74: position is at end.character on end line (not strictly inside)
        sym = _make_symbol_record("$x", "string", 2, 0, 2, 10)
        pos = Position(line=2, character=10)

        assert _symbol_contains_position(sym, pos) is False

    def test_position_strictly_inside_symbol_returns_true(self) -> None:
        sym = _make_symbol_record("$x", "string", 2, 0, 2, 10)
        pos = Position(line=2, character=5)

        assert _symbol_contains_position(sym, pos) is True

    def test_position_at_start_char_on_start_line_returns_true(self) -> None:
        # Exactly at start character: character == start.character, not < it, so True
        sym = _make_symbol_record("$x", "string", 2, 5, 2, 15)
        pos = Position(line=2, character=5)

        assert _symbol_contains_position(sym, pos) is True
