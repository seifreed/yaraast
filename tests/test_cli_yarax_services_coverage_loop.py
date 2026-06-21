"""
Regression tests covering the regex-fallback branches in yarax_services.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Context
-------
``detect_yarax_features`` and ``detect_playground_features`` each try to
extract YARA-X feature names by parsing the input with ``YaraXParser``.
When parsing succeeds the function returns early (lines 94-95 / 148-149).
When parsing fails ``_features_from_parsed_ast`` silently returns ``[]``
and the caller falls through to a set of regex searches against the
``_strip_string_literals`` view of the content.

The existing test suite exercises all regex branches *except* the
ones for dict expressions (line 113 / 160), slice expressions (line
115 / 162), and tuple indexing (line 117 / 164), because those tests
supply valid YARA-X rules whose features are detected via the parser
path — meaning the regex section is never reached.

Strategy
--------
Supply content that is **not** a valid YARA-X rule document so that
``YaraXParser.parse()`` raises ``YaraASTError`` and
``_features_from_parsed_ast`` returns ``[]``.  The content must also
match the three regex patterns so that the corresponding ``_add_feature``
calls are reached.

The snippets used here look like condition expressions in isolation
(no ``rule Foo { ... }`` wrapper), which is why the parser rejects
them while the patterns still fire.
"""

from __future__ import annotations

import pytest

from yaraast.cli.yarax_services import detect_playground_features, detect_yarax_features

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Each snippet below intentionally lacks the ``rule Name { ... }`` structure
# required by YaraXParser, so the parser raises YaraASTError and the regex
# fallback runs.  Each snippet also satisfies exactly one of the three
# previously-uncovered regex patterns.

_DICT_EXPR_SNIPPET = 'condition: {"key": true}'
_SLICE_EXPR_SNIPPET = "condition: $str[0:1]"
_TUPLE_IDX_SNIPPET = "condition: (1, 2)[0]"

# A snippet that triggers all three patterns at once (combined fallback path).
_COMBINED_FALLBACK_SNIPPET = 'condition: {"key": true} and $str[0:1] and (1, 2)[0]'


# ---------------------------------------------------------------------------
# detect_yarax_features — regex-fallback dict expressions (line 113)
# ---------------------------------------------------------------------------


def test_detect_yarax_features_dict_expressions_via_regex_fallback() -> None:
    """
    Line 113: ``_add_feature(features, "dict expressions")``

    Input fails YARA-X parsing, so the regex path executes.
    The snippet ``{"key": true}`` after a colon matches DICT_LITERAL_PATTERN.
    """
    # Arrange
    content = _DICT_EXPR_SNIPPET

    # Act
    features = detect_yarax_features(content)

    # Assert
    assert "dict expressions" in features
    # Confirm we are on the fallback path — only the matched feature appears,
    # not features that come from successful parser output.
    assert "with statements" not in features
    assert "array comprehensions" not in features


# ---------------------------------------------------------------------------
# detect_yarax_features — regex-fallback slice expressions (line 115)
# ---------------------------------------------------------------------------


def test_detect_yarax_features_slice_expressions_via_regex_fallback() -> None:
    """
    Line 115: ``_add_feature(features, "slice expressions")``

    Input fails YARA-X parsing.  The identifier followed by ``[n:m]``
    matches SLICE_PATTERN.
    """
    # Arrange
    content = _SLICE_EXPR_SNIPPET

    # Act
    features = detect_yarax_features(content)

    # Assert
    assert "slice expressions" in features
    assert "dict expressions" not in features
    assert "tuple indexing" not in features


# ---------------------------------------------------------------------------
# detect_yarax_features — regex-fallback tuple indexing (line 117)
# ---------------------------------------------------------------------------


def test_detect_yarax_features_tuple_indexing_via_regex_fallback() -> None:
    """
    Line 117: ``_add_feature(features, "tuple indexing")``

    Input fails YARA-X parsing.  The pattern ``(expr, expr)[`` matches
    TUPLE_INDEXING_PATTERN.
    """
    # Arrange
    content = _TUPLE_IDX_SNIPPET

    # Act
    features = detect_yarax_features(content)

    # Assert
    assert "tuple indexing" in features
    assert "dict expressions" not in features
    assert "slice expressions" not in features


# ---------------------------------------------------------------------------
# detect_yarax_features — combined fallback path covers all three at once
# ---------------------------------------------------------------------------


def test_detect_yarax_features_combined_fallback_covers_all_three_patterns() -> None:
    """
    Lines 113, 115, 117 all executed in one call.

    A single unparseable snippet containing dict, slice, and tuple-index
    expressions exercises the complete fallback regex sequence for these
    three features simultaneously.
    """
    # Arrange
    content = _COMBINED_FALLBACK_SNIPPET

    # Act
    features = detect_yarax_features(content)

    # Assert — all three previously-uncovered branches fire
    assert "dict expressions" in features
    assert "slice expressions" in features
    assert "tuple indexing" in features


# ---------------------------------------------------------------------------
# detect_playground_features — regex-fallback dict expressions (line 160)
# ---------------------------------------------------------------------------


def test_detect_playground_features_dict_expressions_via_regex_fallback() -> None:
    """
    Line 160: ``_add_feature(features, "dict expressions")``

    detect_playground_features has an independent copy of the fallback
    logic.  The same unparseable dict-expr snippet exercises line 160.
    """
    # Arrange
    content = _DICT_EXPR_SNIPPET

    # Act
    features = detect_playground_features(content)

    # Assert
    assert "dict expressions" in features
    assert "with statements" not in features
    assert "comprehensions" not in features


# ---------------------------------------------------------------------------
# detect_playground_features — regex-fallback slice expressions (line 162)
# ---------------------------------------------------------------------------


def test_detect_playground_features_slice_expressions_via_regex_fallback() -> None:
    """
    Line 162: ``_add_feature(features, "slice expressions")``

    Slice-expr snippet fails parsing; regex branch fires.
    """
    # Arrange
    content = _SLICE_EXPR_SNIPPET

    # Act
    features = detect_playground_features(content)

    # Assert
    assert "slice expressions" in features
    assert "dict expressions" not in features
    assert "tuple indexing" not in features


# ---------------------------------------------------------------------------
# detect_playground_features — regex-fallback tuple indexing (line 164)
# ---------------------------------------------------------------------------


def test_detect_playground_features_tuple_indexing_via_regex_fallback() -> None:
    """
    Line 164: ``_add_feature(features, "tuple indexing")``

    Tuple-indexing snippet fails parsing; regex branch fires.
    """
    # Arrange
    content = _TUPLE_IDX_SNIPPET

    # Act
    features = detect_playground_features(content)

    # Assert
    assert "tuple indexing" in features
    assert "dict expressions" not in features
    assert "slice expressions" not in features


# ---------------------------------------------------------------------------
# detect_playground_features — combined fallback (lines 160 + 162 + 164)
# ---------------------------------------------------------------------------


def test_detect_playground_features_combined_fallback_covers_all_three() -> None:
    """
    Lines 160, 162, 164 all executed in one call.

    Mirrors the detect_yarax_features combined test for the playground
    variant.
    """
    # Arrange
    content = _COMBINED_FALLBACK_SNIPPET

    # Act
    features = detect_playground_features(content)

    # Assert
    assert "dict expressions" in features
    assert "slice expressions" in features
    assert "tuple indexing" in features


# ---------------------------------------------------------------------------
# Regression: fallback path returns empty list for plain text with no patterns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "no patterns here at all",
        "just some words without any special syntax",
        "42 plus some arithmetic",
    ],
)
def test_detect_yarax_features_fallback_returns_empty_for_plain_text(
    content: str,
) -> None:
    """
    When the input is not parseable AND contains no pattern matches,
    the fallback returns an empty list.  This confirms the fallback path
    does not produce false positives.
    """
    # Act
    features = detect_yarax_features(content)

    # Assert
    assert features == []


@pytest.mark.parametrize(
    "content",
    [
        "no patterns here at all",
        "just some words without any special syntax",
    ],
)
def test_detect_playground_features_fallback_returns_empty_for_plain_text(
    content: str,
) -> None:
    """
    Counterpart for detect_playground_features: confirms empty output when
    no patterns match in the fallback.
    """
    # Act
    features = detect_playground_features(content)

    # Assert
    assert features == []
