from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.modifiers import StringModifier
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.errors import EvaluationError
from yaraast.evaluation.string_matcher import MatchResult, StringMatcher


def test_string_matcher_repr_and_match_all_argument_validation() -> None:
    result = MatchResult("$a", 3, 5, b"hello")
    assert repr(result) == "MatchResult($a at 3, 5 bytes)"

    matcher = StringMatcher()
    with pytest.raises(EvaluationError, match="exactly 2 arguments"):
        matcher.match_all(b"data")

    assert matcher.match_all([object()], b"abc") == {}


def test_string_matcher_match_string_for_plain_hex_regex_and_unknown_type() -> None:
    matcher = StringMatcher()

    plain = PlainString("$a", value="abc", modifiers=[])
    plain_matches = matcher.match_string(plain, b"zabcabc")
    assert [m.offset for m in plain_matches] == [1, 4]

    bytes_plain = PlainString("$bytes", value=b"\xffA", modifiers=[])
    bytes_plain_matches = matcher.match_string(bytes_plain, b"z\xffA\xffA")
    assert [m.offset for m in bytes_plain_matches] == [1, 3]

    hex_string = HexString("$h", tokens=[HexByte("41"), HexWildcard(), HexByte(0x43)])
    hex_matches = matcher.match_string(hex_string, b"zA1CA2C")
    assert [m.offset for m in hex_matches] == [1, 4]

    regex = RegexString("$r", regex="abc", modifiers=[])
    regex_matches = matcher.match_string(regex, b"zabcabc")
    assert [m.offset for m in regex_matches] == [1, 4]
    assert regex_matches[0].matched_data == b"abc"

    assert matcher.match_string(object(), b"abc") == []


def test_string_matcher_match_string_replaces_previous_match_state() -> None:
    matcher = StringMatcher()

    first = PlainString("$a", value="abc", modifiers=[])
    second = PlainString("$b", value="xyz", modifiers=[])

    assert len(matcher.match_string(first, b"abc")) == 1
    assert matcher.get_match_count("$a") == 1

    assert matcher.match_string(second, b"") == []
    assert matcher.get_match_count("$a") == 0
    assert matcher.get_match_count("$b") == 0


def test_string_matcher_regex_reports_overlapping_matches() -> None:
    matcher = StringMatcher()
    regex = RegexString("$re", regex="aa", modifiers=[])

    regex_matches = matcher.match_string(regex, b"aaa")

    assert [match.offset for match in regex_matches] == [0, 1]
    assert [match.length for match in regex_matches] == [2, 2]


def test_string_matcher_regex_reports_zero_length_matches_inside_data() -> None:
    matcher = StringMatcher()
    regex = RegexString("$re", regex="z*", modifiers=[])

    regex_matches = matcher.match_string(regex, b"AB")

    assert [(match.offset, match.length) for match in regex_matches] == [(0, 0), (1, 0)]


def test_string_matcher_regex_wide_and_ascii_modifiers() -> None:
    matcher = StringMatcher()
    wide_regex = RegexString(
        "$re",
        regex="AB",
        modifiers=[StringModifier.from_name_value("wide")],
    )
    ascii_wide_regex = RegexString(
        "$re",
        regex="AB",
        modifiers=[
            StringModifier.from_name_value("ascii"),
            StringModifier.from_name_value("wide"),
        ],
    )

    assert matcher.match_string(wide_regex, b"AB") == []
    assert [
        (match.offset, match.length) for match in matcher.match_string(wide_regex, b"A\x00B\x00")
    ] == [(0, 4)]
    assert [
        (match.offset, match.length)
        for match in matcher.match_string(ascii_wide_regex, b"AB A\x00B\x00")
    ] == [(0, 2), (3, 4)]


def test_string_matcher_wide_regex_reports_zero_length_byte_offsets() -> None:
    matcher = StringMatcher()
    regex = RegexString(
        "$re",
        regex="A*",
        modifiers=[StringModifier.from_name_value("wide")],
    )

    regex_matches = matcher.match_string(regex, b"A\x00B\x00")

    assert [(match.offset, match.length) for match in regex_matches] == [
        (0, 2),
        (1, 0),
        (2, 0),
        (3, 0),
    ]


def test_string_matcher_wide_regex_builds_contiguous_segments_once() -> None:
    matcher = StringMatcher()
    data = b"A\x00" * 128

    segments = matcher._wide_regex_segments(data)

    assert segments == [(b"A" * 128, list(range(0, 256, 2)))]


def test_string_matcher_regex_fullword_filters_boundaries() -> None:
    matcher = StringMatcher()
    regex = RegexString(
        "$re",
        regex="abc",
        modifiers=[StringModifier.from_name_value("fullword")],
    )

    regex_matches = matcher.match_string(regex, b"xabc abc! abc_")

    assert [(match.offset, match.length) for match in regex_matches] == [(5, 3), (10, 3)]


def test_string_matcher_fullword_and_boundary_helpers() -> None:
    matcher = StringMatcher()
    string_def = PlainString(
        "$fw",
        modifiers=[StringModifier.from_name_value("fullword")],
        value="abc",
    )
    matcher.match_all(b"xabc abc! abc_ abc", [string_def])

    offsets = [m.offset for m in matcher.matches["$fw"]]
    assert offsets == [5, 10, 15]

    assert matcher._is_fullword(b" abc ", 1, 3) is True
    assert matcher._is_fullword(b"abc ", 0, 3) is True
    assert matcher._is_fullword(b"xabc ", 1, 3) is False
    assert matcher._is_fullword(b" abc_", 1, 3) is True


def test_string_matcher_regex_invalid_nocase_and_range_queries() -> None:
    matcher = StringMatcher()
    regex = RegexString(
        "$re",
        regex="abc",
        modifiers=[StringModifier.from_name_value("nocase")],
    )
    matcher.match_all(b"ABC abc", [regex])

    assert matcher.get_match_count("$re") == 2
    assert matcher.get_match_offset("$re", 1) == 4
    assert matcher.get_match_offset("$re", 9) is None
    assert matcher.get_match_length("$re", 0) == 3
    assert matcher.get_match_length("$re", 9) is None
    assert matcher.string_at("$re", 4) is True
    assert matcher.string_at("$re", 2) is False
    assert matcher.string_in("$re", 0, 5) is True
    assert matcher.string_in("$re", 5, 7) is False

    invalid = RegexString("$bad", regex=cast(Any, None), modifiers=[])
    matcher.match_all(b"anything", [invalid])
    assert matcher.matches["$bad"] == []


def test_string_matcher_regex_dotall_modifier_matches_across_newline() -> None:
    matcher = StringMatcher()
    regex = RegexString(
        "$dot",
        regex="a.*c",
        modifiers=[StringModifier.from_name_value("dotall")],
    )

    matcher.match_all(b"a\nc", [regex])

    assert matcher.get_match_count("$dot") == 1
    assert matcher.get_match_offset("$dot", 0) == 0
    assert matcher.get_match_length("$dot", 0) == 3

    multiline = RegexString(
        "$multi",
        regex="^b",
        modifiers=[StringModifier.from_name_value("multiline")],
    )
    matcher.match_all(b"a\nb", [multiline])
    assert matcher.get_match_count("$multi") == 1
    assert matcher.get_match_offset("$multi", 0) == 2


def test_string_matcher_regex_string_modifiers_accept_string_aliases() -> None:
    matcher = StringMatcher()
    regex = RegexString("$alias", regex="^b", modifiers=["i", "m"])

    matcher.match_all(b"a\nB", [regex])

    assert matcher.get_match_count("$alias") == 1
    assert matcher.get_match_offset("$alias", 0) == 2


def test_string_matcher_wide_ascii_and_hex_helper_edge_cases() -> None:
    matcher = StringMatcher()
    wide_ascii = PlainString(
        "$mix",
        modifiers=[
            StringModifier.from_name_value("wide"),
            StringModifier.from_name_value("ascii"),
        ],
        value="Hi",
    )
    data = b"Hi H\x00i\x00"
    matcher.match_all([wide_ascii], data)
    assert [m.offset for m in matcher.matches["$mix"]] == [0, 3]

    overlap = PlainString(
        "$overlap",
        modifiers=[
            StringModifier.from_name_value("ascii"),
            StringModifier.from_name_value("wide"),
        ],
        value="A",
    )
    overlap_matches = matcher.match_string(overlap, b"A\x00A")
    assert [(match.offset, match.length, match.matched_data) for match in overlap_matches] == [
        (0, 1, b"A"),
        (2, 1, b"A"),
    ]

    assert matcher._find_hex_pattern(b"abc", [], []) == []
    assert matcher._find_hex_pattern(b"ab", [0x61, 0x62, 0x63], [False, False, False]) == []


def test_string_matcher_wide_fullword_uses_utf16_boundaries() -> None:
    matcher = StringMatcher()
    string = PlainString(
        "$wide",
        modifiers=[
            StringModifier.from_name_value("wide"),
            StringModifier.from_name_value("fullword"),
        ],
        value="A",
    )

    assert matcher.match_string(string, b"x\x00A\x00") == []
    assert [
        (match.offset, match.length) for match in matcher.match_string(string, b"!\x00A\x00")
    ] == [(2, 2)]
    assert matcher.match_string(string, b"A\x00x\x00") == []
    assert [(match.offset, match.length) for match in matcher.match_string(string, b"A\x00x")] == [
        (0, 2)
    ]


def test_string_matcher_hex_tokens_match_yara_token_semantics() -> None:
    matcher = StringMatcher()
    hex_string = HexString(
        "$h",
        tokens=[
            HexByte(0x41),
            HexJump(2, 2),
            HexAlternative([[HexNibble(high=True, value=0x4)], [HexNegatedByte(0x3B)]]),
            HexNibble(high=False, value=0xF),
        ],
    )

    matches = matcher.match_string(hex_string, b"AxyB\x0fAz\xff\x3b\x0f")

    assert [(match.offset, match.length) for match in matches] == [(0, 5)]

    negated = HexString("$n", tokens=[HexByte(0x41), HexNegatedByte(0x00)])
    negated_matches = matcher.match_string(negated, b"A\x01A\x00")

    assert [(match.offset, match.length) for match in negated_matches] == [(0, 2)]

    scalar_alt = HexString("$scalar", tokens=[HexAlternative([0x90, "91"])])
    scalar_matches = matcher.match_string(scalar_alt, b"\x90\x91\x92")

    assert [(match.offset, match.length, match.matched_data) for match in scalar_matches] == [
        (0, 1, b"\x90"),
        (1, 1, b"\x91"),
    ]


def test_string_matcher_plain_string_xor_modifier_matches_encoded_bytes() -> None:
    matcher = StringMatcher()
    xor_string = PlainString(
        "$xor",
        value="ABC",
        modifiers=[StringModifier.from_name_value("xor", 1)],
    )

    matcher.match_all(b"ABC \x40\x43\x42", [xor_string])

    assert [(match.offset, match.matched_data) for match in matcher.matches["$xor"]] == [
        (4, b"\x40\x43\x42")
    ]


def test_string_matcher_bare_xor_modifier_includes_plaintext_key() -> None:
    matcher = StringMatcher()
    xor_string = PlainString(
        "$xor",
        value="ABC",
        modifiers=[StringModifier.from_name_value("xor")],
    )

    matcher.match_all(b"ABC \x40\x43\x42", [xor_string])

    assert [(match.offset, match.matched_data) for match in matcher.matches["$xor"]] == [
        (0, b"ABC"),
        (4, b"\x40\x43\x42"),
    ]


def test_string_matcher_plain_string_base64_modifier_matches_encoded_text() -> None:
    matcher = StringMatcher()
    base64_string = PlainString(
        "$b64",
        value="ABC",
        modifiers=[StringModifier.from_name_value("base64")],
    )

    matcher.match_all(b"ABC QUJD FCQ BQk", [base64_string])

    assert [(match.offset, match.matched_data) for match in matcher.matches["$b64"]] == [
        (4, b"QUJD"),
        (9, b"FCQ"),
        (13, b"BQk"),
    ]

    base64wide_string = PlainString(
        "$b64w",
        value="AB",
        modifiers=[StringModifier.from_name_value("base64wide")],
    )
    matcher.match_all(b"AB Q\x00U\x00 F\x00C\x00 B\x00Q\x00 QQBCAA==", [base64wide_string])
    assert [(match.offset, match.matched_data) for match in matcher.matches["$b64w"]] == [
        (3, b"Q\x00U\x00"),
        (8, b"F\x00C\x00"),
        (13, b"B\x00Q\x00"),
    ]

    custom_alphabet_string = PlainString(
        "$b64custom",
        value=b"\xfb\xff",
        modifiers=[
            StringModifier.from_name_value(
                "base64",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            )
        ],
    )
    matcher.match_all(b"+/ -_", [custom_alphabet_string])
    assert [(match.offset, match.matched_data) for match in matcher.matches["$b64custom"]] == [
        (3, b"-_"),
    ]
