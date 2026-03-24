from __future__ import annotations

import pytest

from yaraast.ast.modifiers import StringModifier
from yaraast.ast.strings import HexByte, HexString, HexWildcard, PlainString, RegexString
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

    hex_string = HexString("$h", tokens=[HexByte("41"), HexWildcard(), HexByte(0x43)])
    hex_matches = matcher.match_string(hex_string, b"zA1CA2C")
    assert [m.offset for m in hex_matches] == [1, 4]

    regex = RegexString("$r", regex="abc", modifiers=[])
    regex_matches = matcher.match_string(regex, b"zabcabc")
    assert [m.offset for m in regex_matches] == [1, 4]
    assert regex_matches[0].matched_data == b"abc"

    assert matcher.match_string(object(), b"abc") == []


def test_string_matcher_fullword_and_boundary_helpers() -> None:
    matcher = StringMatcher()
    string_def = PlainString(
        "$fw",
        modifiers=[StringModifier.from_name_value("fullword")],
        value="abc",
    )
    matcher.match_all(b"xabc abc! abc_ abc", [string_def])

    offsets = [m.offset for m in matcher.matches["$fw"]]
    assert offsets == [5, 15]

    assert matcher._is_fullword(b" abc ", 1, 3) is True
    assert matcher._is_fullword(b"abc ", 0, 3) is True
    assert matcher._is_fullword(b"xabc ", 1, 3) is False
    assert matcher._is_fullword(b" abc_", 1, 3) is False


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

    invalid = RegexString("$bad", regex=None, modifiers=[])  # type: ignore[arg-type]
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

    assert matcher._find_hex_pattern(b"abc", [], []) == []
    assert matcher._find_hex_pattern(b"ab", [0x61, 0x62, 0x63], [False, False, False]) == []
