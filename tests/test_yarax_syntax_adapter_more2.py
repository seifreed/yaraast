from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.pragmas import CustomPragma, InRulePragma
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexJump, HexString, PlainString, RegexString
from yaraast.yarax.compatibility_checker import CompatibilityIssue
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.syntax_adapter import YaraXSyntaxAdapter


def test_adapt_with_count_and_passthrough_paths() -> None:
    node = YaraFile(
        rules=[
            Rule(
                name="plain",
                modifiers=["private", "private"],
                pragmas=[InRulePragma(CustomPragma("vendor"))],
                strings=[PlainString(identifier="$a", value="abcd")],
                condition=BooleanLiteral(True),
            ),
        ],
    )

    features = YaraXFeatures.yara_compatible()
    features.disallow_duplicate_modifiers = False
    adapter = YaraXSyntaxAdapter(features=features, target="yara")
    adapted, count = adapter.adapt(node)

    assert count == 0
    assert [str(m) for m in adapted.rules[0].modifiers] == ["private", "private"]
    adapted_string = adapted.rules[0].strings[0]
    assert isinstance(adapted_string, PlainString)
    assert adapted_string.value == "abcd"
    assert [pragma.pragma.name for pragma in adapted.rules[0].pragmas] == ["vendor"]


def test_regex_adaptation_helpers_cover_escape_unescape_and_quantifiers() -> None:
    strict = YaraXSyntaxAdapter(YaraXFeatures.yarax_strict(), target="yarax")
    assert strict._escape_braces(r"abc\{x") == r"abc\{x"
    assert strict._escape_braces("ab{c") == r"ab\{c"
    assert strict._escape_braces("a{2}") == "a{2}"
    assert strict._is_quantifier_brace("{abc", 0) is False
    assert strict._is_quantifier_brace("(a){2}", 3) is True
    assert strict._is_quantifier_brace(r"\w{2,}", 2) is True
    assert strict._is_quantifier_brace("a{,2}", 1) is True
    assert strict._is_quantifier_brace("+{2}", 1) is False

    relaxed = YaraXSyntaxAdapter(YaraXFeatures.yara_compatible(), target="yara")
    regex = RegexString(identifier="$r", regex=r"a\{b\}", modifiers=[])
    adapted = relaxed.visit_regex_string(regex)
    assert adapted.regex == "a{b}"
    assert relaxed._unescape_braces(r"\{x\}") == "{x}"


def test_hex_nodes_and_plain_string_passthrough_are_preserved() -> None:
    adapter = YaraXSyntaxAdapter(YaraXFeatures.yarax_strict(), target="yarax")

    plain = PlainString(identifier="$a", value="abcdef", modifiers=[])
    assert adapter.visit_plain_string(plain) is plain

    hex_string = HexString(
        identifier="$anon_1",
        tokens=[HexByte(0x41), HexJump(1, 2)],
        modifiers=[],
        is_anonymous=True,
    )
    adapted_hex = adapter.visit_hex_string(hex_string)
    assert adapted_hex.tokens == hex_string.tokens
    assert adapted_hex.is_anonymous is True

    jump = HexJump(2, 4)
    assert adapter.visit_hex_jump(jump) is jump


def test_generate_migration_guide_covers_all_sections() -> None:
    adapter = YaraXSyntaxAdapter(YaraXFeatures.yarax_strict(), target="yarax")
    issues = [
        CompatibilityIssue("error", None, "unescaped_brace", "brace", ""),
        CompatibilityIssue("error", None, "invalid_escape", "Invalid escape '\\\\g' found", ""),
        CompatibilityIssue("error", None, "invalid_escape", "Invalid escape '\\\\k' found", ""),
        CompatibilityIssue("error", None, "base64_too_short", "base64", ""),
        CompatibilityIssue("error", None, "duplicate_modifier", "dup", ""),
        CompatibilityIssue("warning", None, "yarax_feature", "YARA-X feature: with statements", ""),
    ]

    guide = adapter.generate_migration_guide(issues)

    assert "Regex Brace Escaping" in guide
    assert "Invalid Escape Sequences" in guide
    assert r"\g" in guide and r"\k" in guide
    assert "Base64 Pattern Length" in guide
    assert "Duplicate Modifiers" in guide
    assert "YARA-X Specific Features" in guide
    assert "with statements" in guide


def test_base64_padding_and_regex_noop_paths() -> None:
    features = YaraXFeatures.yarax_strict()
    features.minimum_base64_length = 4
    adapter = YaraXSyntaxAdapter(features=features, target="yarax")

    base64_string = PlainString(
        identifier="$b",
        value="aa",
        modifiers=[StringModifier(StringModifierType.BASE64)],
    )
    adapted = adapter.visit_plain_string(base64_string)
    assert adapted.value == "aa\x00\x00"  # Padded with null bytes for semantic neutrality

    byte_base64_string = PlainString(
        identifier="$anon_1",
        value=b"aa",
        modifiers=["base64"],
        is_anonymous=True,
    )
    adapted_bytes = adapter.visit_plain_string(byte_base64_string)
    assert adapted_bytes.value == b"aa\x00\x00"
    assert adapted_bytes.is_anonymous is True

    utf8_base64_string = PlainString(identifier="$utf8", value="éé", modifiers=["base64"])
    assert adapter.visit_plain_string(utf8_base64_string) is utf8_base64_string

    short_utf8_base64_string = PlainString(
        identifier="$short_utf8", value="é", modifiers=["base64"]
    )
    adapted_utf8 = adapter.visit_plain_string(short_utf8_base64_string)
    assert adapted_utf8.value == "é\x00\x00"

    regex = RegexString(identifier="$anon_2", regex=r"a\{2\}", modifiers=[], is_anonymous=True)
    assert adapter.visit_regex_string(regex) is regex


def test_adapted_regex_preserves_anonymous_flag() -> None:
    adapter = YaraXSyntaxAdapter(YaraXFeatures.yarax_strict(), target="yarax")
    regex = RegexString(identifier="$anon_1", regex="a{b", modifiers=[], is_anonymous=True)

    adapted = adapter.visit_regex_string(regex)

    assert adapted.regex == r"a\{b"
    assert adapted.is_anonymous is True
