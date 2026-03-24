"""Comprehensive tests for FluentStringBuilder to achieve 80%+ coverage.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import pytest

from yaraast.ast.modifiers import StringModifierType
from yaraast.ast.strings import (
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.builder.fluent_string_builder import (
    FluentStringBuilder,
    elf_header,
    email_regex,
    hex_pattern,
    ip_regex,
    mz_header,
    pe_header,
    regex,
    string,
    text,
    url_regex,
)
from yaraast.errors import ValidationError


class TestFluentStringBuilderInitialization:
    """Test FluentStringBuilder initialization."""

    def test_initialization_with_identifier(self) -> None:
        """Builder should initialize with identifier."""
        builder = FluentStringBuilder(identifier="$test")

        assert builder.identifier == "$test"
        assert builder._content is None
        assert builder._string_type == "plain"
        assert builder._modifiers == []

    def test_initialization_sets_defaults(self) -> None:
        """Builder should set default values."""
        builder = FluentStringBuilder("$default")

        assert builder._string_type == "plain"
        assert builder._content is None
        assert builder._hex_builder is None


class TestFluentStringBuilderTextStrings:
    """Test text/plain string creation."""

    def test_literal_sets_plain_string(self) -> None:
        """Literal method should set plain string content."""
        builder = FluentStringBuilder("$text")

        result = builder.literal("malware")

        assert result is builder
        assert builder._content == "malware"
        assert builder._string_type == "plain"

    def test_text_is_alias_for_literal(self) -> None:
        """Text method should work as alias for literal."""
        builder = FluentStringBuilder("$text")

        result = builder.text("payload")

        assert result is builder
        assert builder._content == "payload"
        assert builder._string_type == "plain"

    def test_literal_build_creates_plain_string(self) -> None:
        """Building literal should create PlainString."""
        builder = FluentStringBuilder("$plain").literal("test")

        string_def = builder.build()

        assert isinstance(string_def, PlainString)
        assert string_def.identifier == "$plain"
        assert string_def.value == "test"


class TestFluentStringBuilderHexStrings:
    """Test hex string creation."""

    def test_hex_parses_pattern(self) -> None:
        """Hex method should parse hex pattern."""
        builder = FluentStringBuilder("$hex")

        result = builder.hex("4D 5A 90")

        assert result is builder
        assert builder._string_type == "hex"
        assert isinstance(builder._content, list)
        assert len(builder._content) == 3

    def test_hex_with_wildcards(self) -> None:
        """Hex method should parse wildcard patterns."""
        builder = FluentStringBuilder("$hex")

        result = builder.hex("FF ?? AA")

        assert result is builder
        tokens = builder._content
        assert isinstance(tokens, list)
        assert len(tokens) == 3
        assert isinstance(tokens[0], HexByte)
        assert isinstance(tokens[1], HexWildcard)
        assert isinstance(tokens[2], HexByte)

    def test_hex_bytes_with_integers(self) -> None:
        """Hex_bytes method should accept integer values."""
        builder = FluentStringBuilder("$hex")

        result = builder.hex_bytes(0x4D, 0x5A, 0x90)

        assert result is builder
        assert len(builder._content) == 3
        assert all(isinstance(t, HexByte) for t in builder._content)

    def test_hex_bytes_with_strings(self) -> None:
        """Hex_bytes method should accept string values."""
        builder = FluentStringBuilder("$hex")

        result = builder.hex_bytes("4D", "5A", "90")

        assert result is builder
        assert len(builder._content) == 3

    def test_hex_bytes_with_wildcard_string(self) -> None:
        """Hex_bytes should recognize ?? as wildcard."""
        builder = FluentStringBuilder("$hex")

        result = builder.hex_bytes("FF", "??", "AA")

        assert result is builder
        tokens = builder._content
        assert isinstance(tokens[1], HexWildcard)

    def test_hex_bytes_with_question_mark(self) -> None:
        """Hex_bytes should recognize ? as wildcard."""
        builder = FluentStringBuilder("$hex")

        result = builder.hex_bytes("?")

        assert result is builder
        assert isinstance(builder._content[0], HexWildcard)

    def test_hex_builder_with_lambda(self) -> None:
        """Hex_builder method should accept builder function."""
        builder = FluentStringBuilder("$hex")

        result = builder.hex_builder(lambda hb: hb.add(0x4D).add(0x5A).wildcard())

        assert result is builder
        assert builder._string_type == "hex"
        assert len(builder._content) == 3

    def test_hex_build_creates_hex_string(self) -> None:
        """Building hex should create HexString."""
        builder = FluentStringBuilder("$hex").hex("4D 5A")

        string_def = builder.build()

        assert isinstance(string_def, HexString)
        assert string_def.identifier == "$hex"
        assert len(string_def.tokens) == 2


class TestFluentStringBuilderRegexStrings:
    """Test regex string creation."""

    def test_regex_sets_regex_pattern(self) -> None:
        """Regex method should set regex pattern."""
        builder = FluentStringBuilder("$re")

        result = builder.regex(r"[0-9]+")

        assert result is builder
        assert builder._content == r"[0-9]+"
        assert builder._string_type == "regex"

    def test_regexp_is_alias_for_regex(self) -> None:
        """Regexp method should work as alias for regex."""
        builder = FluentStringBuilder("$re")

        result = builder.regexp(r"\w+")

        assert result is builder
        assert builder._content == r"\w+"
        assert builder._string_type == "regex"

    def test_regex_build_creates_regex_string(self) -> None:
        """Building regex should create RegexString."""
        builder = FluentStringBuilder("$re").regex(r"test.*")

        string_def = builder.build()

        assert isinstance(string_def, RegexString)
        assert string_def.identifier == "$re"
        assert string_def.regex == r"test.*"


class TestFluentStringBuilderModifiers:
    """Test string modifier methods."""

    def test_ascii_adds_ascii_modifier(self) -> None:
        """Ascii method should add ASCII modifier."""
        builder = FluentStringBuilder("$s").literal("test")

        result = builder.ascii()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.ASCII

    def test_wide_adds_wide_modifier(self) -> None:
        """Wide method should add wide modifier."""
        builder = FluentStringBuilder("$s").literal("test")

        result = builder.wide()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.WIDE

    def test_nocase_adds_nocase_modifier(self) -> None:
        """Nocase method should add nocase modifier."""
        builder = FluentStringBuilder("$s").literal("test")

        result = builder.nocase()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.NOCASE

    def test_case_insensitive_is_alias(self) -> None:
        """Case_insensitive should be alias for nocase."""
        builder = FluentStringBuilder("$s").literal("test")

        result = builder.case_insensitive()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.NOCASE

    def test_fullword_adds_fullword_modifier(self) -> None:
        """Fullword method should add fullword modifier."""
        builder = FluentStringBuilder("$s").literal("word")

        result = builder.fullword()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.FULLWORD

    def test_private_adds_private_modifier(self) -> None:
        """Private method should add private modifier."""
        builder = FluentStringBuilder("$s").literal("hidden")

        result = builder.private()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.PRIVATE

    def test_base64_adds_base64_modifier(self) -> None:
        """Base64 method should add base64 modifier."""
        builder = FluentStringBuilder("$s").literal("encoded")

        result = builder.base64()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.BASE64

    def test_base64wide_adds_base64wide_modifier(self) -> None:
        """Base64wide method should add base64wide modifier."""
        builder = FluentStringBuilder("$s").literal("encoded")

        result = builder.base64wide()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.BASE64WIDE

    def test_xor_without_key(self) -> None:
        """Xor without key should add XOR modifier."""
        builder = FluentStringBuilder("$s").literal("data")

        result = builder.xor()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.XOR

    def test_xor_with_integer_key(self) -> None:
        """Xor with integer key should set key value."""
        builder = FluentStringBuilder("$s").literal("data")

        result = builder.xor(0xFF)

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].value == 0xFF

    def test_xor_with_hex_string_key(self) -> None:
        """Xor with hex string should convert to integer."""
        builder = FluentStringBuilder("$s").literal("data")

        result = builder.xor("FF")

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].value == 0xFF

    def test_xor_with_invalid_hex_string(self) -> None:
        """Xor with invalid hex string should default to None."""
        builder = FluentStringBuilder("$s").literal("data")

        result = builder.xor("XYZ")

        assert result is builder
        assert len(builder._modifiers) == 1

    def test_xor_range_sets_range_value(self) -> None:
        """Xor_range should set min and max key values."""
        builder = FluentStringBuilder("$s").literal("data")

        result = builder.xor_range(0, 255)

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].value["min"] == 0
        assert builder._modifiers[0].value["max"] == 255


class TestFluentStringBuilderRegexModifiers:
    """Test regex-specific modifiers."""

    def test_case_sensitive_removes_nocase(self) -> None:
        """Case_sensitive should remove nocase modifier."""
        builder = FluentStringBuilder("$re").regex(r"\w+").nocase()

        result = builder.case_sensitive()

        assert result is builder
        assert len(builder._modifiers) == 0

    def test_regex_with_nocase_modifier(self) -> None:
        """Regex should work with nocase modifier."""
        builder = FluentStringBuilder("$re").regex(r".*")

        result = builder.nocase()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.NOCASE

    def test_regex_with_wide_modifier(self) -> None:
        """Regex should work with wide modifier."""
        builder = FluentStringBuilder("$re").regex(r"^test")

        result = builder.wide()

        assert result is builder
        assert len(builder._modifiers) == 1
        assert builder._modifiers[0].modifier_type == StringModifierType.WIDE


class TestFluentStringBuilderCommonPatterns:
    """Test common pattern helper methods."""

    def test_mz_header_creates_mz_pattern(self) -> None:
        """Mz_header should create MZ header pattern."""
        builder = FluentStringBuilder("$mz")

        result = builder.mz_header()
        string_def = result.build()

        assert isinstance(string_def, HexString)
        assert len(string_def.tokens) == 2
        assert string_def.tokens[0].value == 0x4D
        assert string_def.tokens[1].value == 0x5A

    def test_pe_header_creates_pe_pattern(self) -> None:
        """Pe_header should create PE header pattern."""
        builder = FluentStringBuilder("$pe")

        result = builder.pe_header()
        string_def = result.build()

        assert isinstance(string_def, HexString)
        assert len(string_def.tokens) == 4

    def test_elf_header_creates_elf_pattern(self) -> None:
        """Elf_header should create ELF header pattern."""
        builder = FluentStringBuilder("$elf")

        result = builder.elf_header()
        string_def = result.build()

        assert isinstance(string_def, HexString)
        assert len(string_def.tokens) == 4

    def test_zip_header_creates_zip_pattern(self) -> None:
        """Zip_header should create ZIP header pattern."""
        builder = FluentStringBuilder("$zip")

        result = builder.zip_header()
        string_def = result.build()

        assert isinstance(string_def, HexString)
        assert len(string_def.tokens) == 4

    def test_pdf_header_creates_pdf_pattern(self) -> None:
        """Pdf_header should create PDF header pattern."""
        builder = FluentStringBuilder("$pdf")

        result = builder.pdf_header()
        string_def = result.build()

        assert isinstance(string_def, PlainString)
        assert string_def.value == "%PDF-"

    def test_email_pattern_creates_email_regex(self) -> None:
        """Email_pattern should create email regex."""
        builder = FluentStringBuilder("$email")

        result = builder.email_pattern()
        string_def = result.build()

        assert isinstance(string_def, RegexString)
        assert "@" in string_def.regex

    def test_ip_address_pattern_creates_ip_regex(self) -> None:
        """Ip_address_pattern should create IP address regex."""
        builder = FluentStringBuilder("$ip")

        result = builder.ip_address_pattern()
        string_def = result.build()

        assert isinstance(string_def, RegexString)

    def test_url_pattern_creates_url_regex(self) -> None:
        """Url_pattern should create URL regex."""
        builder = FluentStringBuilder("$url")

        result = builder.url_pattern()
        string_def = result.build()

        assert isinstance(string_def, RegexString)
        assert "https?" in string_def.regex

    def test_domain_pattern_creates_domain_regex(self) -> None:
        """Domain_pattern should create domain regex."""
        builder = FluentStringBuilder("$domain")

        result = builder.domain_pattern()
        string_def = result.build()

        assert isinstance(string_def, RegexString)


class TestFluentStringBuilderAdvancedHexPatterns:
    """Test advanced hex pattern methods."""

    def test_wildcard_sequence_creates_wildcards(self) -> None:
        """Wildcard_sequence should create sequence of wildcards."""
        builder = FluentStringBuilder("$wild")

        result = builder.wildcard_sequence(5)

        assert result is builder
        assert len(builder._content) == 5
        assert all(isinstance(t, HexWildcard) for t in builder._content)

    def test_mixed_pattern_parses_mixed_hex(self) -> None:
        """Mixed_pattern should parse hex with wildcards."""
        builder = FluentStringBuilder("$mixed")

        result = builder.mixed_pattern("FF ?? AA")

        assert result is builder
        assert len(builder._content) == 3

    def test_jump_pattern_creates_jump(self) -> None:
        """Jump_pattern should create jump token."""
        builder = FluentStringBuilder("$jump")

        result = builder.jump_pattern(2, 8)

        assert result is builder
        assert len(builder._content) == 1
        assert isinstance(builder._content[0], HexJump)
        assert builder._content[0].min_jump == 2
        assert builder._content[0].max_jump == 8

    def test_jump_pattern_without_max(self) -> None:
        """Jump_pattern without max should use min as max."""
        builder = FluentStringBuilder("$jump")

        result = builder.jump_pattern(5)

        assert result is builder
        assert builder._content[0].min_jump == 5
        assert builder._content[0].max_jump == 5


class TestFluentStringBuilderBuildMethod:
    """Test build method and error handling."""

    def test_build_without_content_raises_error(self) -> None:
        """Build without content should raise ValueError."""
        builder = FluentStringBuilder("$empty")

        with pytest.raises(ValidationError, match="String content not set"):
            builder.build()

    def test_build_with_invalid_type_raises_error(self) -> None:
        """Build with invalid string type should raise ValueError."""
        builder = FluentStringBuilder("$invalid")
        builder._string_type = "invalid_type"
        builder._content = "test"

        with pytest.raises(ValidationError, match="Unknown string type"):
            builder.build()

    def test_build_plain_string_with_modifiers(self) -> None:
        """Build should include modifiers in plain string."""
        builder = FluentStringBuilder("$s").literal("test").nocase().wide()

        string_def = builder.build()

        assert isinstance(string_def, PlainString)
        assert len(string_def.modifiers) == 2

    def test_build_hex_string_with_modifiers(self) -> None:
        """Build should include modifiers in hex string."""
        builder = FluentStringBuilder("$h").hex("FF AA").private()

        string_def = builder.build()

        assert isinstance(string_def, HexString)
        assert len(string_def.modifiers) == 1

    def test_build_regex_string_with_modifiers(self) -> None:
        """Build should include modifiers in regex string."""
        builder = FluentStringBuilder("$r").regex(r"\w+").nocase()

        string_def = builder.build()

        assert isinstance(string_def, RegexString)
        assert len(string_def.modifiers) == 1


class TestFluentStringBuilderHelperMethods:
    """Test helper methods."""

    def test_add_modifier_removes_duplicates(self) -> None:
        """_add_modifier should remove existing modifier of same type."""
        builder = FluentStringBuilder("$s").literal("test")
        builder._add_modifier(StringModifierType.NOCASE)
        builder._add_modifier(StringModifierType.WIDE)
        builder._add_modifier(StringModifierType.NOCASE)

        assert len(builder._modifiers) == 2

    def test_parse_hex_pattern_handles_complex_pattern(self) -> None:
        """_parse_hex_pattern should handle complex patterns."""
        builder = FluentStringBuilder("$hex")
        tokens = builder._parse_hex_pattern("4D 5A ?? F? ?A 90")

        assert len(tokens) > 0

    def test_normalize_hex_pattern_removes_whitespace(self) -> None:
        """_normalize_hex_pattern should remove whitespace."""
        builder = FluentStringBuilder("$hex")
        result = builder._normalize_hex_pattern("4D 5A\t90\n00")

        assert result == "4D5A9000"

    def test_parse_hex_pair_with_wildcard(self) -> None:
        """_parse_hex_pair should recognize wildcard."""
        builder = FluentStringBuilder("$hex")
        token, consumed = builder._parse_hex_pair("??")

        assert isinstance(token, HexWildcard)
        assert consumed == 2

    def test_parse_hex_pair_with_nibble(self) -> None:
        """_parse_hex_pair should recognize nibble patterns."""
        builder = FluentStringBuilder("$hex")
        token, consumed = builder._parse_hex_pair("F?")

        assert isinstance(token, HexNibble)
        assert consumed == 2

    def test_parse_hex_pair_with_byte(self) -> None:
        """_parse_hex_pair should parse byte value."""
        builder = FluentStringBuilder("$hex")
        token, consumed = builder._parse_hex_pair("FF")

        assert isinstance(token, HexByte)
        assert token.value == 0xFF
        assert consumed == 2

    def test_parse_nibble_high_nibble(self) -> None:
        """_parse_nibble should parse high nibble pattern."""
        builder = FluentStringBuilder("$hex")
        nibble = builder._parse_nibble("F?")

        assert isinstance(nibble, HexNibble)
        assert nibble.high is True
        assert nibble.value == 0xF

    def test_parse_nibble_low_nibble(self) -> None:
        """_parse_nibble should parse low nibble pattern."""
        builder = FluentStringBuilder("$hex")
        nibble = builder._parse_nibble("?A")

        assert isinstance(nibble, HexNibble)
        assert nibble.high is False
        assert nibble.value == 0xA


class TestFluentStringBuilderStaticMethods:
    """Test static factory methods."""

    def test_string_factory_creates_builder(self) -> None:
        """String static method should create builder."""
        builder = FluentStringBuilder.string("$test")

        assert isinstance(builder, FluentStringBuilder)
        assert builder.identifier == "$test"

    def test_text_string_factory_creates_builder_with_content(self) -> None:
        """Text_string should create builder with content."""
        builder = FluentStringBuilder.text_string("$s", "malware")

        assert builder.identifier == "$s"
        assert builder._content == "malware"

    def test_plain_is_alias_for_text_string(self) -> None:
        """Plain should be alias for text_string."""
        builder = FluentStringBuilder.plain("$p", "test")

        assert builder._content == "test"

    def test_hex_string_factory_creates_hex_builder(self) -> None:
        """Hex_string should create builder with hex pattern."""
        builder = FluentStringBuilder.hex_string("$h", "4D 5A")

        assert builder._string_type == "hex"

    def test_regex_string_factory_creates_regex_builder(self) -> None:
        """Regex_string should create builder with regex pattern."""
        builder = FluentStringBuilder.regex_string("$r", r"\w+")

        assert builder._string_type == "regex"
        assert builder._content == r"\w+"


class TestFluentStringBuilderConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_string_function_creates_builder(self) -> None:
        """String function should create builder."""
        builder = string("$test")

        assert isinstance(builder, FluentStringBuilder)
        assert builder.identifier == "$test"

    def test_text_function_creates_text_builder(self) -> None:
        """Text function should create text builder."""
        builder = text("$t", "content")

        assert builder._content == "content"

    def test_hex_pattern_function_creates_hex_builder(self) -> None:
        """Hex_pattern function should create hex builder."""
        builder = hex_pattern("$h", "FF AA")

        assert builder._string_type == "hex"

    def test_regex_function_creates_regex_builder(self) -> None:
        """Regex function should create regex builder."""
        builder = regex("$r", r"[0-9]+")

        assert builder._string_type == "regex"

    def test_mz_header_function_creates_mz_pattern(self) -> None:
        """Mz_header function should create MZ pattern builder."""
        builder = mz_header()

        assert builder.identifier == "$mz"
        string_def = builder.build()
        assert isinstance(string_def, HexString)

    def test_mz_header_with_custom_identifier(self) -> None:
        """Mz_header should accept custom identifier."""
        builder = mz_header("$custom")

        assert builder.identifier == "$custom"

    def test_pe_header_function_creates_pe_pattern(self) -> None:
        """Pe_header function should create PE pattern builder."""
        builder = pe_header()

        assert builder.identifier == "$pe"

    def test_elf_header_function_creates_elf_pattern(self) -> None:
        """Elf_header function should create ELF pattern builder."""
        builder = elf_header()

        assert builder.identifier == "$elf"

    def test_email_regex_function_creates_email_pattern(self) -> None:
        """Email_regex function should create email pattern."""
        builder = email_regex()

        assert builder.identifier == "$email"
        string_def = builder.build()
        assert isinstance(string_def, RegexString)

    def test_ip_regex_function_creates_ip_pattern(self) -> None:
        """Ip_regex function should create IP pattern."""
        builder = ip_regex()

        assert builder.identifier == "$ip"

    def test_url_regex_function_creates_url_pattern(self) -> None:
        """Url_regex function should create URL pattern."""
        builder = url_regex()

        assert builder.identifier == "$url"


class TestFluentStringBuilderComplexScenarios:
    """Test complex real-world scenarios."""

    def test_malware_detection_string_with_modifiers(self) -> None:
        """Build complete malware detection string."""
        string_def = (
            FluentStringBuilder("$malware")
            .literal("This program cannot be run")
            .nocase()
            .wide()
            .fullword()
            .build()
        )

        assert isinstance(string_def, PlainString)
        assert len(string_def.modifiers) == 3

    def test_obfuscated_string_with_xor(self) -> None:
        """Build obfuscated string with XOR."""
        string_def = FluentStringBuilder("$obf").literal("hidden").xor_range(1, 255).build()

        assert isinstance(string_def, PlainString)
        assert len(string_def.modifiers) == 1

    def test_shellcode_hex_pattern(self) -> None:
        """Build complex shellcode hex pattern."""
        string_def = FluentStringBuilder("$shellcode").hex("48 8B").build()

        assert isinstance(string_def, HexString)
        assert len(string_def.tokens) == 2

    def test_regex_with_multiple_modifiers(self) -> None:
        """Build regex with multiple modifiers."""
        string_def = (
            FluentStringBuilder("$regex")
            .regex(r"malware.*payload")
            .nocase()
            .ascii()
            .fullword()
            .build()
        )

        assert isinstance(string_def, RegexString)
        assert len(string_def.modifiers) == 3

    def test_fluent_api_chain(self) -> None:
        """Test complete fluent API chain."""
        string_def = FluentStringBuilder("$chain").literal("test").ascii().wide().nocase().build()

        assert isinstance(string_def, PlainString)
        assert len(string_def.modifiers) == 3

    def test_pe_header_with_wildcards(self) -> None:
        """Build PE header with wildcard bytes."""
        string_def = FluentStringBuilder("$pe").hex_bytes(0x4D, 0x5A, "??", "??").build()

        assert isinstance(string_def, HexString)
        assert len(string_def.tokens) == 4
