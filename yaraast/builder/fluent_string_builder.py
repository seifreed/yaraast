"""Fluent string builder with comprehensive modifier support."""

from __future__ import annotations

from copy import deepcopy

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.strings import (
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.builder.hex_validation import validate_hex_tokens_for_builder
from yaraast.errors import ValidationError


class FluentStringBuilder:
    """Fluent builder for YARA string definitions with full modifier support."""

    def __init__(self, identifier: str) -> None:
        self.identifier = identifier
        self._content: str | list[HexToken] | None = None
        self._string_type: str = "plain"  # "plain", "hex", "regex"
        self._modifiers: list[StringModifier] = []
        self._hex_builder: HexStringBuilder | None = None

    # String content methods
    def literal(self, content: str) -> FluentStringBuilder:
        """Set as plain string literal."""
        self._content = content
        self._string_type = "plain"
        return self

    def text(self, content: str) -> FluentStringBuilder:
        """Alias for literal."""
        return self.literal(content)

    def hex(self, pattern: str) -> FluentStringBuilder:
        """Set as hex string from pattern (e.g., '4D 5A ?? 00')."""
        self._content = self._parse_hex_pattern(pattern)
        self._string_type = "hex"
        return self

    def hex_bytes(self, *bytes_values: int | str) -> FluentStringBuilder:
        """Set as hex string from byte values."""
        tokens = []
        for byte_val in bytes_values:
            if isinstance(byte_val, bool):
                msg = f"Invalid type for hex value: {type(byte_val)}"
                raise TypeError(msg)
            if isinstance(byte_val, int):
                if not 0 <= byte_val <= 255:
                    msg = f"Byte value must be 0-255, got {byte_val}"
                    raise ValidationError(msg)
                tokens.append(HexByte(value=byte_val))
            elif isinstance(byte_val, str):
                if byte_val in {"?", "??"}:
                    tokens.append(HexWildcard())
                elif len(byte_val) == 2 and "?" in byte_val:
                    tokens.append(self._parse_nibble(byte_val.upper()))
                else:
                    try:
                        val = int(byte_val, 16)
                    except ValueError:
                        msg = f"Invalid hex byte: {byte_val}"
                        raise ValidationError(msg) from None
                    if len(byte_val) != 2 or not 0 <= val <= 255:
                        msg = f"Invalid hex byte: {byte_val}"
                        raise ValidationError(msg)
                    tokens.append(HexByte(value=val))

        self._content = tokens
        self._string_type = "hex"
        return self

    def hex_builder(self, builder_func) -> FluentStringBuilder:
        """Set hex content using a HexStringBuilder lambda."""
        builder = HexStringBuilder()
        self._content = builder_func(builder).build()
        self._string_type = "hex"
        return self

    def regex(self, pattern: str) -> FluentStringBuilder:
        """Set as regex string."""
        self._content = pattern
        self._string_type = "regex"
        return self

    def regexp(self, pattern: str) -> FluentStringBuilder:
        """Alias for regex."""
        return self.regex(pattern)

    # String modifier methods using enhanced enums
    def ascii(self) -> FluentStringBuilder:
        """Add ASCII modifier."""
        self._add_modifier(StringModifierType.ASCII)
        return self

    def wide(self) -> FluentStringBuilder:
        """Add wide modifier."""
        self._add_modifier(StringModifierType.WIDE)
        return self

    def nocase(self) -> FluentStringBuilder:
        """Add nocase modifier."""
        self._add_modifier(StringModifierType.NOCASE)
        return self

    def case_insensitive(self) -> FluentStringBuilder:
        """Alias for nocase."""
        return self.nocase()

    def fullword(self) -> FluentStringBuilder:
        """Add fullword modifier."""
        self._add_modifier(StringModifierType.FULLWORD)
        return self

    def private(self) -> FluentStringBuilder:
        """Add private modifier."""
        self._add_modifier(StringModifierType.PRIVATE)
        return self

    def base64(self) -> FluentStringBuilder:
        """Add base64 modifier."""
        self._add_modifier(StringModifierType.BASE64)
        return self

    def base64wide(self) -> FluentStringBuilder:
        """Add base64wide modifier."""
        self._add_modifier(StringModifierType.BASE64WIDE)
        return self

    def xor(self, key: int | str | None = None) -> FluentStringBuilder:
        """Add XOR modifier with optional key."""
        if key is not None:
            key = self._coerce_xor_key(key)
            modifier = StringModifier(
                modifier_type=StringModifierType.XOR,
                value=key,
            )
        else:
            modifier = StringModifier(modifier_type=StringModifierType.XOR)

        self._modifiers.append(modifier)
        return self

    def _coerce_xor_key(self, key: int | str) -> int:
        if isinstance(key, bool):
            msg = f"Invalid XOR key value: {key}"
            raise TypeError(msg)
        if isinstance(key, str):
            try:
                key = int(key, 16)
            except ValueError:
                msg = f"Invalid XOR key value: {key}"
                raise ValidationError(msg) from None
        if not isinstance(key, int):
            msg = f"Invalid XOR key value: {key}"
            raise TypeError(msg)
        if not 0 <= key <= 255:
            msg = "XOR key must be 0-255"
            raise ValidationError(msg)
        return key

    def xor_range(self, min_key: int, max_key: int) -> FluentStringBuilder:
        """Add XOR modifier with key range."""
        if (
            isinstance(min_key, bool)
            or isinstance(max_key, bool)
            or not isinstance(min_key, int)
            or not isinstance(max_key, int)
        ):
            msg = f"Invalid XOR key value: {(min_key, max_key)}"
            raise TypeError(msg)
        if not 0 <= min_key <= 255 or not 0 <= max_key <= 255:
            msg = "XOR key range must be 0-255"
            raise ValidationError(msg)
        if min_key > max_key:
            msg = "XOR range must be ascending"
            raise ValidationError(msg)
        modifier = StringModifier(
            modifier_type=StringModifierType.XOR,
            value=(min_key, max_key),
        )
        self._modifiers.append(modifier)
        return self

    # Regex-specific modifiers
    def case_sensitive(self) -> FluentStringBuilder:
        """Mark regex as case sensitive (default)."""
        # Remove nocase if present
        self._modifiers = [
            m for m in self._modifiers if m.modifier_type != StringModifierType.NOCASE
        ]
        return self

    def dotall(self) -> FluentStringBuilder:
        """Add dotall modifier for regex (. matches newlines)."""
        self._add_modifier(StringModifierType.DOTALL)
        return self

    def multiline(self) -> FluentStringBuilder:
        """Add multiline modifier for regex."""
        self._add_modifier(StringModifierType.MULTILINE)
        return self

    # String content pattern helpers
    def mz_header(self) -> FluentStringBuilder:
        """Common MZ header pattern."""
        return self.hex("4D 5A")

    def pe_header(self) -> FluentStringBuilder:
        """Common PE header pattern."""
        return self.hex("50 45 00 00")

    def elf_header(self) -> FluentStringBuilder:
        """Common ELF header pattern."""
        return self.hex("7F 45 4C 46")

    def zip_header(self) -> FluentStringBuilder:
        """Common ZIP header pattern."""
        return self.hex("50 4B 03 04")

    def pdf_header(self) -> FluentStringBuilder:
        """PDF file header."""
        return self.literal("%PDF-")

    def email_pattern(self) -> FluentStringBuilder:
        """Email address regex pattern."""
        return self.regex(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    def ip_address_pattern(self) -> FluentStringBuilder:
        """IP address regex pattern."""
        return self.regex(r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

    def url_pattern(self) -> FluentStringBuilder:
        """URL regex pattern."""
        return self.regex(r"https?://[^\s<>\"]+")

    def domain_pattern(self) -> FluentStringBuilder:
        """Domain name regex pattern."""
        return self.regex(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

    # Advanced hex patterns
    def wildcard_sequence(self, count: int) -> FluentStringBuilder:
        """Create sequence of hex wildcards."""
        tokens = [HexWildcard() for _ in range(count)]
        self._content = tokens
        self._string_type = "hex"
        return self

    def mixed_pattern(self, pattern: str) -> FluentStringBuilder:
        """Mixed hex/wildcard pattern with ? for wildcards."""
        self._content = self._parse_hex_pattern(pattern)
        self._string_type = "hex"
        return self

    def jump_pattern(
        self,
        min_bytes: int,
        max_bytes: int | None = None,
    ) -> FluentStringBuilder:
        """Create hex jump pattern [min-max]."""
        if max_bytes is None:
            max_bytes = min_bytes

        tokens = [HexJump(min_jump=min_bytes, max_jump=max_bytes)]
        self._content = tokens
        self._string_type = "hex"
        return self

    # Build methods
    def build(self) -> StringDefinition:
        """Build the string definition."""
        if self._content is None:
            msg = f"String content not set for {self.identifier}"
            raise ValidationError(msg)

        self._validate_modifier_compatibility()

        if self._string_type == "plain":
            return PlainString(
                identifier=self.identifier,
                value=str(self._content),
                modifiers=deepcopy(self._modifiers),
            )
        if self._string_type == "hex":
            tokens = self._hex_tokens_for_build()
            validate_hex_tokens_for_builder(tokens, self.identifier)
            return HexString(
                identifier=self.identifier,
                tokens=deepcopy(tokens),
                modifiers=deepcopy(self._modifiers),
            )
        if self._string_type == "regex":
            return RegexString(
                identifier=self.identifier,
                regex=str(self._content),
                modifiers=deepcopy(self._modifiers),
            )
        msg = f"Unknown string type: {self._string_type}"
        raise ValidationError(msg)

    # Helper methods
    def _hex_tokens_for_build(self) -> list[HexToken]:
        if isinstance(self._content, list):
            return self._content
        return []

    def _add_modifier(self, modifier_type: StringModifierType) -> None:
        """Add a modifier, avoiding duplicates."""
        # Remove existing modifier of same type
        self._modifiers = [m for m in self._modifiers if m.modifier_type != modifier_type]
        # Add new modifier
        self._modifiers.append(StringModifier(modifier_type=modifier_type))

    def _validate_modifier_compatibility(self) -> None:
        regex_only = {StringModifierType.DOTALL, StringModifierType.MULTILINE}
        invalid = [
            modifier.name for modifier in self._modifiers if modifier.modifier_type in regex_only
        ]
        if invalid and self._string_type != "regex":
            names = ", ".join(invalid)
            msg = f"Regex-only modifier(s) cannot be used with {self._string_type} string {self.identifier}: {names}"
            raise ValidationError(msg)

    def _parse_hex_pattern(self, pattern: str) -> list[HexToken]:
        """Parse hex pattern string into tokens."""
        tokens = []
        hex_chars = self._normalize_hex_pattern(pattern)

        i = 0
        while i < len(hex_chars):
            if i + 1 >= len(hex_chars):
                msg = f"Invalid hex pattern at offset {i}: {hex_chars[i:]}"
                raise ValidationError(msg)

            two_char = hex_chars[i : i + 2]
            token, consumed = self._parse_hex_pair(two_char)

            tokens.append(token)
            i += consumed

        return tokens

    def _normalize_hex_pattern(self, pattern: str) -> str:
        """Normalize hex pattern by removing whitespace and converting to uppercase."""
        return pattern.replace(" ", "").replace("\t", "").replace("\n", "").upper()

    def _parse_hex_pair(self, two_char: str) -> tuple[HexToken | None, int]:
        """Parse two characters as hex token.

        Returns:
            Tuple of (token or None, characters consumed)

        """
        if two_char == "??":
            return HexWildcard(), 2

        if "?" in two_char:
            return self._parse_nibble(two_char), 2

        try:
            byte_val = int(two_char, 16)
            return HexByte(value=byte_val), 2
        except ValueError:
            msg = f"Invalid hex pair: {two_char}"
            raise ValidationError(msg) from None

    def _parse_nibble(self, two_char: str) -> HexNibble:
        """Parse a half-wildcard pattern like ?0 or 0?."""
        try:
            if two_char[0] == "?":
                return HexNibble(high=False, value=int(two_char[1], 16))
            return HexNibble(high=True, value=int(two_char[0], 16))
        except ValueError:
            msg = f"Invalid nibble pattern: {two_char}"
            raise ValidationError(msg) from None

    # Static factory methods
    @staticmethod
    def string(identifier: str) -> FluentStringBuilder:
        """Create a new string builder."""
        return FluentStringBuilder(identifier)

    @staticmethod
    def text_string(identifier: str, content: str) -> FluentStringBuilder:
        """Create a text string builder."""
        return FluentStringBuilder(identifier).literal(content)

    @staticmethod
    def plain(identifier: str, content: str) -> FluentStringBuilder:
        """Create a plain string builder (alias for text_string)."""
        return FluentStringBuilder.text_string(identifier, content)

    @staticmethod
    def hex_string(identifier: str, pattern: str) -> FluentStringBuilder:
        """Create a hex string builder."""
        return FluentStringBuilder(identifier).hex(pattern)

    @staticmethod
    def regex_string(identifier: str, pattern: str) -> FluentStringBuilder:
        """Create a regex string builder."""
        return FluentStringBuilder(identifier).regex(pattern)


# Convenience functions for common patterns
def string(identifier: str) -> FluentStringBuilder:
    """Create a new fluent string builder."""
    return FluentStringBuilder.string(identifier)


def text(identifier: str, content: str) -> FluentStringBuilder:
    """Create a text string with content."""
    return FluentStringBuilder.text_string(identifier, content)


def hex_pattern(identifier: str, pattern: str) -> FluentStringBuilder:
    """Create a hex string with pattern."""
    return FluentStringBuilder.hex_string(identifier, pattern)


def regex(identifier: str, pattern: str) -> FluentStringBuilder:
    """Create a regex string with pattern."""
    return FluentStringBuilder.regex_string(identifier, pattern)


# Common pattern builders
def mz_header(identifier: str = "$mz") -> FluentStringBuilder:
    """MZ header string."""
    return FluentStringBuilder.string(identifier).mz_header()


def pe_header(identifier: str = "$pe") -> FluentStringBuilder:
    """PE header string."""
    return FluentStringBuilder.string(identifier).pe_header()


def elf_header(identifier: str = "$elf") -> FluentStringBuilder:
    """ELF header string."""
    return FluentStringBuilder.string(identifier).elf_header()


def email_regex(identifier: str = "$email") -> FluentStringBuilder:
    """Email regex string."""
    return FluentStringBuilder.string(identifier).email_pattern()


def ip_regex(identifier: str = "$ip") -> FluentStringBuilder:
    """IP address regex string."""
    return FluentStringBuilder.string(identifier).ip_address_pattern()


def url_regex(identifier: str = "$url") -> FluentStringBuilder:
    """URL regex string."""
    return FluentStringBuilder.string(identifier).url_pattern()
