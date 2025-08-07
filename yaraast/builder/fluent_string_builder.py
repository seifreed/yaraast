"""Fluent string builder with comprehensive modifier support."""

from __future__ import annotations

from yaraast.ast.modifiers import StringModifier as EnhancedStringModifier
from yaraast.ast.modifiers import StringModifierType
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


class FluentStringBuilder:
    """Fluent builder for YARA string definitions with full modifier support."""

    def __init__(self, identifier: str) -> None:
        self.identifier = identifier
        self._content: str | list[HexToken] | None = None
        self._string_type: str = "plain"  # "plain", "hex", "regex"
        self._modifiers: list[EnhancedStringModifier] = []
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
            if isinstance(byte_val, int):
                tokens.append(HexByte(value=byte_val))
            elif isinstance(byte_val, str):
                if byte_val in {"?", "??"}:
                    tokens.append(HexWildcard())
                else:
                    # Parse hex string
                    try:
                        val = int(byte_val, 16)
                        tokens.append(HexByte(value=val))
                    except ValueError:
                        tokens.append(HexWildcard())

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
            if isinstance(key, str):
                # Convert hex string to int
                try:
                    key = int(key, 16)
                except ValueError:
                    key = None

            modifier = EnhancedStringModifier(
                modifier_type=StringModifierType.XOR,
                value=key,
            )
        else:
            modifier = EnhancedStringModifier(modifier_type=StringModifierType.XOR)

        self._modifiers.append(modifier)
        return self

    def xor_range(self, min_key: int, max_key: int) -> FluentStringBuilder:
        """Add XOR modifier with key range."""
        modifier = EnhancedStringModifier(
            modifier_type=StringModifierType.XOR,
            value={"min": min_key, "max": max_key},
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
        return self.regex(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

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
            raise ValueError(msg)

        # Convert enhanced modifiers to legacy format for compatibility
        legacy_modifiers = []
        for mod in self._modifiers:
            legacy_modifiers.append(mod.to_legacy_modifier())

        if self._string_type == "plain":
            return PlainString(
                identifier=self.identifier,
                value=str(self._content),
                modifiers=legacy_modifiers,
            )
        if self._string_type == "hex":
            return HexString(
                identifier=self.identifier,
                tokens=self._content if isinstance(self._content, list) else [],
                modifiers=legacy_modifiers,
            )
        if self._string_type == "regex":
            return RegexString(
                identifier=self.identifier,
                regex=str(self._content),
                modifiers=legacy_modifiers,
            )
        msg = f"Unknown string type: {self._string_type}"
        raise ValueError(msg)

    # Helper methods
    def _add_modifier(self, modifier_type: StringModifierType) -> None:
        """Add a modifier, avoiding duplicates."""
        # Remove existing modifier of same type
        self._modifiers = [m for m in self._modifiers if m.modifier_type != modifier_type]
        # Add new modifier
        self._modifiers.append(EnhancedStringModifier(modifier_type=modifier_type))

    def _parse_hex_pattern(self, pattern: str) -> list[HexToken]:
        """Parse hex pattern string into tokens."""
        tokens = []
        hex_chars = self._normalize_hex_pattern(pattern)

        i = 0
        while i < len(hex_chars):
            if i + 1 >= len(hex_chars):
                i += 1  # Single character, skip
                continue

            two_char = hex_chars[i : i + 2]
            token, consumed = self._parse_hex_pair(two_char)

            if token:
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
            return None, 1

    def _parse_nibble(self, two_char: str) -> HexNibble:
        """Parse a half-wildcard pattern like ?0 or 0?."""
        if two_char[0] == "?":
            return HexNibble(high=False, value=int(two_char[1], 16))
        return HexNibble(high=True, value=int(two_char[0], 16))

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
