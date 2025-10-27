"""Hover provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Hover, MarkupContent, MarkupKind, Position

from yaraast.lsp.utils import get_word_at_position
from yaraast.parser.parser import Parser
from yaraast.types.module_loader import ModuleLoader

if TYPE_CHECKING:
    pass


class HoverProvider:
    """Provides hover information for YARA symbols."""

    def __init__(self) -> None:
        self.module_loader = ModuleLoader()
        self._init_documentation()

    def _init_documentation(self) -> None:
        """Initialize documentation for YARA keywords and built-ins."""
        self.keyword_docs = {
            "rule": "Defines a YARA rule. Each rule has a name, optional tags, meta section, strings section, and condition section.",
            "private": "Makes a rule private. Private rules are not reported by YARA, but can be used by other rules.",
            "global": "Makes a rule global. Global rules are applied to all files.",
            "meta": "Metadata section containing key-value pairs describing the rule.",
            "strings": "Section where string patterns are defined using $identifier syntax.",
            "condition": "Boolean expression that determines if the rule matches.",
            "import": "Import a YARA module to access additional functions and data structures.",
            "include": "Include another YARA file.",
            "and": "Logical AND operator",
            "or": "Logical OR operator",
            "not": "Logical NOT operator",
            "all": "Quantifier meaning 'all of'",
            "any": "Quantifier meaning 'any of'",
            "of": "Used in quantifier expressions like 'any of them'",
            "them": "Refers to all string identifiers in the current rule",
            "for": "Loop construct for iterating over collections",
            "in": "Membership operator or part of for loop",
            "at": "Tests if a string appears at a specific offset",
            "filesize": "Built-in variable containing the size of the file being scanned in bytes",
            "entrypoint": "Built-in variable containing the entry point address of PE files",
            "true": "Boolean true value",
            "false": "Boolean false value",
            "defined": "Tests if an expression is defined (useful for optional module fields)",
        }

        self.builtin_docs = {
            "uint8": "```yara\nuint8(offset) -> integer\n```\n\nReads an unsigned 8-bit integer at the given offset.",
            "uint16": "```yara\nuint16(offset) -> integer\n```\n\nReads an unsigned 16-bit integer at the given offset (little-endian).",
            "uint32": "```yara\nuint32(offset) -> integer\n```\n\nReads an unsigned 32-bit integer at the given offset (little-endian).",
            "uint16le": "```yara\nuint16le(offset) -> integer\n```\n\nReads an unsigned 16-bit integer at the given offset (little-endian).",
            "uint32le": "```yara\nuint32le(offset) -> integer\n```\n\nReads an unsigned 32-bit integer at the given offset (little-endian).",
            "uint16be": "```yara\nuint16be(offset) -> integer\n```\n\nReads an unsigned 16-bit integer at the given offset (big-endian).",
            "uint32be": "```yara\nuint32be(offset) -> integer\n```\n\nReads an unsigned 32-bit integer at the given offset (big-endian).",
            "int8": "```yara\nint8(offset) -> integer\n```\n\nReads a signed 8-bit integer at the given offset.",
            "int16": "```yara\nint16(offset) -> integer\n```\n\nReads a signed 16-bit integer at the given offset (little-endian).",
            "int32": "```yara\nint32(offset) -> integer\n```\n\nReads a signed 32-bit integer at the given offset (little-endian).",
        }

        self.module_docs = {
            "pe": "PE file format module. Provides access to PE headers, sections, imports, exports, and resources.",
            "elf": "ELF file format module. Provides access to ELF headers, sections, and segments.",
            "math": "Mathematical operations module. Provides entropy calculation and other math functions.",
            "hash": "Hash calculation module. Provides MD5, SHA1, SHA256, and checksum functions.",
            "dotnet": ".NET module. Provides access to .NET assembly metadata.",
            "time": "Time module. Provides functions for time-based operations.",
            "magic": "Magic module. Provides file type identification.",
            "console": "Console module. Provides console output for debugging.",
            "cuckoo": "Cuckoo sandbox integration module.",
            "string": "String manipulation module.",
        }

    def get_hover(self, text: str, position: Position) -> Hover | None:
        """
        Get hover information for the symbol at the given position.

        Args:
            text: The YARA source code
            position: The cursor position

        Returns:
            Hover information or None
        """
        word, word_range = get_word_at_position(text, position)

        if not word:
            return None

        # Check keywords
        if word in self.keyword_docs:
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=f"**{word}** (keyword)\n\n{self.keyword_docs[word]}",
                ),
                range=word_range,
            )

        # Check built-in functions
        if word in self.builtin_docs:
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=f"**{word}** (built-in function)\n\n{self.builtin_docs[word]}",
                ),
                range=word_range,
            )

        # Check modules
        if word in self.module_docs:
            return Hover(
                contents=MarkupContent(
                    kind=MarkupKind.Markdown,
                    value=f"**{word}** (module)\n\n{self.module_docs[word]}",
                ),
                range=word_range,
            )

        # Check module members (e.g., pe.imphash)
        if "." in word:
            parts = word.split(".")
            if len(parts) == 2:
                module_name, member_name = parts
                return self._get_module_member_hover(module_name, member_name, word_range)

        # Check string identifiers
        if word.startswith("$"):
            return self._get_string_identifier_hover(text, word, word_range)

        # Check rule names
        rule_hover = self._get_rule_hover(text, word, word_range)
        if rule_hover:
            return rule_hover

        return None

    def _get_module_member_hover(
        self,
        module_name: str,
        member_name: str,
        word_range,
    ) -> Hover | None:
        """Get hover for a module member (field or function)."""
        module_def = self.module_loader.get_module(module_name)
        if not module_def:
            return None

        # Check functions
        if member_name in module_def.functions:
            func_def = module_def.functions[member_name]
            params = ", ".join(f"{p[0]}: {p[1]}" for p in func_def.parameters)
            signature = f"{module_name}.{member_name}({params}) -> {func_def.return_type}"
            doc = f"**{member_name}** (function)\n\n```yara\n{signature}\n```"

            if func_def.description:
                doc += f"\n\n{func_def.description}"

            return Hover(
                contents=MarkupContent(kind=MarkupKind.Markdown, value=doc),
                range=word_range,
            )

        # Check fields
        if member_name in module_def.fields:
            field_def = module_def.fields[member_name]
            doc = f"**{member_name}** (field)\n\n```yara\n{module_name}.{member_name}: {field_def.type}\n```"

            if field_def.description:
                doc += f"\n\n{field_def.description}"

            return Hover(
                contents=MarkupContent(kind=MarkupKind.Markdown, value=doc),
                range=word_range,
            )

        return None

    def _get_string_identifier_hover(
        self,
        text: str,
        identifier: str,
        word_range,
    ) -> Hover | None:
        """Get hover for a string identifier."""
        try:
            parser = Parser(text)
            ast = parser.parse()

            # Find the string definition
            for rule in ast.rules:
                for string_def in rule.strings:
                    if string_def.identifier == identifier:
                        # Get string value
                        if hasattr(string_def, "value"):
                            value = string_def.value
                            string_type = "text string"
                        elif hasattr(string_def, "regex"):
                            value = string_def.regex
                            string_type = "regex"
                        elif hasattr(string_def, "tokens"):
                            value = "<hex pattern>"
                            string_type = "hex string"
                        else:
                            value = "<unknown>"
                            string_type = "string"

                        # Get modifiers
                        modifiers = []
                        if hasattr(string_def, "modifiers"):
                            modifiers = [m.name for m in string_def.modifiers]

                        doc = f"**{identifier}** ({string_type})\n\n"
                        doc += f"```\n{value}\n```"

                        if modifiers:
                            doc += f"\n\nModifiers: {', '.join(modifiers)}"

                        return Hover(
                            contents=MarkupContent(kind=MarkupKind.Markdown, value=doc),
                            range=word_range,
                        )

        except Exception:
            pass

        # Generic string identifier hover
        return Hover(
            contents=MarkupContent(
                kind=MarkupKind.Markdown,
                value=f"**{identifier}** (string identifier)\n\nString pattern defined in the strings section.",
            ),
            range=word_range,
        )

    def _get_rule_hover(self, text: str, rule_name: str, word_range) -> Hover | None:
        """Get hover for a rule name."""
        try:
            parser = Parser(text)
            ast = parser.parse()

            for rule in ast.rules:
                if rule.name == rule_name:
                    # Build rule documentation
                    doc = f"**{rule_name}** (rule)"

                    if rule.modifiers:
                        doc += f" [{', '.join(rule.modifiers)}]"

                    if rule.tags:
                        tags = [tag.name for tag in rule.tags]
                        doc += f"\n\nTags: {', '.join(tags)}"

                    if rule.meta:
                        doc += "\n\n**Metadata:**\n"
                        for key, value in rule.meta.items():
                            doc += f"- {key}: {value}\n"

                    if rule.strings:
                        doc += f"\n\n**Strings:** {len(rule.strings)} defined"

                    return Hover(
                        contents=MarkupContent(kind=MarkupKind.Markdown, value=doc),
                        range=word_range,
                    )

        except Exception:
            pass

        return None
