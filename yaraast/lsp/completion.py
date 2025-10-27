"""Completion provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import (
    CompletionItem,
    CompletionItemKind,
    CompletionList,
    InsertTextFormat,
    Position,
)

from yaraast.parser.parser import Parser
from yaraast.types.module_loader import ModuleLoader

if TYPE_CHECKING:
    pass


class CompletionProvider:
    """Provides intelligent autocompletion for YARA files."""

    def __init__(self) -> None:
        self.module_loader = ModuleLoader()
        self._init_keywords()
        self._init_builtins()

    def _init_keywords(self) -> None:
        """Initialize YARA keywords."""
        self.keywords = [
            "rule",
            "private",
            "global",
            "meta",
            "strings",
            "condition",
            "import",
            "include",
            "and",
            "or",
            "not",
            "all",
            "any",
            "of",
            "them",
            "for",
            "in",
            "at",
            "filesize",
            "entrypoint",
            "true",
            "false",
            "defined",
        ]

    def _init_builtins(self) -> None:
        """Initialize built-in functions."""
        self.builtin_functions = {
            "uint8": "Read unsigned 8-bit integer at offset",
            "uint16": "Read unsigned 16-bit integer at offset",
            "uint32": "Read unsigned 32-bit integer at offset",
            "uint16le": "Read unsigned 16-bit integer (little-endian) at offset",
            "uint32le": "Read unsigned 32-bit integer (little-endian) at offset",
            "uint16be": "Read unsigned 16-bit integer (big-endian) at offset",
            "uint32be": "Read unsigned 32-bit integer (big-endian) at offset",
            "int8": "Read signed 8-bit integer at offset",
            "int16": "Read signed 16-bit integer at offset",
            "int32": "Read signed 32-bit integer at offset",
            "int16le": "Read signed 16-bit integer (little-endian) at offset",
            "int32le": "Read signed 32-bit integer (little-endian) at offset",
            "int16be": "Read signed 16-bit integer (big-endian) at offset",
            "int32be": "Read signed 32-bit integer (big-endian) at offset",
        }

        self.string_modifiers = {
            "nocase": "Case-insensitive string matching",
            "wide": "Match wide-character (UTF-16) strings",
            "ascii": "Match ASCII strings",
            "xor": "Match XOR-encoded strings",
            "base64": "Match base64-encoded strings",
            "base64wide": "Match base64-encoded wide strings",
            "fullword": "Match complete words only",
        }

    def get_completions(
        self,
        text: str,
        position: Position,
    ) -> CompletionList:
        """
        Get completion items for the given position.

        Args:
            text: The YARA source code
            position: The cursor position

        Returns:
            CompletionList with available completions
        """
        items = []

        # Analyze context
        context = self._analyze_context(text, position)

        if context == "import":
            items.extend(self._get_module_completions())
        elif context == "module_member":
            module_name = self._get_current_module(text, position)
            if module_name:
                items.extend(self._get_module_member_completions(module_name))
        elif context == "string_modifier":
            items.extend(self._get_string_modifier_completions())
        elif context == "condition":
            items.extend(self._get_condition_completions(text))
        elif context == "meta":
            items.extend(self._get_meta_completions())
        else:
            # General completions
            items.extend(self._get_keyword_completions())
            items.extend(self._get_builtin_function_completions())

        return CompletionList(is_incomplete=False, items=items)

    def _analyze_context(self, text: str, position: Position) -> str:
        """Analyze the context at the current position."""
        lines = text.split("\n")
        if position.line >= len(lines):
            return "general"

        current_line = lines[position.line]
        before_cursor = current_line[: position.character]

        # Check for import context
        if "import" in before_cursor and '"' in before_cursor:
            return "import"

        # Check for module member access
        if "." in before_cursor:
            parts = before_cursor.rsplit(".", 1)
            if len(parts) == 2:
                return "module_member"

        # Check for string modifier context
        if "$" in before_cursor and "=" in before_cursor:
            # We're in a string definition
            if any(mod in before_cursor for mod in ["nocase", "wide", "ascii", "xor"]):
                return "string_modifier"
            # After the string value, we can add modifiers
            if '"' in before_cursor or "}}" in before_cursor or "/" in before_cursor:
                return "string_modifier"

        # Check if we're in a condition section
        for i in range(position.line, -1, -1):
            if i < len(lines):
                line = lines[i].strip()
                if line.startswith("condition:"):
                    return "condition"
                if line.startswith("meta:"):
                    return "meta"
                if line.startswith("strings:"):
                    return "strings"
                if line.startswith("rule "):
                    break

        return "general"

    def _get_current_module(self, text: str, position: Position) -> str | None:
        """Get the module name before the current position."""
        lines = text.split("\n")
        if position.line >= len(lines):
            return None

        current_line = lines[position.line]
        before_cursor = current_line[: position.character]

        # Find the last dot and extract module name
        if "." in before_cursor:
            parts = before_cursor.rsplit(".", 1)
            if len(parts) == 2:
                # Extract module name (might be preceded by other tokens)
                tokens = parts[0].split()
                if tokens:
                    module_name = tokens[-1]
                    # Remove any operators or special chars
                    module_name = "".join(c for c in module_name if c.isalnum() or c == "_")
                    return module_name

        return None

    def _get_keyword_completions(self) -> list[CompletionItem]:
        """Get keyword completions."""
        items = []
        for keyword in self.keywords:
            items.append(
                CompletionItem(
                    label=keyword,
                    kind=CompletionItemKind.Keyword,
                    detail="YARA keyword",
                    insert_text=keyword,
                )
            )
        return items

    def _get_builtin_function_completions(self) -> list[CompletionItem]:
        """Get built-in function completions."""
        items = []
        for func_name, description in self.builtin_functions.items():
            items.append(
                CompletionItem(
                    label=func_name,
                    kind=CompletionItemKind.Function,
                    detail="Built-in function",
                    documentation=description,
                    insert_text=f"{func_name}($0)",
                    insert_text_format=InsertTextFormat.Snippet,
                )
            )
        return items

    def _get_module_completions(self) -> list[CompletionItem]:
        """Get available YARA modules."""
        modules = [
            ("pe", "PE file format module"),
            ("elf", "ELF file format module"),
            ("math", "Mathematical operations"),
            ("hash", "Hash calculation functions"),
            ("dotnet", ".NET module"),
            ("time", "Time-related functions"),
            ("magic", "File type identification"),
            ("console", "Console output for debugging"),
            ("cuckoo", "Cuckoo sandbox integration"),
            ("string", "String manipulation functions"),
        ]

        items = []
        for module_name, description in modules:
            items.append(
                CompletionItem(
                    label=module_name,
                    kind=CompletionItemKind.Module,
                    detail="YARA module",
                    documentation=description,
                    insert_text=module_name,
                )
            )
        return items

    def _get_module_member_completions(self, module_name: str) -> list[CompletionItem]:
        """Get completions for module members."""
        items = []

        # Load module definition
        module_def = self.module_loader.get_module(module_name)
        if not module_def:
            return items

        # Add functions
        for func_name, func_def in module_def.functions.items():
            params = ", ".join(p[0] for p in func_def.parameters)
            items.append(
                CompletionItem(
                    label=func_name,
                    kind=CompletionItemKind.Function,
                    detail=f"{module_name}.{func_name}({params})",
                    documentation=func_def.description,
                    insert_text=f"{func_name}($0)",
                    insert_text_format=InsertTextFormat.Snippet,
                )
            )

        # Add fields
        for field_name, field_def in module_def.fields.items():
            items.append(
                CompletionItem(
                    label=field_name,
                    kind=CompletionItemKind.Field,
                    detail=f"{module_name}.{field_name}: {field_def.type}",
                    documentation=field_def.description,
                    insert_text=field_name,
                )
            )

        return items

    def _get_string_modifier_completions(self) -> list[CompletionItem]:
        """Get string modifier completions."""
        items = []
        for modifier, description in self.string_modifiers.items():
            items.append(
                CompletionItem(
                    label=modifier,
                    kind=CompletionItemKind.Property,
                    detail="String modifier",
                    documentation=description,
                    insert_text=modifier,
                )
            )
        return items

    def _get_condition_completions(self, text: str) -> list[CompletionItem]:
        """Get completions relevant to condition context."""
        items = []

        # Parse the file to extract string identifiers
        try:
            parser = Parser(text)
            ast = parser.parse()

            # Get string identifiers from current rule
            for rule in ast.rules:
                for string_def in rule.strings:
                    identifier = string_def.identifier
                    items.append(
                        CompletionItem(
                            label=identifier,
                            kind=CompletionItemKind.Variable,
                            detail="String identifier",
                            insert_text=identifier,
                        )
                    )

                    # Also add count (#), offset (@), and length (!) variants
                    if identifier.startswith("$"):
                        base_name = identifier[1:]
                        items.extend(
                            [
                                CompletionItem(
                                    label=f"#{base_name}",
                                    kind=CompletionItemKind.Variable,
                                    detail="String count",
                                    insert_text=f"#{base_name}",
                                ),
                                CompletionItem(
                                    label=f"@{base_name}",
                                    kind=CompletionItemKind.Variable,
                                    detail="String offset",
                                    insert_text=f"@{base_name}",
                                ),
                                CompletionItem(
                                    label=f"!{base_name}",
                                    kind=CompletionItemKind.Variable,
                                    detail="String length",
                                    insert_text=f"!{base_name}",
                                ),
                            ]
                        )

        except Exception:
            # If parsing fails, just return keyword completions
            pass

        # Add condition-specific keywords
        items.extend(self._get_keyword_completions())

        return items

    def _get_meta_completions(self) -> list[CompletionItem]:
        """Get completions for meta section."""
        common_meta_keys = [
            ("author", "Rule author name"),
            ("description", "Rule description"),
            ("date", "Rule creation date"),
            ("version", "Rule version"),
            ("reference", "External reference or link"),
            ("hash", "Sample hash"),
            ("sample", "Sample filename"),
            ("tlp", "Traffic Light Protocol classification"),
        ]

        items = []
        for key, description in common_meta_keys:
            items.append(
                CompletionItem(
                    label=key,
                    kind=CompletionItemKind.Property,
                    detail="Meta field",
                    documentation=description,
                    insert_text=f'{key} = "$0"',
                    insert_text_format=InsertTextFormat.Snippet,
                )
            )

        return items
