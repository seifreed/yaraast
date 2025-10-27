"""Document symbols provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import DocumentSymbol, Position, Range, SymbolKind

from yaraast.parser.parser import Parser

if TYPE_CHECKING:
    pass


class SymbolsProvider:
    """Provides document symbols (outline view)."""

    def get_symbols(self, text: str) -> list[DocumentSymbol]:
        """
        Get document symbols for the given YARA file.

        Args:
            text: The YARA source code

        Returns:
            List of document symbols
        """
        symbols = []

        try:
            parser = Parser(text)
            ast = parser.parse()

            lines = text.split("\n")

            # Add imports
            for imp in ast.imports:
                line_num = self._find_line_containing(lines, f'import "{imp.module}"')
                if line_num >= 0:
                    symbols.append(
                        DocumentSymbol(
                            name=f'import "{imp.module}"',
                            kind=SymbolKind.Namespace,
                            range=self._make_range(line_num, 0, line_num, len(lines[line_num])),
                            selection_range=self._make_range(
                                line_num, 0, line_num, len(lines[line_num])
                            ),
                        )
                    )

            # Add rules
            for rule in ast.rules:
                rule_line = self._find_line_containing(lines, f"rule {rule.name}")
                if rule_line < 0:
                    continue

                # Find rule end (closing brace)
                rule_end = self._find_closing_brace(lines, rule_line)

                rule_symbol = DocumentSymbol(
                    name=rule.name,
                    kind=SymbolKind.Class,
                    range=self._make_range(
                        rule_line, 0, rule_end, len(lines[rule_end]) if rule_end < len(lines) else 0
                    ),
                    selection_range=self._make_range(
                        rule_line,
                        lines[rule_line].index(rule.name),
                        rule_line,
                        lines[rule_line].index(rule.name) + len(rule.name),
                    ),
                    children=[],
                )

                # Add meta section
                if rule.meta:
                    meta_line = self._find_line_containing(lines, "meta:", rule_line)
                    if meta_line >= 0:
                        meta_children = []
                        for key, value in rule.meta.items():
                            key_line = self._find_line_containing(lines, f"{key} =", meta_line)
                            if key_line >= 0:
                                meta_children.append(
                                    DocumentSymbol(
                                        name=f"{key} = {value}",
                                        kind=SymbolKind.Property,
                                        range=self._make_range(
                                            key_line, 0, key_line, len(lines[key_line])
                                        ),
                                        selection_range=self._make_range(
                                            key_line, 0, key_line, len(lines[key_line])
                                        ),
                                    )
                                )

                        if meta_children:
                            rule_symbol.children.append(
                                DocumentSymbol(
                                    name="meta",
                                    kind=SymbolKind.Namespace,
                                    range=self._make_range(
                                        meta_line, 0, meta_line, len(lines[meta_line])
                                    ),
                                    selection_range=self._make_range(
                                        meta_line, 0, meta_line, len(lines[meta_line])
                                    ),
                                    children=meta_children,
                                )
                            )

                # Add strings section
                if rule.strings:
                    strings_line = self._find_line_containing(lines, "strings:", rule_line)
                    if strings_line >= 0:
                        string_children = []
                        for string_def in rule.strings:
                            string_line = self._find_line_containing(
                                lines,
                                string_def.identifier,
                                strings_line,
                            )
                            if string_line >= 0:
                                string_children.append(
                                    DocumentSymbol(
                                        name=string_def.identifier,
                                        kind=SymbolKind.String,
                                        range=self._make_range(
                                            string_line, 0, string_line, len(lines[string_line])
                                        ),
                                        selection_range=self._make_range(
                                            string_line,
                                            0,
                                            string_line,
                                            len(lines[string_line]),
                                        ),
                                    )
                                )

                        if string_children:
                            rule_symbol.children.append(
                                DocumentSymbol(
                                    name="strings",
                                    kind=SymbolKind.Namespace,
                                    range=self._make_range(
                                        strings_line, 0, strings_line, len(lines[strings_line])
                                    ),
                                    selection_range=self._make_range(
                                        strings_line,
                                        0,
                                        strings_line,
                                        len(lines[strings_line]),
                                    ),
                                    children=string_children,
                                )
                            )

                # Add condition section
                if rule.condition:
                    condition_line = self._find_line_containing(lines, "condition:", rule_line)
                    if condition_line >= 0:
                        rule_symbol.children.append(
                            DocumentSymbol(
                                name="condition",
                                kind=SymbolKind.Function,
                                range=self._make_range(
                                    condition_line, 0, condition_line, len(lines[condition_line])
                                ),
                                selection_range=self._make_range(
                                    condition_line,
                                    0,
                                    condition_line,
                                    len(lines[condition_line]),
                                ),
                            )
                        )

                symbols.append(rule_symbol)

        except Exception:
            # If parsing fails, return empty symbols
            pass

        return symbols

    def _find_line_containing(
        self,
        lines: list[str],
        text: str,
        start: int = 0,
    ) -> int:
        """Find the line number containing the given text."""
        for i in range(start, len(lines)):
            if text in lines[i]:
                return i
        return -1

    def _find_closing_brace(self, lines: list[str], start: int) -> int:
        """Find the closing brace for a rule."""
        depth = 0
        for i in range(start, len(lines)):
            depth += lines[i].count("{")
            depth -= lines[i].count("}")
            if depth == 0 and "}" in lines[i]:
                return i
        return len(lines) - 1

    def _make_range(self, start_line: int, start_char: int, end_line: int, end_char: int) -> Range:
        """Create an LSP Range."""
        return Range(
            start=Position(line=start_line, character=start_char),
            end=Position(line=end_line, character=end_char),
        )
