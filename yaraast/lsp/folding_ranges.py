"""Folding ranges provider for YARAAST LSP."""

from __future__ import annotations

from typing import Any

from lsprotocol.types import FoldingRange, FoldingRangeKind

from yaraast.lsp.parsing import parse_for_lsp
from yaraast.lsp.structure import find_rule_end, find_rule_line, find_section_range


class FoldingRangesProvider:
    """Provide folding ranges for YARA code."""

    def get_folding_ranges(self, text: str) -> list[FoldingRange]:
        """Get all folding ranges in the document."""
        try:
            ast = parse_for_lsp(text)

            ranges = []

            # Add folding ranges for imports block
            if ast.imports:
                import_lines = self._get_import_block_lines(text, ast.imports)
                if import_lines:
                    ranges.append(
                        FoldingRange(
                            start_line=import_lines[0],
                            end_line=import_lines[1],
                            kind=FoldingRangeKind.Imports,
                        )
                    )

            # Add folding ranges for each rule
            for rule in ast.rules:
                rule_range = self._get_rule_folding_range(text, rule)
                if rule_range:
                    ranges.append(rule_range)

                # Add nested folding ranges for rule sections
                section_ranges = self._get_section_folding_ranges(text, rule)
                ranges.extend(section_ranges)

            return ranges

        except Exception:
            # Fallback to regex-based folding
            return self._fallback_folding_ranges(text)

    def _get_import_block_lines(self, text: str, imports: list[Any]) -> tuple[int, int] | None:
        """Get the line range for the imports block."""
        if not imports:
            return None

        lines = text.split("\n")

        # Find first import
        first_line = None
        last_line = None

        for line_num, line in enumerate(lines):
            if line.strip().startswith("import"):
                if first_line is None:
                    first_line = line_num
                last_line = line_num

        if first_line is not None and last_line is not None and last_line > first_line:
            return (first_line, last_line)

        return None

    def _get_rule_folding_range(self, text: str, rule: Any) -> FoldingRange | None:
        """Get folding range for entire rule."""
        lines = text.split("\n")

        start_line = find_rule_line(lines, rule.name)
        if start_line is None or start_line < 0:
            return None

        end_line = find_rule_end(lines, start_line)
        if end_line is None or end_line <= start_line or "}" not in lines[end_line]:
            return None

        return FoldingRange(start_line=start_line, end_line=end_line, kind=FoldingRangeKind.Region)

    def _get_section_folding_ranges(self, text: str, rule: Any) -> list[FoldingRange]:
        """Get folding ranges for rule sections (meta, strings, condition)."""
        ranges: list[FoldingRange] = []
        lines = text.split("\n")

        rule_start = find_rule_line(lines, rule.name)
        if rule_start is None or rule_start < 0:
            return ranges
        rule_end = find_rule_end(lines, rule_start)

        # Look for meta: section
        if rule.meta:
            meta_range = self._find_section_range(lines, rule_start, rule_end, "meta")
            if meta_range:
                ranges.append(
                    FoldingRange(
                        start_line=meta_range[0],
                        end_line=meta_range[1],
                        kind=FoldingRangeKind.Region,
                    )
                )

        # Look for strings: section
        if rule.strings:
            strings_range = self._find_section_range(lines, rule_start, rule_end, "strings")
            if strings_range:
                ranges.append(
                    FoldingRange(
                        start_line=strings_range[0],
                        end_line=strings_range[1],
                        kind=FoldingRangeKind.Region,
                    )
                )

        # Look for condition: section
        if rule.condition:
            condition_range = self._find_section_range(lines, rule_start, rule_end, "condition")
            if condition_range:
                ranges.append(
                    FoldingRange(
                        start_line=condition_range[0],
                        end_line=condition_range[1],
                        kind=FoldingRangeKind.Region,
                    )
                )

        return ranges

    def _find_section_range(
        self,
        lines: list[str],
        start_line: int,
        rule_end_or_section_name: int | str,
        section_name: str | None = None,
    ) -> tuple[int, int] | None:
        if section_name is None:
            raw_section_name = str(rule_end_or_section_name).removesuffix(":")
            rule_end = find_rule_end(lines, start_line)
        else:
            raw_section_name = section_name
            rule_end = int(rule_end_or_section_name)
        range_ = find_section_range(lines, raw_section_name, start_line, rule_end)
        if range_ is None or range_.end.line <= range_.start.line:
            return None
        return (range_.start.line, range_.end.line)

    def _fallback_folding_ranges(self, text: str) -> list[FoldingRange]:
        """Fallback regex-based folding when AST parsing fails."""
        ranges = []
        lines = text.split("\n")

        brace_stack = []

        for line_num, line in enumerate(lines):
            line.strip()

            # Track opening braces
            if "{" in line:
                brace_stack.append(line_num)

            # Track closing braces
            if "}" in line and brace_stack:
                start_line = brace_stack.pop()
                if line_num - start_line > 0:  # At least 1 line to fold
                    ranges.append(
                        FoldingRange(
                            start_line=start_line, end_line=line_num, kind=FoldingRangeKind.Region
                        )
                    )

        return ranges
