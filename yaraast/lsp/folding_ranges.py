"""Folding ranges provider for YARAAST LSP."""

from lsprotocol.types import FoldingRange, FoldingRangeKind

from yaraast.parser.parser import Parser


class FoldingRangesProvider:
    """Provide folding ranges for YARA code."""

    def get_folding_ranges(self, text: str) -> list[FoldingRange]:
        """Get all folding ranges in the document."""
        try:
            parser = Parser(text)
            ast = parser.parse()

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

    def _get_import_block_lines(self, text: str, imports: list) -> tuple[int, int] | None:
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

    def _get_rule_folding_range(self, text: str, rule) -> FoldingRange | None:
        """Get folding range for entire rule."""
        lines = text.split("\n")

        # Find rule declaration line
        start_line = None
        for line_num, line in enumerate(lines):
            if f"rule {rule.name}" in line:
                start_line = line_num
                break

        if start_line is None:
            return None

        # Find closing brace
        end_line = None
        brace_count = 0
        for line_num in range(start_line, len(lines)):
            line = lines[line_num]
            brace_count += line.count("{")
            brace_count -= line.count("}")

            if brace_count == 0 and "}" in line:
                end_line = line_num
                break

        if end_line is None or end_line <= start_line:
            return None

        return FoldingRange(start_line=start_line, end_line=end_line, kind=FoldingRangeKind.Region)

    def _get_section_folding_ranges(self, text: str, rule) -> list[FoldingRange]:
        """Get folding ranges for rule sections (meta, strings, condition)."""
        ranges = []
        lines = text.split("\n")

        # Find rule start
        rule_start = None
        for line_num, line in enumerate(lines):
            if f"rule {rule.name}" in line:
                rule_start = line_num
                break

        if rule_start is None:
            return ranges

        # Look for meta: section
        if rule.meta:
            meta_range = self._find_section_range(lines, rule_start, "meta:")
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
            strings_range = self._find_section_range(lines, rule_start, "strings:")
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
            condition_range = self._find_section_range(lines, rule_start, "condition:")
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
        self, lines: list[str], start_line: int, section_keyword: str
    ) -> tuple[int, int] | None:
        """Find the line range for a rule section."""
        section_start = None

        # Find section start
        for line_num in range(start_line, len(lines)):
            line = lines[line_num].strip()
            if line.startswith(section_keyword):
                section_start = line_num
                break

        if section_start is None:
            return None

        # Find section end (next section keyword or closing brace)
        section_keywords = ["meta:", "strings:", "condition:"]
        section_end = None

        for line_num in range(section_start + 1, len(lines)):
            line = lines[line_num].strip()

            # Check for next section
            if any(line.startswith(kw) for kw in section_keywords):
                section_end = line_num - 1
                break

            # Check for closing brace
            if line == "}":
                section_end = line_num - 1
                break

        if section_end is None or section_end <= section_start:
            return None

        # Ensure we have at least 2 lines to fold
        if section_end - section_start < 1:
            return None

        return (section_start, section_end)

    def _fallback_folding_ranges(self, text: str) -> list[FoldingRange]:
        """Fallback regex-based folding when AST parsing fails."""
        ranges = []
        lines = text.split("\n")

        brace_stack = []

        for line_num, line in enumerate(lines):
            stripped = line.strip()

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
