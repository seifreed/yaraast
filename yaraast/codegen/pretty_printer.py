"""Enhanced pretty printer for YARA rules with formatting preservation."""

from __future__ import annotations

from dataclasses import dataclass
from io import StringIO
from typing import TYPE_CHECKING, Any

from yaraast.ast.strings import HexString, PlainString, RegexString, StringDefinition
from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import Expression
    from yaraast.ast.rules import Rule


@dataclass
class PrettyPrintOptions:
    """Options for pretty printing YARA rules."""

    # Indentation
    indent_size: int = 4
    indent_with_tabs: bool = False

    # Spacing
    blank_lines_before_rule: int = 2
    blank_lines_after_imports: int = 2
    blank_lines_after_includes: int = 1
    blank_lines_between_sections: int = 1
    space_around_operators: bool = True
    space_after_comma: bool = True

    # Alignment
    align_string_definitions: bool = True
    align_meta_values: bool = True
    align_comments: bool = True
    min_alignment_column: int = 40

    # Comments
    preserve_comments: bool = True
    comment_column: int = 60
    inline_comment_spacing: int = 2

    # String formatting
    quote_style: str = "double"  # "double", "single", "preserve"
    hex_uppercase: bool = True
    hex_spacing: bool = True

    # Line length and wrapping
    max_line_length: int = 120
    wrap_long_conditions: bool = True
    wrap_long_strings: bool = False

    # Sorting
    sort_imports: bool = True
    sort_includes: bool = True
    sort_meta_keys: bool = False
    sort_tags: bool = True

    # Style preferences
    compact_conditions: bool = False
    verbose_conditions: bool = False
    preserve_original_style: bool = False


class PrettyPrinter(CommentAwareCodeGenerator):
    """Enhanced pretty printer with advanced formatting options."""

    def __init__(self, options: PrettyPrintOptions | None = None) -> None:
        self.options = options or PrettyPrintOptions()
        super().__init__(
            indent_size=self.options.indent_size,
            preserve_comments=self.options.preserve_comments,
        )
        self._string_alignment_column = 0
        self._meta_alignment_column = 0

    def pretty_print(self, ast: YaraFile) -> str:
        """Pretty print the entire YARA file."""
        self.buffer = StringIO()
        self.indent_level = 0

        # Calculate alignment columns if needed
        if self.options.align_string_definitions:
            self._calculate_string_alignment_column(ast)
        if self.options.align_meta_values:
            self._calculate_meta_alignment_column(ast)

        return self.visit_yara_file(ast)

    def visit_yara_file(self, node: YaraFile) -> str:
        """Pretty print YARA file with enhanced formatting."""
        # Imports section
        if node.imports:
            imports = (
                sorted(node.imports, key=lambda x: x.module)
                if self.options.sort_imports
                else node.imports
            )

            for imp in imports:
                self.visit_import(imp)
                self._writeline()

            # Add blank lines after imports
            for _ in range(self.options.blank_lines_after_imports - 1):
                self._writeline()

        # Includes section
        if node.includes:
            includes = (
                sorted(node.includes, key=lambda x: x.path)
                if self.options.sort_includes
                else node.includes
            )

            for inc in includes:
                self.visit_include(inc)
                self._writeline()

            # Add blank lines after includes
            for _ in range(self.options.blank_lines_after_includes):
                self._writeline()

        # Rules section
        for i, rule in enumerate(node.rules):
            if i > 0:
                # Add blank lines between rules
                for _ in range(self.options.blank_lines_before_rule):
                    self._writeline()

            self.visit_rule(rule)
            self._writeline()

        return self.buffer.getvalue()

    def visit_rule(self, node: Rule) -> str:
        """Pretty print rule with enhanced formatting."""
        # Write leading comments
        self._write_comments(node.leading_comments)

        # Rule declaration line
        line_parts = []

        # Modifiers
        if node.modifiers:
            line_parts.extend(node.modifiers)

        # Rule keyword and name
        line_parts.extend(["rule", node.name])

        # Tags
        if node.tags:
            tags = (
                sorted([tag.name for tag in node.tags])
                if self.options.sort_tags
                else [tag.name for tag in node.tags]
            )
            line_parts.append(":")
            line_parts.extend(tags)

        # Write rule declaration
        self._writeline(" ".join(line_parts) + " {")
        self._indent()

        # Meta section
        if node.meta:
            self._writeline("meta:")
            self._indent()
            self._write_meta_section(node.meta)
            self._dedent()

            # Blank line after meta
            if node.strings or node.condition:
                for _ in range(self.options.blank_lines_between_sections):
                    self._writeline()

        # Strings section
        if node.strings:
            self._writeline("strings:")
            self._indent()
            self._write_strings_section(node.strings)
            self._dedent()

            # Blank line after strings
            if node.condition:
                for _ in range(self.options.blank_lines_between_sections):
                    self._writeline()

        # Condition section
        if node.condition:
            self._writeline("condition:")
            self._indent()
            self._write_condition_section(node.condition)
            self._dedent()

        self._dedent()
        self._writeline("}")

        return self.buffer.getvalue()

    def _write_meta_section(self, meta: dict[str, Any] | list[Any]) -> None:
        """Write meta section with alignment."""
        if isinstance(meta, dict):
            items = list(meta.items())
            if self.options.sort_meta_keys:
                items.sort(key=lambda x: x[0])

            for key, value in items:
                self._write_meta_entry(key, value)
        else:
            # Handle list of meta entries
            for entry in meta:
                if hasattr(entry, "key") and hasattr(entry, "value"):
                    self._write_meta_entry(entry.key, entry.value)

    def _write_meta_entry(self, key: str, value: Any) -> None:
        """Write a single meta entry with alignment."""
        if self.options.align_meta_values and self._meta_alignment_column > 0:
            # Calculate padding for alignment
            key_part = f"{key} ="
            padding = max(1, self._meta_alignment_column - len(key_part))
            self._write(key_part + " " * padding)
        else:
            self._write(f"{key} = ")

        # Format value based on type
        if isinstance(value, str):
            quote = '"' if self.options.quote_style == "double" else "'"
            self._write(f"{quote}{value}{quote}")
        elif isinstance(value, bool):
            self._write("true" if value else "false")
        else:
            self._write(str(value))

        self._writeline()

    def _write_strings_section(self, strings: list[StringDefinition]) -> None:
        """Write strings section with alignment."""
        for string_def in strings:
            self._write_string_definition(string_def)

    def _write_string_definition(self, string_def: StringDefinition) -> None:
        """Write string definition with alignment and formatting."""
        if isinstance(string_def, PlainString):
            self._write_plain_string_aligned(string_def)
        elif isinstance(string_def, HexString):
            self._write_hex_string_aligned(string_def)
        elif isinstance(string_def, RegexString):
            self._write_regex_string_aligned(string_def)
        else:
            # Fallback
            self.visit(string_def)
            self._writeline()

    def _write_plain_string_aligned(self, node: PlainString) -> None:
        """Write plain string with alignment."""
        quote = '"' if self.options.quote_style == "double" else "'"
        string_part = f"{node.identifier} = {quote}{node.value}{quote}"

        if self.options.align_string_definitions and self._string_alignment_column > 0:
            padding = max(1, self._string_alignment_column - len(string_part))
            self._write(string_part + " " * padding)
        else:
            self._write(string_part)

        # Modifiers
        if node.modifiers:
            modifier_parts = []
            for modifier in node.modifiers:
                modifier_parts.append(modifier.name)
            self._write(" " + " ".join(modifier_parts))

        self._writeline()

    def _write_hex_string_aligned(self, node: HexString) -> None:
        """Write hex string with alignment and formatting."""
        # Build hex pattern
        hex_parts = []
        for token in node.tokens:
            if hasattr(token, "value"):  # HexByte
                # Handle both string and int values
                if isinstance(token.value, str):
                    hex_val = (
                        token.value.upper() if self.options.hex_uppercase else token.value.lower()
                    )
                else:
                    hex_val = (
                        f"{token.value:02X}" if self.options.hex_uppercase else f"{token.value:02x}"
                    )
                hex_parts.append(hex_val)
            elif hasattr(token, "min_jump"):  # HexJump
                if token.min_jump == token.max_jump:
                    hex_parts.append(f"[{token.min_jump}]")
                else:
                    hex_parts.append(f"[{token.min_jump}-{token.max_jump}]")
            else:  # HexWildcard or others
                hex_parts.append("??")

        hex_pattern = " ".join(hex_parts) if self.options.hex_spacing else "".join(hex_parts)
        string_part = f"{node.identifier} = {{ {hex_pattern} }}"

        if self.options.align_string_definitions and self._string_alignment_column > 0:
            padding = max(1, self._string_alignment_column - len(string_part))
            self._write(string_part + " " * padding)
        else:
            self._write(string_part)

        # Modifiers
        if node.modifiers:
            modifier_parts = []
            for modifier in node.modifiers:
                modifier_parts.append(modifier.name)
            self._write(" " + " ".join(modifier_parts))

        self._writeline()

    def _write_regex_string_aligned(self, node: RegexString) -> None:
        """Write regex string with alignment."""
        string_part = f"{node.identifier} = /{node.regex}/"

        if self.options.align_string_definitions and self._string_alignment_column > 0:
            padding = max(1, self._string_alignment_column - len(string_part))
            self._write(string_part + " " * padding)
        else:
            self._write(string_part)

        # Modifiers
        if node.modifiers:
            modifier_parts = []
            for modifier in node.modifiers:
                modifier_parts.append(modifier.name)
            self._write(" " + " ".join(modifier_parts))

        self._writeline()

    def _write_condition_section(self, condition: Expression) -> None:
        """Write condition section with formatting."""
        if self.options.wrap_long_conditions:
            # For now, simple implementation
            condition_str = self._expression_to_string(condition)
            if len(condition_str) > self.options.max_line_length:
                # Simple line wrapping (could be enhanced)
                self._write_wrapped_condition(condition_str)
            else:
                self._writeline(condition_str)
        else:
            condition_str = self._expression_to_string(condition)
            self._writeline(condition_str)

    def _write_wrapped_condition(self, condition_str: str) -> None:
        """Write condition with line wrapping."""
        # Simple implementation - split on operators

        current_line = ""
        words = condition_str.split()

        for word in words:
            if len(current_line + " " + word) > self.options.max_line_length:
                self._writeline(current_line)
                current_line = "    " + word  # Add extra indent for continuation
            elif current_line:
                current_line += " " + word
            else:
                current_line = word

        if current_line:
            self._writeline(current_line)

    def _expression_to_string(self, expr: Expression) -> str:
        """Convert expression to string (simplified)."""
        # This is a simplified implementation
        # In practice, would use a separate visitor for expression serialization
        from yaraast.codegen import CodeGenerator

        generator = CodeGenerator()
        # Use visit directly instead of generate which expects a full AST
        return generator.visit(expr).strip()

    def _calculate_string_alignment_column(self, ast: YaraFile) -> None:
        """Calculate alignment column for string definitions."""
        max_length = 0

        for rule in ast.rules:
            for string_def in rule.strings:
                if isinstance(string_def, PlainString):
                    length = len(f'{string_def.identifier} = "{string_def.value}"')
                elif isinstance(string_def, HexString):
                    # Estimate hex string length
                    length = (
                        len(f"{string_def.identifier} = {{ ... }}") + len(string_def.tokens) * 3
                    )
                elif isinstance(string_def, RegexString):
                    length = len(f"{string_def.identifier} = /{string_def.regex}/")
                else:
                    length = len(string_def.identifier) + 10  # Estimate

                max_length = max(max_length, length)

        self._string_alignment_column = min(
            max_length + 2,
            self.options.min_alignment_column,
        )

    def _calculate_meta_alignment_column(self, ast: YaraFile) -> None:
        """Calculate alignment column for meta values."""
        max_length = 0

        for rule in ast.rules:
            if isinstance(rule.meta, dict):
                for key in rule.meta:
                    length = len(f"{key} =")
                    max_length = max(max_length, length)

        self._meta_alignment_column = min(
            max_length + 2,
            self.options.min_alignment_column,
        )


class StylePresets:
    """Predefined style presets for different use cases."""

    @staticmethod
    def compact() -> PrettyPrintOptions:
        """Compact style for minimal whitespace."""
        return PrettyPrintOptions(
            blank_lines_before_rule=1,
            blank_lines_after_imports=1,
            blank_lines_after_includes=0,
            blank_lines_between_sections=0,
            align_string_definitions=False,
            align_meta_values=False,
            compact_conditions=True,
            max_line_length=80,
        )

    @staticmethod
    def readable() -> PrettyPrintOptions:
        """Readable style with good spacing and alignment."""
        return PrettyPrintOptions(
            blank_lines_before_rule=2,
            blank_lines_after_imports=2,
            blank_lines_after_includes=1,
            blank_lines_between_sections=1,
            align_string_definitions=True,
            align_meta_values=True,
            align_comments=True,
            max_line_length=120,
        )

    @staticmethod
    def dense() -> PrettyPrintOptions:
        """Dense style for large files."""
        return PrettyPrintOptions(
            blank_lines_before_rule=1,
            blank_lines_after_imports=1,
            blank_lines_after_includes=0,
            blank_lines_between_sections=0,
            align_string_definitions=True,
            align_meta_values=False,
            max_line_length=100,
            compact_conditions=True,
        )

    @staticmethod
    def verbose() -> PrettyPrintOptions:
        """Verbose style with extensive spacing."""
        return PrettyPrintOptions(
            blank_lines_before_rule=3,
            blank_lines_after_imports=3,
            blank_lines_after_includes=2,
            blank_lines_between_sections=2,
            align_string_definitions=True,
            align_meta_values=True,
            align_comments=True,
            verbose_conditions=True,
            max_line_length=140,
        )


# Convenience functions
def pretty_print(ast: YaraFile, options: PrettyPrintOptions | None = None) -> str:
    """Pretty print YARA AST with specified options."""
    printer = PrettyPrinter(options)
    return printer.pretty_print(ast)


def pretty_print_compact(ast: YaraFile) -> str:
    """Pretty print with compact style."""
    return pretty_print(ast, StylePresets.compact())


def pretty_print_readable(ast: YaraFile) -> str:
    """Pretty print with readable style."""
    return pretty_print(ast, StylePresets.readable())


def pretty_print_dense(ast: YaraFile) -> str:
    """Pretty print with dense style."""
    return pretty_print(ast, StylePresets.dense())


def pretty_print_verbose(ast: YaraFile) -> str:
    """Pretty print with verbose style."""
    return pretty_print(ast, StylePresets.verbose())
