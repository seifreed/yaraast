"""Code generator for converting AST back to YARA rules."""

from io import StringIO
from typing import Any, List

from yaraast.ast.base import *
from yaraast.ast.conditions import *
from yaraast.ast.expressions import *
from yaraast.ast.meta import *
from yaraast.ast.modules import *
from yaraast.ast.operators import *
from yaraast.ast.rules import *
from yaraast.ast.strings import *
from yaraast.visitor import ASTVisitor


class CodeGenerator(ASTVisitor[str]):
    """Generate YARA code from AST nodes."""

    def __init__(self, indent_size: int = 4):
        self.indent_size = indent_size
        self.indent_level = 0
        self.buffer = StringIO()

    def generate(self, node: ASTNode) -> str:
        """Generate code for the given AST node."""
        self.buffer = StringIO()
        self.visit(node)
        return self.buffer.getvalue()

    def _write(self, text: str) -> None:
        """Write text to buffer."""
        self.buffer.write(text)

    def _writeline(self, text: str = "") -> None:
        """Write line with proper indentation."""
        if text:
            self.buffer.write(" " * (self.indent_level * self.indent_size))
            self.buffer.write(text)
        self.buffer.write("\n")

    def _indent(self) -> None:
        """Increase indentation level."""
        self.indent_level += 1

    def _dedent(self) -> None:
        """Decrease indentation level."""
        self.indent_level = max(0, self.indent_level - 1)

    # Visit methods
    def visit_yara_file(self, node: YaraFile) -> str:
        """Generate code for YaraFile."""
        # Imports
        for imp in node.imports:
            self.visit(imp)
            self._writeline()

        if node.imports:
            self._writeline()

        # Includes
        for inc in node.includes:
            self.visit(inc)
            self._writeline()

        if node.includes:
            self._writeline()

        # Rules
        for i, rule in enumerate(node.rules):
            if i > 0:
                self._writeline()
            self.visit(rule)

        return self.buffer.getvalue()

    def visit_import(self, node: Import) -> str:
        """Generate code for Import."""
        self._write(f'import "{node.module}"')
        if node.alias:
            self._write(f' as {node.alias}')
        return ""

    def visit_include(self, node: Include) -> str:
        """Generate code for Include."""
        self._write(f'include "{node.path}"')
        return ""

    def visit_rule(self, node: Rule) -> str:
        """Generate code for Rule."""
        # Rule header
        modifiers = " ".join(node.modifiers)
        if modifiers:
            self._write(f"{modifiers} ")

        self._write(f"rule {node.name}")

        # Tags
        if node.tags:
            self._write(" : ")
            self._write(" ".join(tag.name for tag in node.tags))

        self._writeline(" {")
        self._indent()

        # Meta section
        if node.meta:
            self._writeline("meta:")
            self._indent()
            for key, value in node.meta.items():
                if isinstance(value, str):
                    self._writeline(f'{key} = "{value}"')
                elif isinstance(value, bool):
                    self._writeline(f'{key} = {"true" if value else "false"}')
                else:
                    self._writeline(f'{key} = {value}')
            self._dedent()
            self._writeline()

        # Strings section
        if node.strings:
            self._writeline("strings:")
            self._indent()
            for string in node.strings:
                self.visit(string)
                self._writeline()
            self._dedent()
            if node.condition:
                self._writeline()

        # Condition section
        if node.condition:
            self._writeline("condition:")
            self._indent()
            condition_code = self.visit(node.condition)
            self._writeline(condition_code)
            self._dedent()

        self._dedent()
        self._writeline("}")
        return ""

    def visit_tag(self, node: Tag) -> str:
        """Generate code for Tag."""
        return node.name

    def visit_string_definition(self, node: StringDefinition) -> str:
        """Generate code for StringDefinition."""
        return ""  # Should not be called directly

    def visit_plain_string(self, node: PlainString) -> str:
        """Generate code for PlainString."""
        self._write(f'{node.identifier} = "{node.value}"')

        # Add modifiers
        for mod in node.modifiers:
            self._write(f" {self.visit(mod)}")

        return ""

    def visit_hex_string(self, node: HexString) -> str:
        """Generate code for HexString."""
        self._write(f"{node.identifier} = {{ ")

        # Generate hex tokens
        for token in node.tokens:
            self._write(self.visit(token))
            self._write(" ")

        self._write("}")

        # Add modifiers
        for mod in node.modifiers:
            self._write(f" {self.visit(mod)}")

        return ""

    def visit_regex_string(self, node: RegexString) -> str:
        """Generate code for RegexString."""
        self._write(f"{node.identifier} = /{node.regex}/")

        # Add modifiers
        for mod in node.modifiers:
            self._write(f" {self.visit(mod)}")

        return ""

    def visit_string_modifier(self, node: StringModifier) -> str:
        """Generate code for StringModifier."""
        if node.value is not None:
            if isinstance(node.value, tuple):
                return f"{node.name}({node.value[0]}-{node.value[1]})"
            else:
                return f"{node.name}({node.value})"
        return node.name

    def visit_hex_token(self, node: HexToken) -> str:
        """Generate code for HexToken."""
        return ""  # Should not be called directly

    def visit_hex_byte(self, node: HexByte) -> str:
        """Generate code for HexByte."""
        # Handle both string and int values
        if isinstance(node.value, str):
            return node.value.upper()
        else:
            return f"{node.value:02X}"

    def visit_hex_wildcard(self, node: HexWildcard) -> str:
        """Generate code for HexWildcard."""
        return "??"

    def visit_hex_jump(self, node: HexJump) -> str:
        """Generate code for HexJump."""
        if node.min_jump is None and node.max_jump is None:
            return "[-]"
        elif node.min_jump == node.max_jump:
            return f"[{node.min_jump}]"
        elif node.min_jump is None:
            return f"[-{node.max_jump}]"
        elif node.max_jump is None:
            return f"[{node.min_jump}-]"
        else:
            return f"[{node.min_jump}-{node.max_jump}]"

    def visit_hex_alternative(self, node: HexAlternative) -> str:
        """Generate code for HexAlternative."""
        alts = []
        for alt in node.alternatives:
            alt_str = " ".join(self.visit(token) for token in alt)
            alts.append(alt_str)
        return f"( {' | '.join(alts)} )"

    def visit_hex_nibble(self, node) -> str:
        """Generate code for HexNibble."""
        if node.high:
            # X? pattern
            return f"{node.value:X}?"
        else:
            # ?X pattern
            return f"?{node.value:X}"

    def visit_expression(self, node: Expression) -> str:
        """Generate code for Expression."""
        return ""  # Should not be called directly

    def visit_identifier(self, node: Identifier) -> str:
        """Generate code for Identifier."""
        return node.name

    def visit_string_identifier(self, node: StringIdentifier) -> str:
        """Generate code for StringIdentifier."""
        return node.name

    def visit_string_count(self, node: StringCount) -> str:
        """Generate code for StringCount."""
        return f"#{node.string_id}"

    def visit_string_offset(self, node: StringOffset) -> str:
        """Generate code for StringOffset."""
        if node.index:
            return f"@{node.string_id}[{self.visit(node.index)}]"
        return f"@{node.string_id}"

    def visit_string_length(self, node: StringLength) -> str:
        """Generate code for StringLength."""
        if node.index:
            return f"!{node.string_id}[{self.visit(node.index)}]"
        return f"!{node.string_id}"

    def visit_integer_literal(self, node: IntegerLiteral) -> str:
        """Generate code for IntegerLiteral."""
        # Common hex values in YARA
        hex_values = {
            0x4D5A: "0x4D5A",  # MZ header
            0x5A4D: "0x5A4D",  # MZ reversed
            0x00004550: "0x00004550",  # PE header
            0x50450000: "0x50450000",  # PE header big-endian
            0x14C: "0x14c",  # PE machine type
            0x3C: "0x3c",  # PE offset location
            60: "0x3c",  # PE offset location (decimal)
            332: "0x14c",  # PE machine type (decimal)
            1024: "0x400",  # 1KB
        }

        if node.value in hex_values:
            return hex_values[node.value]

        # For other large values, use hex if it looks cleaner
        if node.value >= 256:
            # Check if it's a round hex number
            if node.value == 1024:
                return "1024"  # Keep 1024 as decimal for readability
            elif node.value % 256 == 0 or node.value % 16 == 0:
                return hex(node.value)

        return str(node.value)

    def visit_double_literal(self, node: DoubleLiteral) -> str:
        """Generate code for DoubleLiteral."""
        return str(node.value)

    def visit_string_literal(self, node: StringLiteral) -> str:
        """Generate code for StringLiteral."""
        return f'"{node.value}"'

    def visit_regex_literal(self, node: RegexLiteral) -> str:
        """Generate code for RegexLiteral."""
        return f'/{node.pattern}/{node.modifiers}'

    def visit_boolean_literal(self, node: BooleanLiteral) -> str:
        """Generate code for BooleanLiteral."""
        return "true" if node.value else "false"

    def visit_binary_expression(self, node: BinaryExpression) -> str:
        """Generate code for BinaryExpression."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        return f"{left} {node.operator} {right}"

    def visit_unary_expression(self, node: UnaryExpression) -> str:
        """Generate code for UnaryExpression."""
        operand = self.visit(node.operand)
        if node.operator == "not":
            return f"not {operand}"
        return f"{node.operator}{operand}"

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> str:
        """Generate code for ParenthesesExpression."""
        expr = self.visit(node.expression)
        return f"({expr})"

    def visit_set_expression(self, node: SetExpression) -> str:
        """Generate code for SetExpression."""
        elements = [self.visit(elem) for elem in node.elements]
        return f"({', '.join(elements)})"

    def visit_range_expression(self, node: RangeExpression) -> str:
        """Generate code for RangeExpression."""
        low = self.visit(node.low)
        high = self.visit(node.high)
        return f"({low}..{high})"

    def visit_function_call(self, node: FunctionCall) -> str:
        """Generate code for FunctionCall."""
        args = [self.visit(arg) for arg in node.arguments]
        return f"{node.function}({', '.join(args)})"

    def visit_array_access(self, node: ArrayAccess) -> str:
        """Generate code for ArrayAccess."""
        array = self.visit(node.array)
        index = self.visit(node.index)
        return f"{array}[{index}]"

    def visit_member_access(self, node: MemberAccess) -> str:
        """Generate code for MemberAccess."""
        obj = self.visit(node.object)
        return f"{obj}.{node.member}"

    def visit_condition(self, node: Condition) -> str:
        """Generate code for Condition."""
        return ""  # Should not be called directly

    def visit_for_expression(self, node: ForExpression) -> str:
        """Generate code for ForExpression."""
        iterable = self.visit(node.iterable)
        body = self.visit(node.body)
        return f"for {node.quantifier} {node.variable} in {iterable} : ({body})"

    def visit_for_of_expression(self, node: ForOfExpression) -> str:
        """Generate code for ForOfExpression."""
        string_set = self.visit(node.string_set)
        if node.condition:
            condition = self.visit(node.condition)
            return f"for {node.quantifier} of {string_set} : ({condition})"
        return f"{node.quantifier} of {string_set}"

    def visit_at_expression(self, node: AtExpression) -> str:
        """Generate code for AtExpression."""
        offset = self.visit(node.offset)
        return f"{node.string_id} at {offset}"

    def visit_in_expression(self, node: InExpression) -> str:
        """Generate code for InExpression."""
        range_expr = self.visit(node.range)
        return f"{node.string_id} in {range_expr}"

    def visit_of_expression(self, node: OfExpression) -> str:
        """Generate code for OfExpression."""
        quantifier = self.visit(node.quantifier)
        string_set = self.visit(node.string_set)
        return f"{quantifier} of {string_set}"

    def visit_meta(self, node: Meta) -> str:
        """Generate code for Meta."""
        if isinstance(node.value, str):
            return f'{node.key} = "{node.value}"'
        elif isinstance(node.value, bool):
            return f'{node.key} = {"true" if node.value else "false"}'
        else:
            return f'{node.key} = {node.value}'

    def visit_module_reference(self, node) -> str:
        """Generate code for ModuleReference."""
        return node.module

    def visit_dictionary_access(self, node) -> str:
        """Generate code for DictionaryAccess."""
        obj = self.visit(node.object)
        if isinstance(node.key, str):
            return f'{obj}["{node.key}"]'
        else:
            key = self.visit(node.key)
            return f'{obj}[{key}]'

    def visit_defined_expression(self, node: DefinedExpression) -> str:
        """Generate code for DefinedExpression."""
        expr = self.visit(node.expression)
        return f"defined {expr}"

    def visit_string_operator_expression(self, node: StringOperatorExpression) -> str:
        """Generate code for StringOperatorExpression."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        return f"{left} {node.operator} {right}"

    def visit_comment(self, node) -> str:
        """Generate code for Comment."""
        return f"// {node.text}"

    def visit_comment_group(self, node) -> str:
        """Generate code for CommentGroup."""
        return "\n".join(f"// {line}" for line in node.lines)

    def visit_meta(self, node) -> str:
        """Generate code for Meta."""
        if isinstance(node.value, str):
            return f'{node.key} = "{node.value}"'
        else:
            return f'{node.key} = {node.value}'
