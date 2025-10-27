"""Signature help provider for YARAAST LSP."""

from lsprotocol.types import ParameterInformation, Position, SignatureHelp, SignatureInformation

from yaraast.lsp.utils import get_word_at_position


class SignatureHelpProvider:
    """Provide signature help for functions."""

    def __init__(self):
        """Initialize signature help provider."""
        # YARA module functions with signatures
        self.function_signatures = {
            # PE module
            "pe.imphash": SignatureInformation(
                label="imphash() -> string",
                documentation="Calculate the import hash of a PE file",
                parameters=[],
            ),
            "pe.exports": SignatureInformation(
                label="exports(function_name: string) -> bool",
                documentation="Check if PE file exports a specific function",
                parameters=[
                    ParameterInformation(
                        label="function_name",
                        documentation="Name of the function to check",
                    )
                ],
            ),
            "pe.imports": SignatureInformation(
                label="imports(dll_name: string, function_name: string) -> bool",
                documentation="Check if PE file imports a specific function from a DLL",
                parameters=[
                    ParameterInformation(label="dll_name", documentation="Name of the DLL"),
                    ParameterInformation(
                        label="function_name", documentation="Name of the function"
                    ),
                ],
            ),
            "pe.section_index": SignatureInformation(
                label="section_index(name: string) -> int",
                documentation="Get the index of a section by name",
                parameters=[ParameterInformation(label="name", documentation="Section name")],
            ),
            # ELF module
            "elf.type": SignatureInformation(
                label="type -> int",
                documentation="ELF file type constant",
                parameters=[],
            ),
            # Hash module
            "hash.md5": SignatureInformation(
                label="md5(offset: int, length: int) -> string",
                documentation="Calculate MD5 hash of data region",
                parameters=[
                    ParameterInformation(label="offset", documentation="Starting offset"),
                    ParameterInformation(label="length", documentation="Number of bytes"),
                ],
            ),
            "hash.sha1": SignatureInformation(
                label="sha1(offset: int, length: int) -> string",
                documentation="Calculate SHA1 hash of data region",
                parameters=[
                    ParameterInformation(label="offset", documentation="Starting offset"),
                    ParameterInformation(label="length", documentation="Number of bytes"),
                ],
            ),
            "hash.sha256": SignatureInformation(
                label="sha256(offset: int, length: int) -> string",
                documentation="Calculate SHA256 hash of data region",
                parameters=[
                    ParameterInformation(label="offset", documentation="Starting offset"),
                    ParameterInformation(label="length", documentation="Number of bytes"),
                ],
            ),
            # Math module
            "math.entropy": SignatureInformation(
                label="entropy(offset: int, length: int) -> float",
                documentation="Calculate entropy of data region",
                parameters=[
                    ParameterInformation(label="offset", documentation="Starting offset"),
                    ParameterInformation(label="length", documentation="Number of bytes"),
                ],
            ),
            "math.mean": SignatureInformation(
                label="mean(offset: int, length: int) -> float",
                documentation="Calculate mean of byte values in region",
                parameters=[
                    ParameterInformation(label="offset", documentation="Starting offset"),
                    ParameterInformation(label="length", documentation="Number of bytes"),
                ],
            ),
            "math.deviation": SignatureInformation(
                label="deviation(offset: int, length: int, mean: float) -> float",
                documentation="Calculate standard deviation of byte values",
                parameters=[
                    ParameterInformation(label="offset", documentation="Starting offset"),
                    ParameterInformation(label="length", documentation="Number of bytes"),
                    ParameterInformation(label="mean", documentation="Mean value"),
                ],
            ),
            # Built-in functions
            "uint8": SignatureInformation(
                label="uint8(offset: int) -> int",
                documentation="Read unsigned 8-bit integer at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "uint16": SignatureInformation(
                label="uint16(offset: int) -> int",
                documentation="Read unsigned 16-bit integer at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "uint32": SignatureInformation(
                label="uint32(offset: int) -> int",
                documentation="Read unsigned 32-bit integer at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "int8": SignatureInformation(
                label="int8(offset: int) -> int",
                documentation="Read signed 8-bit integer at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "int16": SignatureInformation(
                label="int16(offset: int) -> int",
                documentation="Read signed 16-bit integer at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "int32": SignatureInformation(
                label="int32(offset: int) -> int",
                documentation="Read signed 32-bit integer at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "uint8be": SignatureInformation(
                label="uint8be(offset: int) -> int",
                documentation="Read unsigned 8-bit integer (big-endian) at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "uint16be": SignatureInformation(
                label="uint16be(offset: int) -> int",
                documentation="Read unsigned 16-bit integer (big-endian) at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "uint32be": SignatureInformation(
                label="uint32be(offset: int) -> int",
                documentation="Read unsigned 32-bit integer (big-endian) at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "int8be": SignatureInformation(
                label="int8be(offset: int) -> int",
                documentation="Read signed 8-bit integer (big-endian) at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "int16be": SignatureInformation(
                label="int16be(offset: int) -> int",
                documentation="Read signed 16-bit integer (big-endian) at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
            "int32be": SignatureInformation(
                label="int32be(offset: int) -> int",
                documentation="Read signed 32-bit integer (big-endian) at offset",
                parameters=[ParameterInformation(label="offset", documentation="File offset")],
            ),
        }

    def get_signature_help(self, text: str, position: Position) -> SignatureHelp | None:
        """Get signature help at position."""
        # Find the function call we're inside
        function_name = self._find_function_at_position(text, position)
        if not function_name:
            return None

        # Get signature for this function
        signature = self.function_signatures.get(function_name)
        if not signature:
            return None

        # Calculate which parameter we're on
        active_parameter = self._calculate_active_parameter(text, position)

        return SignatureHelp(
            signatures=[signature], active_signature=0, active_parameter=active_parameter
        )

    def _find_function_at_position(self, text: str, position: Position) -> str | None:
        """Find the function call at the cursor position."""
        lines = text.split("\n")
        if position.line >= len(lines):
            return None

        line = lines[position.line]
        char_pos = position.character

        # Look backwards for opening parenthesis
        paren_pos = None
        for i in range(char_pos - 1, -1, -1):
            if line[i] == "(":
                paren_pos = i
                break
            elif line[i] in [";", "}", "{"]:
                # Hit a statement boundary
                return None

        if paren_pos is None:
            return None

        # Extract function name before parenthesis
        func_name_end = paren_pos
        func_name_start = func_name_end
        for i in range(func_name_end - 1, -1, -1):
            if line[i].isalnum() or line[i] in ["_", "."]:
                func_name_start = i
            else:
                break

        if func_name_start == func_name_end:
            return None

        function_name = line[func_name_start:func_name_end]
        return function_name

    def _calculate_active_parameter(self, text: str, position: Position) -> int:
        """Calculate which parameter the cursor is on."""
        lines = text.split("\n")
        if position.line >= len(lines):
            return 0

        line = lines[position.line]
        char_pos = position.character

        # Count commas before cursor position (within current parentheses level)
        paren_depth = 0
        comma_count = 0

        for i in range(char_pos):
            if i >= len(line):
                break

            if line[i] == "(":
                paren_depth += 1
            elif line[i] == ")":
                paren_depth -= 1
            elif line[i] == "," and paren_depth == 1:
                comma_count += 1

        return comma_count
