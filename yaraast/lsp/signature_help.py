"""Signature help provider for YARAAST LSP."""

from __future__ import annotations

from lsprotocol.types import ParameterInformation, Position, SignatureHelp, SignatureInformation

# Specification data: (label, documentation, [(param_label, param_doc), ...])
_SIGNATURE_SPECS: dict[str, tuple[str, str, list[tuple[str, str]]]] = {
    # PE module
    "pe.imphash": (
        "imphash() -> string",
        "Calculate the import hash of a PE file",
        [],
    ),
    "pe.exports": (
        "exports(function_name: string) -> bool",
        "Check if PE file exports a specific function",
        [("function_name", "Name of the function to check")],
    ),
    "pe.imports": (
        "imports(dll_name: string, function_name: string) -> bool",
        "Check if PE file imports a specific function from a DLL",
        [("dll_name", "Name of the DLL"), ("function_name", "Name of the function")],
    ),
    "pe.section_index": (
        "section_index(name: string) -> int",
        "Get the index of a section by name",
        [("name", "Section name")],
    ),
    # ELF module
    "elf.type": (
        "type -> int",
        "ELF file type constant",
        [],
    ),
    # Hash module
    "hash.md5": (
        "md5(offset: int, length: int) -> string",
        "Calculate MD5 hash of data region",
        [("offset", "Starting offset"), ("length", "Number of bytes")],
    ),
    "hash.sha1": (
        "sha1(offset: int, length: int) -> string",
        "Calculate SHA1 hash of data region",
        [("offset", "Starting offset"), ("length", "Number of bytes")],
    ),
    "hash.sha256": (
        "sha256(offset: int, length: int) -> string",
        "Calculate SHA256 hash of data region",
        [("offset", "Starting offset"), ("length", "Number of bytes")],
    ),
    # Math module
    "math.entropy": (
        "entropy(offset: int, length: int) -> float",
        "Calculate entropy of data region",
        [("offset", "Starting offset"), ("length", "Number of bytes")],
    ),
    "math.mean": (
        "mean(offset: int, length: int) -> float",
        "Calculate mean of byte values in region",
        [("offset", "Starting offset"), ("length", "Number of bytes")],
    ),
    "math.deviation": (
        "deviation(offset: int, length: int, mean: float) -> float",
        "Calculate standard deviation of byte values",
        [("offset", "Starting offset"), ("length", "Number of bytes"), ("mean", "Mean value")],
    ),
    # Built-in functions
    "uint8": (
        "uint8(offset: int) -> int",
        "Read unsigned 8-bit integer at offset",
        [("offset", "File offset")],
    ),
    "uint16": (
        "uint16(offset: int) -> int",
        "Read unsigned 16-bit integer at offset",
        [("offset", "File offset")],
    ),
    "uint32": (
        "uint32(offset: int) -> int",
        "Read unsigned 32-bit integer at offset",
        [("offset", "File offset")],
    ),
    "int8": (
        "int8(offset: int) -> int",
        "Read signed 8-bit integer at offset",
        [("offset", "File offset")],
    ),
    "int16": (
        "int16(offset: int) -> int",
        "Read signed 16-bit integer at offset",
        [("offset", "File offset")],
    ),
    "int32": (
        "int32(offset: int) -> int",
        "Read signed 32-bit integer at offset",
        [("offset", "File offset")],
    ),
    "uint8be": (
        "uint8be(offset: int) -> int",
        "Read unsigned 8-bit integer (big-endian) at offset",
        [("offset", "File offset")],
    ),
    "uint16be": (
        "uint16be(offset: int) -> int",
        "Read unsigned 16-bit integer (big-endian) at offset",
        [("offset", "File offset")],
    ),
    "uint32be": (
        "uint32be(offset: int) -> int",
        "Read unsigned 32-bit integer (big-endian) at offset",
        [("offset", "File offset")],
    ),
    "int8be": (
        "int8be(offset: int) -> int",
        "Read signed 8-bit integer (big-endian) at offset",
        [("offset", "File offset")],
    ),
    "int16be": (
        "int16be(offset: int) -> int",
        "Read signed 16-bit integer (big-endian) at offset",
        [("offset", "File offset")],
    ),
    "int32be": (
        "int32be(offset: int) -> int",
        "Read signed 32-bit integer (big-endian) at offset",
        [("offset", "File offset")],
    ),
}


def _build_signature(spec: tuple[str, str, list[tuple[str, str]]]) -> SignatureInformation:
    """Build a SignatureInformation from a spec tuple."""
    label, doc, params = spec
    return SignatureInformation(
        label=label,
        documentation=doc,
        parameters=[
            ParameterInformation(label=p_label, documentation=p_doc) for p_label, p_doc in params
        ],
    )


class SignatureHelpProvider:
    """Provide signature help for functions."""

    def __init__(self) -> None:
        """Initialize signature help provider."""
        self.function_signatures = {
            name: _build_signature(spec) for name, spec in _SIGNATURE_SPECS.items()
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
        paren_pos: int | None = None
        for i in range(char_pos - 1, -1, -1):
            if line[i] == "(":
                paren_pos = i
                break
            if line[i] in [";", "}", "{"]:
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

        function_name: str = line[func_name_start:func_name_end]
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
