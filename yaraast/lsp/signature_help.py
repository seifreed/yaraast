"""Signature help provider for YARAAST LSP."""

from __future__ import annotations

from lsprotocol.types import ParameterInformation, Position, SignatureHelp, SignatureInformation

from yaraast.lsp.structure import _starts_regex_literal
from yaraast.lsp.utf16 import utf16_col_to_utf8


def _function_name_before_open_paren(line: str, paren_index: int) -> str | None:
    end = paren_index
    while end > 0 and line[end - 1].isspace():
        end -= 1
    start = end
    while start > 0 and (line[start - 1].isalnum() or line[start - 1] in {"_", "."}):
        start -= 1
    if start == end:
        return None
    return line[start:end]


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
        "section_index(name_or_offset: string | int) -> int",
        "Get the index of a section by name or file offset",
        [("name_or_offset", "Section name or file offset")],
    ),
    "pe.rich_signature.version": (
        "version(toolid: int, version: int = optional) -> int",
        "Count Rich signature entries matching a tool id and optional version",
        [("toolid", "Rich signature tool id"), ("version", "Rich signature version")],
    ),
    "pe.rich_signature.toolid": (
        "toolid(toolid: int, version: int = optional) -> int",
        "Count Rich signature entries matching a tool id and optional version",
        [("toolid", "Rich signature tool id"), ("version", "Rich signature version")],
    ),
    # ELF module
    "elf.type": (
        "type -> int",
        "ELF file type constant",
        [],
    ),
    # Hash module
    "hash.md5": (
        "md5(value: string) -> string | md5(offset: int, length: int) -> string",
        "Calculate MD5 hash of a string or data region",
        [("value_or_offset", "String value or starting offset"), ("length", "Number of bytes")],
    ),
    "hash.sha1": (
        "sha1(value: string) -> string | sha1(offset: int, length: int) -> string",
        "Calculate SHA1 hash of a string or data region",
        [("value_or_offset", "String value or starting offset"), ("length", "Number of bytes")],
    ),
    "hash.sha256": (
        "sha256(value: string) -> string | sha256(offset: int, length: int) -> string",
        "Calculate SHA256 hash of a string or data region",
        [("value_or_offset", "String value or starting offset"), ("length", "Number of bytes")],
    ),
    # Math module
    "math.entropy": (
        "entropy(value: string) -> float | entropy(offset: int, length: int) -> float",
        "Calculate entropy of a string or data region",
        [("value_or_offset", "String value or starting offset"), ("length", "Number of bytes")],
    ),
    "math.mean": (
        "mean(value: string) -> float | mean(offset: int, length: int) -> float",
        "Calculate mean byte value of a string or data region",
        [("value_or_offset", "String value or starting offset"), ("length", "Number of bytes")],
    ),
    "math.deviation": (
        "deviation(value: string, mean: float) -> float | deviation(offset: int, length: int, mean: float) -> float",
        "Calculate standard deviation of byte values",
        [
            ("value_or_offset", "String value or starting offset"),
            ("length_or_mean", "Number of bytes or mean value"),
            ("mean", "Mean value"),
        ],
    ),
    "math.count": (
        "count(byte: int, offset: int, length: int) -> int",
        "Count byte occurrences in a data region",
        [("byte", "Byte value"), ("offset", "Starting offset"), ("length", "Number of bytes")],
    ),
    "math.percentage": (
        "percentage(byte: int, offset: int, length: int) -> float",
        "Calculate byte occurrence ratio in a data region",
        [("byte", "Byte value"), ("offset", "Starting offset"), ("length", "Number of bytes")],
    ),
    "math.mode": (
        "mode(offset: int, length: int) -> int",
        "Find most common byte in a data region",
        [("offset", "Starting offset"), ("length", "Number of bytes")],
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
        if not isinstance(text, str):
            msg = "Signature help text must be a string"
            raise TypeError(msg)
        if not isinstance(position, Position):
            msg = "position must be an LSP Position"
            raise TypeError(msg)

        call_context = self._find_call_context_at_position(text, position)
        if call_context is None:
            return None
        function_name, active_parameter = call_context

        # Get signature for this function
        signature = self.function_signatures.get(function_name)
        if not signature:
            return None

        return SignatureHelp(
            signatures=[signature], active_signature=0, active_parameter=active_parameter
        )

    def _find_call_context_at_position(
        self, text: str, position: Position
    ) -> tuple[str, int] | None:
        """Find the innermost open function call and active parameter at position."""
        lines = text.split("\n")
        if position.line >= len(lines):
            return None

        stack: list[tuple[str, int]] = []
        in_block_comment = False

        for line_number, line in enumerate(lines[: position.line + 1]):
            char_pos = (
                utf16_col_to_utf8(line, position.character)
                if line_number == position.line
                else len(line)
            )
            in_string = False
            in_regex = False
            escaped = False
            index = 0

            while index < char_pos:
                char = line[index]
                nxt = line[index + 1] if index + 1 < len(line) else ""

                if in_block_comment:
                    end = line.find("*/", index)
                    if end < 0 or end >= char_pos:
                        if line_number == position.line:
                            return None
                        break
                    in_block_comment = False
                    index = end + 2
                    continue
                if escaped:
                    escaped = False
                    index += 1
                    continue
                if char == "\\" and (in_string or in_regex):
                    escaped = True
                    index += 1
                    continue
                if in_string:
                    if char == '"':
                        in_string = False
                    index += 1
                    continue
                if in_regex:
                    if char == "/":
                        in_regex = False
                    index += 1
                    continue
                if char == "/" and nxt == "/":
                    if line_number == position.line:
                        return None
                    break
                if char == "/" and nxt == "*":
                    end = line.find("*/", index + 2)
                    if end < 0 or end >= char_pos:
                        if line_number == position.line:
                            return None
                        in_block_comment = True
                        break
                    index = end + 2
                    continue
                if char == '"':
                    in_string = True
                elif char == "/" and _starts_regex_literal(line, index):
                    in_regex = True
                elif char in {";", "{", "}"}:
                    stack = []
                elif char == "(":
                    function_name = _function_name_before_open_paren(line, index)
                    stack.append((function_name or "", 0))
                elif char == ")":
                    if stack:
                        stack.pop()
                elif char == "," and stack:
                    function_name, active_parameter = stack[-1]
                    stack[-1] = (function_name, active_parameter + 1)
                index += 1

        if not stack:
            return None
        function_name, active_parameter = stack[-1]
        if not function_name:
            return None
        return function_name, active_parameter
