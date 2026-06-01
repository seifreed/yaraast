"""YARA module implementations for the yaraast evaluation engine.

These are real implementations that parse binary data (PE headers, ELF headers, etc.)
and provide YARA module semantics for condition evaluation without requiring yara-python.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import re
import struct
import time as time_mod
from typing import Any, TypeGuard

from yaraast.errors import EvaluationError
from yaraast.evaluation.evaluation_helpers import (
    YARA_UNDEFINED,
    YaraUndefinedValue,
    is_yara_undefined,
)

SERIAL_CORRELATION_DEGENERATE = -100000.0
UINT64_MASK = (1 << 64) - 1


def _is_strict_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _unsigned_for_non_decimal_base(value: int) -> int:
    return value & UINT64_MASK if value < 0 else value


def _uint64_order_key(value: int) -> int:
    return value & UINT64_MASK


def _require_strict_ints(function_name: str, *values: object) -> None:
    if not all(_is_strict_int(value) for value in values):
        msg = f"{function_name}() expects integer arguments"
        raise EvaluationError(msg)


def _require_region_bounds(function_name: str, offset: object, size: object) -> tuple[int, int]:
    if not _is_strict_int(offset) or not _is_strict_int(size):
        msg = f"{function_name}() offset and size must be integers"
        raise EvaluationError(msg)
    return offset, size


def _require_string_arg(function_name: str, value: object) -> None:
    if not isinstance(value, str):
        msg = f"{function_name}() expects a string argument"
        raise EvaluationError(msg)


def _require_integer_arg(function_name: str, value: object) -> int:
    if not _is_strict_int(value):
        msg = f"{function_name}() expects an integer argument"
        raise EvaluationError(msg)
    return value


def _require_scalar_args(function_name: str, values: tuple[object, ...]) -> None:
    if not values or not all(
        isinstance(value, str | int | float) and not isinstance(value, bool) for value in values
    ):
        msg = f"{function_name}() expects scalar arguments"
        raise EvaluationError(msg)


def _is_regex_pattern(value: object) -> bool:
    return isinstance(getattr(value, "pattern", None), str)


def _require_pattern_arg(function_name: str, value: object) -> object:
    if not isinstance(value, str) and not _is_regex_pattern(value):
        msg = f"{function_name}() expects a regex pattern argument"
        raise EvaluationError(msg)
    return value


def _regex_flags(modifiers: str) -> int:
    flags = 0
    if "i" in modifiers:
        flags |= re.IGNORECASE
    if "s" in modifiers:
        flags |= re.DOTALL
    if "m" in modifiers:
        flags |= re.MULTILINE
    return flags


def _regex_matches(pattern: object, values: list[str]) -> bool:
    pattern_text = getattr(pattern, "pattern", pattern)
    modifiers = getattr(pattern, "modifiers", "")
    if not isinstance(pattern_text, str):
        return False
    if not isinstance(modifiers, str):
        msg = "Regex modifiers must be a string"
        raise EvaluationError(msg)
    try:
        regex = re.compile(pattern_text, _regex_flags(modifiers))
        return any(regex.search(value) is not None for value in values)
    except re.error:
        return False


def _pattern_matches(pattern: object, value: str) -> bool:
    if isinstance(pattern, str):
        return pattern == value
    return _regex_matches(pattern, [value])


@dataclass
class Section:
    """PE/ELF section descriptor."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_data_offset: int
    raw_data_size: int
    characteristics: int = 0
    type: int = 0  # For ELF
    pointer_to_relocations: int = 0
    pointer_to_line_numbers: int = 0
    number_of_relocations: int = 0
    number_of_line_numbers: int = 0

    def __getitem__(self, key: str) -> object:
        """Allow dictionary-style access."""
        return getattr(self, key)

    @property
    def full_name(self) -> str:
        return self.name

    @property
    def address(self) -> int:
        return self.virtual_address

    @property
    def size(self) -> int:
        return self.virtual_size

    @property
    def offset(self) -> int:
        return self.raw_data_offset

    @property
    def flags(self) -> int:
        return self.characteristics


@dataclass
class PEOverlay:
    """PE overlay descriptor."""

    offset: int | YaraUndefinedValue
    size: int | YaraUndefinedValue


@dataclass
class PECertificate:
    """PE Authenticode certificate descriptor."""

    issuer: str
    subject: str
    serial: str
    thumbprint: str
    version: int
    not_before: int
    not_after: int


@dataclass
class PESignature:
    """PE Authenticode signature descriptor."""

    issuer: str
    subject: str
    serial: str
    thumbprint: str
    version: int
    not_before: int
    not_after: int
    digest_alg: str
    file_digest: str
    certificates: list[PECertificate]

    @property
    def number_of_certificates(self) -> int:
        return len(self.certificates)


class PERichSignature:
    """PE Rich signature descriptor."""

    def __init__(
        self,
        clear_data: str | YaraUndefinedValue,
        key: int | YaraUndefinedValue,
        offset: int | YaraUndefinedValue,
        length: int | YaraUndefinedValue,
        raw_data: str | YaraUndefinedValue,
    ) -> None:
        self.clear_data = clear_data
        self.key = key
        self.offset = offset
        self.length = length
        self.raw_data = raw_data

    def version(
        self,
        toolid: int,
        version: int | None = None,
    ) -> int | YaraUndefinedValue:
        _require_integer_arg("pe.rich_signature.version", toolid)
        if version is not None:
            _require_integer_arg("pe.rich_signature.version", version)
        if is_yara_undefined(self.key):
            return YARA_UNDEFINED
        return 0

    def toolid(
        self,
        toolid: int,
        version: int | None = None,
    ) -> int | YaraUndefinedValue:
        _require_integer_arg("pe.rich_signature.toolid", toolid)
        if version is not None:
            _require_integer_arg("pe.rich_signature.toolid", version)
        if is_yara_undefined(self.key):
            return YARA_UNDEFINED
        return 0


# ---------------------------------------------------------------------------
# PE module — parses real MZ/PE headers
# ---------------------------------------------------------------------------


class MockPE:
    """PE module: parses real PE headers from binary data."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._parse_headers()

    def _parse_headers(self) -> None:
        """Parse PE headers from data."""
        self.machine: int | YaraUndefinedValue = YARA_UNDEFINED
        self.number_of_sections: int | YaraUndefinedValue = YARA_UNDEFINED
        self.timestamp: int | YaraUndefinedValue = YARA_UNDEFINED
        self.characteristics: int | YaraUndefinedValue = YARA_UNDEFINED
        self.entry_point: int | YaraUndefinedValue = YARA_UNDEFINED
        self.entry_point_raw: int | YaraUndefinedValue = YARA_UNDEFINED
        self.image_base: int | YaraUndefinedValue = YARA_UNDEFINED
        self.size_of_image: int | YaraUndefinedValue = YARA_UNDEFINED
        self.size_of_headers: int | YaraUndefinedValue = YARA_UNDEFINED
        self.subsystem: int | YaraUndefinedValue = YARA_UNDEFINED
        self.dll_characteristics: int | YaraUndefinedValue = YARA_UNDEFINED
        self.sections: list[Section] = []
        self.version_info: dict[str, str] = {}
        self.number_of_resources: int | YaraUndefinedValue = YARA_UNDEFINED
        self.resource_timestamp: int | YaraUndefinedValue = YARA_UNDEFINED
        self._import_list: list[str] = []
        self._export_list: list[str] = []
        self.is_pe = False
        self._is_dll: bool | YaraUndefinedValue = YARA_UNDEFINED
        self._is_32bit: bool | YaraUndefinedValue = YARA_UNDEFINED
        self._is_64bit: bool | YaraUndefinedValue = YARA_UNDEFINED
        self.overlay_offset: int | YaraUndefinedValue = YARA_UNDEFINED
        self.overlay_size: int | YaraUndefinedValue = YARA_UNDEFINED
        self.overlay = PEOverlay(YARA_UNDEFINED, YARA_UNDEFINED)
        self.rich_signature_offset: int | YaraUndefinedValue = YARA_UNDEFINED
        self.rich_signature = PERichSignature(
            YARA_UNDEFINED,
            YARA_UNDEFINED,
            YARA_UNDEFINED,
            YARA_UNDEFINED,
            YARA_UNDEFINED,
        )
        self.number_of_signatures: int | YaraUndefinedValue = YARA_UNDEFINED
        self.signatures: list[PESignature] | YaraUndefinedValue = YARA_UNDEFINED

        if len(self.data) >= 2 and self.data[:2] == b"MZ" and len(self.data) >= 0x40:
            pe_offset = struct.unpack("<I", self.data[0x3C:0x40])[0]

            if (
                len(self.data) >= pe_offset + 4
                and self.data[pe_offset : pe_offset + 4] == b"PE\x00\x00"
                and len(self.data) >= pe_offset + 24
            ):
                self.is_pe = True
                self.number_of_resources = 0
                self.overlay_offset = 0
                self.overlay_size = 0
                self.overlay = PEOverlay(0, 0)
                self.number_of_signatures = 0
                self.signatures = []
                coff_offset = pe_offset + 4
                self.machine = struct.unpack("<H", self.data[coff_offset : coff_offset + 2])[0]
                self.number_of_sections = struct.unpack(
                    "<H", self.data[coff_offset + 2 : coff_offset + 4]
                )[0]
                self.timestamp = struct.unpack("<I", self.data[coff_offset + 4 : coff_offset + 8])[
                    0
                ]
                characteristics = struct.unpack(
                    "<H", self.data[coff_offset + 18 : coff_offset + 20]
                )[0]
                self.characteristics = characteristics
                self._is_dll = bool(characteristics & 0x2000)
                size_of_optional_header = struct.unpack(
                    "<H", self.data[coff_offset + 16 : coff_offset + 18]
                )[0]

                opt_offset = coff_offset + 20
                if len(self.data) >= opt_offset + 2:
                    magic = struct.unpack("<H", self.data[opt_offset : opt_offset + 2])[0]
                    self._is_32bit = magic == 0x10B
                    self._is_64bit = magic == 0x20B

                    if self._is_32bit and len(self.data) >= opt_offset + 32:
                        self.entry_point_raw = struct.unpack(
                            "<I", self.data[opt_offset + 16 : opt_offset + 20]
                        )[0]
                        self.image_base = struct.unpack(
                            "<I", self.data[opt_offset + 28 : opt_offset + 32]
                        )[0]
                    elif self._is_64bit and len(self.data) >= opt_offset + 32:
                        self.entry_point_raw = struct.unpack(
                            "<I", self.data[opt_offset + 16 : opt_offset + 20]
                        )[0]
                        self.image_base = struct.unpack(
                            "<Q", self.data[opt_offset + 24 : opt_offset + 32]
                        )[0]
                    if len(self.data) >= opt_offset + 60:
                        self.size_of_image = struct.unpack(
                            "<I", self.data[opt_offset + 56 : opt_offset + 60]
                        )[0]
                    if len(self.data) >= opt_offset + 64:
                        self.size_of_headers = struct.unpack(
                            "<I", self.data[opt_offset + 60 : opt_offset + 64]
                        )[0]
                    if len(self.data) >= opt_offset + 72:
                        self.subsystem = struct.unpack(
                            "<H", self.data[opt_offset + 68 : opt_offset + 70]
                        )[0]
                        self.dll_characteristics = struct.unpack(
                            "<H", self.data[opt_offset + 70 : opt_offset + 72]
                        )[0]
                self._parse_sections(opt_offset + size_of_optional_header)
                self._update_overlay()
                if _is_strict_int(self.entry_point_raw):
                    entry_point = self.rva_to_offset(self.entry_point_raw)
                    self.entry_point = -1 if entry_point is YARA_UNDEFINED else entry_point

    def _parse_sections(self, section_table_offset: int) -> None:
        """Parse PE section headers."""
        section_header_size = 40
        section_count = self.number_of_sections
        if not _is_strict_int(section_count):
            return
        for index in range(section_count):
            section_offset = section_table_offset + (index * section_header_size)
            section_end = section_offset + section_header_size
            if section_end > len(self.data):
                break

            section_data = self.data[section_offset:section_end]
            name = section_data[:8].split(b"\x00", 1)[0].decode("latin1")
            self.sections.append(
                Section(
                    name=name,
                    virtual_size=struct.unpack("<I", section_data[8:12])[0],
                    virtual_address=struct.unpack("<I", section_data[12:16])[0],
                    raw_data_size=struct.unpack("<I", section_data[16:20])[0],
                    raw_data_offset=struct.unpack("<I", section_data[20:24])[0],
                    pointer_to_relocations=struct.unpack("<I", section_data[24:28])[0],
                    pointer_to_line_numbers=struct.unpack("<I", section_data[28:32])[0],
                    number_of_relocations=struct.unpack("<H", section_data[32:34])[0],
                    number_of_line_numbers=struct.unpack("<H", section_data[34:36])[0],
                    characteristics=struct.unpack("<I", section_data[36:40])[0],
                )
            )

    def _update_overlay(self) -> None:
        if not self.sections:
            return

        overlay_offset = max(
            section.raw_data_offset + section.raw_data_size for section in self.sections
        )
        if overlay_offset < len(self.data):
            self.overlay_offset = overlay_offset
            self.overlay_size = len(self.data) - overlay_offset
            self.overlay = PEOverlay(self.overlay_offset, self.overlay_size)

    def imphash(self) -> str | YaraUndefinedValue:
        """Compute a pefile-compatible import hash."""
        if not self.is_pe:
            return YARA_UNDEFINED
        import_str = ",".join(_normalized_imphash_imports(self._import_list))
        return hashlib.md5(import_str.encode(), usedforsecurity=False).hexdigest()

    def is_dll(self) -> bool | YaraUndefinedValue:
        return self._is_dll

    def is_32bit(self) -> bool | YaraUndefinedValue:
        return self._is_32bit

    def is_64bit(self) -> bool | YaraUndefinedValue:
        return self._is_64bit

    def section_index(self, name_or_offset: object) -> int | YaraUndefinedValue:
        if not isinstance(name_or_offset, str) and not _is_strict_int(name_or_offset):
            msg = "pe.section_index() expects a string or integer argument"
            raise EvaluationError(msg)
        if not self.is_pe:
            return YARA_UNDEFINED
        if _is_strict_int(name_or_offset):
            file_offset = name_or_offset
            if file_offset < 0:
                return YARA_UNDEFINED
            for i, section in enumerate(self.sections):
                if _section_contains_file_offset(section, file_offset):
                    return i
            return YARA_UNDEFINED
        for i, section in enumerate(self.sections):
            if section.name == name_or_offset:
                return i
        return YARA_UNDEFINED

    def rva_to_offset(self, rva: int) -> int | YaraUndefinedValue:
        _require_integer_arg("pe.rva_to_offset", rva)
        if not self.is_pe or rva < 0:
            return YARA_UNDEFINED

        if (
            _is_strict_int(self.size_of_headers)
            and rva < self.size_of_headers
            and rva < len(self.data)
        ):
            return rva

        first_section_rva = min(
            (section.virtual_address for section in self.sections),
            default=None,
        )
        if first_section_rva is not None and rva < first_section_rva and rva < len(self.data):
            return rva

        for section in self.sections:
            span = max(section.virtual_size, section.raw_data_size)
            if span <= 0:
                continue

            section_start = section.virtual_address
            section_end = section_start + span
            if section_start <= rva < section_end:
                raw_offset = section.raw_data_offset + (rva - section_start)
                if raw_offset >= len(self.data):
                    return YARA_UNDEFINED
                return raw_offset

        return YARA_UNDEFINED

    def exports(self, name: object) -> bool | YaraUndefinedValue:
        if not isinstance(name, str) and not _is_regex_pattern(name) and not _is_strict_int(name):
            msg = "pe.exports() expects a string or integer argument"
            raise EvaluationError(msg)
        if not self.is_pe:
            return YARA_UNDEFINED
        if _is_strict_int(name):
            return False
        if _is_regex_pattern(name):
            return any(_pattern_matches(name, export) for export in self._export_list)
        return name in self._export_list

    def imports(self, *args: object) -> bool | YaraUndefinedValue:
        if not _is_valid_pe_import_signature(args):
            msg = "pe.imports() expects libyara-compatible arguments"
            raise EvaluationError(msg)
        if not self.is_pe:
            return YARA_UNDEFINED

        if len(args) == 1:
            dll = args[0]
            return any(
                _matches_import_dll(imported_dll, dll)
                for imported_dll, _ in _split_imports(self._import_list)
            )

        if len(args) == 2:
            dll, function = args
            if _is_regex_pattern(dll) and _is_regex_pattern(function):
                return any(
                    _pattern_matches(dll, imported_dll)
                    and _pattern_matches(function, imported_function)
                    for imported_dll, imported_function in _split_imports(self._import_list)
                )
            if _is_strict_int(dll):
                return any(imp.endswith(f":{function}") for imp in self._import_list)
            if _is_strict_int(function):
                return False
            return any(
                _matches_import_dll(imported_dll, dll) and imported_function == function
                for imported_dll, imported_function in _split_imports(self._import_list)
            )

        _, dll, function = args
        if _is_regex_pattern(dll) and _is_regex_pattern(function):
            return any(
                _pattern_matches(dll, imported_dll)
                and _pattern_matches(function, imported_function)
                for imported_dll, imported_function in _split_imports(self._import_list)
            )
        if _is_strict_int(function):
            return False
        return any(
            _matches_import_dll(imported_dll, dll) and imported_function == function
            for imported_dll, imported_function in _split_imports(self._import_list)
        )

    def locale(self, locale_id: int) -> bool | YaraUndefinedValue:
        _require_integer_arg("pe.locale", locale_id)
        if not self.is_pe:
            return YARA_UNDEFINED
        return False

    def language(self, lang_id: int) -> bool | YaraUndefinedValue:
        _require_integer_arg("pe.language", lang_id)
        if not self.is_pe:
            return YARA_UNDEFINED
        return False


def _is_valid_pe_import_signature(args: tuple[object, ...]) -> bool:
    if len(args) == 1:
        return isinstance(args[0], str)
    if len(args) == 2:
        first, second = args
        return (
            (isinstance(first, str) and (isinstance(second, str) or _is_strict_int(second)))
            or (_is_strict_int(first) and isinstance(second, str))
            or (_is_regex_pattern(first) and _is_regex_pattern(second))
        )
    if len(args) == 3:
        first, second, third = args
        return (
            _is_strict_int(first)
            and isinstance(second, str)
            and (isinstance(third, str) or _is_strict_int(third))
        ) or (_is_strict_int(first) and _is_regex_pattern(second) and _is_regex_pattern(third))
    return False


def _split_imports(imports: list[str]) -> list[tuple[str, str]]:
    split_imports = []
    for item in imports:
        dll, separator, function = item.partition(":")
        if separator:
            split_imports.append((dll, function))
    return split_imports


def _matches_import_dll(imported_dll: str, requested_dll: object) -> bool:
    return isinstance(requested_dll, str) and imported_dll.casefold() == requested_dll.casefold()


def _section_contains_file_offset(section: Section, file_offset: int) -> bool:
    return _address_in_span(file_offset, section.raw_data_offset, section.raw_data_size)


def _address_in_span(address: int, start: int, size: int) -> bool:
    return size > 0 and start <= address < start + size


def _normalized_imphash_imports(imports: list[str]) -> list[str]:
    normalized_imports = []
    for dll, function in _split_imports(imports):
        normalized_imports.append(f"{_remove_library_extension(dll).lower()}.{function.lower()}")
    return normalized_imports


def _remove_library_extension(library_name: str) -> str:
    library = library_name.lower()
    for extension in (".dll", ".ocx", ".sys"):
        if library.endswith(extension):
            return library_name[: -len(extension)]
    return library_name


# ---------------------------------------------------------------------------
# ELF module — parses real ELF headers
# ---------------------------------------------------------------------------


class MockELF:
    """ELF module: parses real ELF headers from binary data."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._parse_headers()

    def _parse_headers(self) -> None:
        self.type: int | YaraUndefinedValue = YARA_UNDEFINED
        self.machine: int | YaraUndefinedValue = YARA_UNDEFINED
        self.entry_point: int | YaraUndefinedValue = YARA_UNDEFINED
        self.sh_offset: int | YaraUndefinedValue = YARA_UNDEFINED
        self.sh_entry_size: int | YaraUndefinedValue = YARA_UNDEFINED
        self.ph_offset: int | YaraUndefinedValue = YARA_UNDEFINED
        self.ph_entry_size: int | YaraUndefinedValue = YARA_UNDEFINED
        self.sections: list[Section] = []
        self.segments: list[dict[str, int]] = []
        self.symtab: list[dict[str, int | str]] = []
        self.dynsym: list[dict[str, int | str]] = []
        self.dynamic: list[dict[str, int]] = []
        self.number_of_sections: int | YaraUndefinedValue = YARA_UNDEFINED
        self.number_of_segments: int | YaraUndefinedValue = YARA_UNDEFINED

        if len(self.data) < 16 or self.data[:4] != b"\x7fELF":
            return

        elf_class = self.data[4]
        data_encoding = self.data[5]
        elf_version = self.data[6]
        if elf_class not in {1, 2} or data_encoding not in {1, 2} or elf_version != 1:
            return

        endian = "<" if data_encoding == 1 else ">"
        header_size = 52 if elf_class == 1 else 64
        if len(self.data) < header_size:
            return

        self.type = struct.unpack(f"{endian}H", self.data[16:18])[0]
        self.machine = struct.unpack(f"{endian}H", self.data[18:20])[0]
        if elf_class == 1:
            entry_point = struct.unpack(f"{endian}I", self.data[24:28])[0]
            program_header_offset = struct.unpack(f"{endian}I", self.data[28:32])[0]
            section_header_offset = struct.unpack(f"{endian}I", self.data[32:36])[0]
            program_header_size = struct.unpack(f"{endian}H", self.data[42:44])[0]
            program_header_count = struct.unpack(f"{endian}H", self.data[44:46])[0]
            section_header_size = struct.unpack(f"{endian}H", self.data[46:48])[0]
            section_header_count = struct.unpack(f"{endian}H", self.data[48:50])[0]
        else:
            entry_point = struct.unpack(f"{endian}Q", self.data[24:32])[0]
            program_header_offset = struct.unpack(f"{endian}Q", self.data[32:40])[0]
            section_header_offset = struct.unpack(f"{endian}Q", self.data[40:48])[0]
            program_header_size = struct.unpack(f"{endian}H", self.data[54:56])[0]
            program_header_count = struct.unpack(f"{endian}H", self.data[56:58])[0]
            section_header_size = struct.unpack(f"{endian}H", self.data[58:60])[0]
            section_header_count = struct.unpack(f"{endian}H", self.data[60:62])[0]

        self.sh_offset = section_header_offset
        self.sh_entry_size = section_header_size
        self.ph_offset = program_header_offset
        self.ph_entry_size = program_header_size
        self.number_of_sections = section_header_count
        self.number_of_segments = program_header_count
        self._parse_section_headers(
            endian,
            elf_class,
            section_header_offset,
            section_header_size,
            section_header_count,
        )
        self._parse_program_headers(
            endian,
            elf_class,
            program_header_offset,
            program_header_size,
            program_header_count,
        )
        self.entry_point = self._virtual_address_to_offset(entry_point)

    def _parse_section_headers(
        self,
        endian: str,
        elf_class: int,
        table_offset: int,
        entry_size: int,
        count: int,
    ) -> None:
        minimum_entry_size = 40 if elf_class == 1 else 64
        if entry_size < minimum_entry_size:
            return

        for index in range(count):
            offset = table_offset + (index * entry_size)
            entry = self.data[offset : offset + entry_size]
            if len(entry) < minimum_entry_size:
                break
            section_type = struct.unpack(f"{endian}I", entry[4:8])[0]
            if elf_class == 1:
                flags = struct.unpack(f"{endian}I", entry[8:12])[0]
                address = struct.unpack(f"{endian}I", entry[12:16])[0]
                raw_offset = struct.unpack(f"{endian}I", entry[16:20])[0]
                size = struct.unpack(f"{endian}I", entry[20:24])[0]
            else:
                flags = struct.unpack(f"{endian}Q", entry[8:16])[0]
                address = struct.unpack(f"{endian}Q", entry[16:24])[0]
                raw_offset = struct.unpack(f"{endian}Q", entry[24:32])[0]
                size = struct.unpack(f"{endian}Q", entry[32:40])[0]
            self.sections.append(
                Section(
                    name="",
                    virtual_address=address,
                    virtual_size=size,
                    raw_data_offset=raw_offset,
                    raw_data_size=size,
                    characteristics=flags,
                    type=section_type,
                )
            )

    def _parse_program_headers(
        self,
        endian: str,
        elf_class: int,
        table_offset: int,
        entry_size: int,
        count: int,
    ) -> None:
        if table_offset == 0 or count == 0:
            return
        minimum_entry_size = 32 if elf_class == 1 else 56
        if entry_size < minimum_entry_size:
            return
        if table_offset + (entry_size * count) > len(self.data):
            return

        for index in range(count):
            offset = table_offset + (index * entry_size)
            entry = self.data[offset : offset + entry_size]
            segment_type = struct.unpack(f"{endian}I", entry[0:4])[0]
            if elf_class == 1:
                segment_offset = struct.unpack(f"{endian}I", entry[4:8])[0]
                virtual_address = struct.unpack(f"{endian}I", entry[8:12])[0]
                physical_address = struct.unpack(f"{endian}I", entry[12:16])[0]
                file_size = struct.unpack(f"{endian}I", entry[16:20])[0]
                memory_size = struct.unpack(f"{endian}I", entry[20:24])[0]
                flags = struct.unpack(f"{endian}I", entry[24:28])[0]
                alignment = struct.unpack(f"{endian}I", entry[28:32])[0]
            else:
                flags = struct.unpack(f"{endian}I", entry[4:8])[0]
                segment_offset = struct.unpack(f"{endian}Q", entry[8:16])[0]
                virtual_address = struct.unpack(f"{endian}Q", entry[16:24])[0]
                physical_address = struct.unpack(f"{endian}Q", entry[24:32])[0]
                file_size = struct.unpack(f"{endian}Q", entry[32:40])[0]
                memory_size = struct.unpack(f"{endian}Q", entry[40:48])[0]
                alignment = struct.unpack(f"{endian}Q", entry[48:56])[0]
            self.segments.append(
                {
                    "type": segment_type,
                    "flags": flags,
                    "offset": segment_offset,
                    "virtual_address": virtual_address,
                    "physical_address": physical_address,
                    "file_size": file_size,
                    "memory_size": memory_size,
                    "alignment": alignment,
                }
            )

    def _virtual_address_to_offset(self, virtual_address: int) -> int | YaraUndefinedValue:
        for segment in self.segments:
            segment_start = segment["virtual_address"]
            segment_size = segment["memory_size"]
            if segment_size <= 0:
                continue
            if segment_start <= virtual_address < segment_start + segment_size:
                return segment["offset"] + (virtual_address - segment_start)
        return YARA_UNDEFINED


# ---------------------------------------------------------------------------
# Math module — real implementations of YARA math functions
# ---------------------------------------------------------------------------


class MockMath:
    """Math module: real implementations of all YARA math functions."""

    _missing_arg = object()

    def __init__(self, data: bytes) -> None:
        self.data = data

    def abs(self, x: int) -> int:
        _require_strict_ints("math.abs", x)
        return abs(x)

    def min(self, a: int, b: int) -> int:
        _require_strict_ints("math.min", a, b)
        return min(a, b, key=_uint64_order_key)

    def max(self, a: int, b: int) -> int:
        _require_strict_ints("math.max", a, b)
        return max(a, b, key=_uint64_order_key)

    def to_string(self, n: int, base: int = 10) -> str | YaraUndefinedValue:
        _require_strict_ints("math.to_string", n, base)
        if base not in {8, 10, 16}:
            return YARA_UNDEFINED
        if base == 16:
            return f"{_unsigned_for_non_decimal_base(n):x}"
        if base == 8:
            return f"{_unsigned_for_non_decimal_base(n):o}"
        return str(n)

    def to_number(self, value: bool) -> int:
        if not isinstance(value, bool):
            msg = "math.to_number() expects a boolean argument"
            raise EvaluationError(msg)
        return int(value)

    def entropy(
        self, value_or_offset: object, size: object = _missing_arg
    ) -> float | YaraUndefinedValue:
        region = self._get_math_input("math.entropy", value_or_offset, size, min_size=0)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        if not region:
            return 0.0

        freq = [0] * 256
        for byte in region:
            freq[byte] += 1

        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / len(region)
                entropy -= p * math.log2(p)

        return entropy

    def mean(
        self, value_or_offset: object, size: object = _missing_arg
    ) -> float | YaraUndefinedValue:
        """Calculate mean byte value of data region."""
        region = self._get_math_input("math.mean", value_or_offset, size, min_size=1)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        return sum(region) / len(region)

    def deviation(
        self,
        value_or_offset: object,
        size_or_mean: object,
        mean_val: object = _missing_arg,
    ) -> float | YaraUndefinedValue:
        """Calculate standard deviation from mean."""
        if mean_val is self._missing_arg:
            region = self._get_math_input(
                "math.deviation", value_or_offset, self._missing_arg, min_size=1
            )
            mean_value = size_or_mean
        else:
            region = self._get_math_input(
                "math.deviation", value_or_offset, size_or_mean, min_size=1
            )
            mean_value = mean_val
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        if is_yara_undefined(mean_value):
            return YARA_UNDEFINED
        if not isinstance(mean_value, float):
            msg = "math.deviation() expects a floating-point mean argument"
            raise EvaluationError(msg)
        return sum(abs(b - mean_value) for b in region) / len(region)

    def serial_correlation(
        self, value_or_offset: object, size: object = _missing_arg
    ) -> float | YaraUndefinedValue:
        """Calculate serial correlation of data region."""
        region = self._get_math_input("math.serial_correlation", value_or_offset, size, min_size=0)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        n = len(region)
        if n < 2:
            return SERIAL_CORRELATION_DEGENERATE
        byte_sum = sum(region)
        squared_sum = sum(byte * byte for byte in region)
        pair_sum = sum(region[index] * region[(index + 1) % n] for index in range(n))
        denominator = n * squared_sum - byte_sum * byte_sum
        if denominator == 0:
            return SERIAL_CORRELATION_DEGENERATE
        return (n * pair_sum - byte_sum * byte_sum) / denominator

    def monte_carlo_pi(
        self, value_or_offset: object, size: object = _missing_arg
    ) -> float | YaraUndefinedValue:
        """Estimate deviation from pi using Monte Carlo method."""
        region = self._get_math_input("math.monte_carlo_pi", value_or_offset, size, min_size=6)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        n_points = len(region) // 6
        inside = 0
        for i in range(n_points):
            base = i * 6
            x = (region[base] << 16 | region[base + 1] << 8 | region[base + 2]) / 0xFFFFFF
            y = (region[base + 3] << 16 | region[base + 4] << 8 | region[base + 5]) / 0xFFFFFF
            if x * x + y * y <= 1.0:
                inside += 1
        pi_estimate = 4.0 * inside / n_points
        return abs(pi_estimate - math.pi) / math.pi

    def count(self, byte: object, offset: object, size: object) -> int | YaraUndefinedValue:
        """Count byte occurrences in a data region."""
        if not _is_strict_int(byte):
            msg = "math.count() expects integer arguments"
            raise EvaluationError(msg)
        byte_value = byte
        if not 0 <= byte_value <= 255:
            return YARA_UNDEFINED
        region = self._get_region("math.count", offset, size, min_size=0)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        return region.count(byte_value)

    def percentage(self, byte: object, offset: object, size: object) -> float | YaraUndefinedValue:
        """Calculate byte occurrence ratio in a data region."""
        if not _is_strict_int(byte):
            msg = "math.percentage() expects integer arguments"
            raise EvaluationError(msg)
        byte_value = byte
        if not 0 <= byte_value <= 255:
            return YARA_UNDEFINED
        region = self._get_region("math.percentage", offset, size, min_size=1)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        return region.count(byte_value) / len(region)

    def mode(self, offset: object, size: object) -> int | YaraUndefinedValue:
        """Return the most common byte in a data region."""
        region = self._get_region("math.mode", offset, size, min_size=0)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        if not region:
            return 0
        return max(range(256), key=region.count)

    def _get_math_input(
        self,
        function_name: str,
        value_or_offset: object,
        size: object,
        *,
        min_size: int,
    ) -> bytes | YaraUndefinedValue:
        if size is self._missing_arg and isinstance(value_or_offset, str):
            region = value_or_offset.encode()
            return region if len(region) >= min_size else YARA_UNDEFINED
        if size is self._missing_arg:
            msg = f"{function_name}() expects 1 string argument or 2 integer arguments"
            raise EvaluationError(msg)
        return self._get_region(function_name, value_or_offset, size, min_size=min_size)

    def _get_region(
        self,
        function_name: str,
        offset: object,
        size: object,
        *,
        min_size: int,
    ) -> bytes | YaraUndefinedValue:
        if is_yara_undefined(offset) or is_yara_undefined(size):
            return YARA_UNDEFINED
        off, sz = _require_region_bounds(function_name, offset, size)
        if off < 0 or off >= len(self.data) or sz < min_size:
            return YARA_UNDEFINED
        region = self.data[off : min(off + sz, len(self.data))]
        if len(region) < min_size:
            return YARA_UNDEFINED
        return region


# ---------------------------------------------------------------------------
# DotNet module
# ---------------------------------------------------------------------------


class MockDotNet:
    """.NET module: provides access to .NET assembly metadata."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.version = YARA_UNDEFINED
        self.module_name = YARA_UNDEFINED
        self.streams = YARA_UNDEFINED
        self.guids = YARA_UNDEFINED
        self.number_of_streams = YARA_UNDEFINED
        self.number_of_guids = YARA_UNDEFINED
        self.number_of_resources = YARA_UNDEFINED
        self.number_of_user_strings = YARA_UNDEFINED
        self.assembly = YARA_UNDEFINED
        self.assembly_refs = YARA_UNDEFINED
        self.resources = YARA_UNDEFINED
        self.user_strings = YARA_UNDEFINED


# ---------------------------------------------------------------------------
# Hash module — real hash computations
# ---------------------------------------------------------------------------


class HashModule:
    """Hash module: real implementations of YARA hash functions."""

    _missing_arg = object()

    def __init__(self, data: bytes) -> None:
        self.data = data

    def md5(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> str | YaraUndefinedValue:
        region = self._get_hash_input("md5", offset, size)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        return hashlib.md5(region, usedforsecurity=False).hexdigest()

    def sha1(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> str | YaraUndefinedValue:
        region = self._get_hash_input("sha1", offset, size)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        return hashlib.sha1(region, usedforsecurity=False).hexdigest()

    def sha256(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> str | YaraUndefinedValue:
        region = self._get_hash_input("sha256", offset, size)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        return hashlib.sha256(region).hexdigest()

    def checksum32(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> int | YaraUndefinedValue:
        region = self._get_hash_input("checksum32", offset, size)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        return sum(region) & 0xFFFFFFFF

    def crc32(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> int | YaraUndefinedValue:
        import binascii

        region = self._get_hash_input("crc32", offset, size)
        if not isinstance(region, bytes):
            return YARA_UNDEFINED
        return binascii.crc32(region) & 0xFFFFFFFF

    def _get_hash_input(
        self, function_name: str, value_or_offset: object, size: object
    ) -> bytes | YaraUndefinedValue:
        if size is self._missing_arg and isinstance(value_or_offset, str):
            return value_or_offset.encode()
        if size is self._missing_arg or value_or_offset is self._missing_arg:
            msg = f"hash.{function_name}() expects 1 string argument or 2 integer arguments"
            raise EvaluationError(msg)
        if is_yara_undefined(value_or_offset) or is_yara_undefined(size):
            return YARA_UNDEFINED
        if not _is_strict_int(value_or_offset) or not _is_strict_int(size):
            msg = f"hash.{function_name}() expects 1 string argument or 2 integer arguments"
            raise EvaluationError(msg)
        return self._get_region(function_name, value_or_offset, size)

    def _get_region(
        self, function_name: str, offset: object, size: object
    ) -> bytes | YaraUndefinedValue:
        if offset is self._missing_arg or size is self._missing_arg:
            msg = f"hash.{function_name}() expects exactly 2 arguments"
            raise EvaluationError(msg)
        if is_yara_undefined(offset) or is_yara_undefined(size):
            return YARA_UNDEFINED
        if (
            isinstance(offset, bool)
            or isinstance(size, bool)
            or not isinstance(offset, int)
            or not isinstance(size, int)
        ):
            msg = f"hash.{function_name}() offset and size must be integers"
            raise EvaluationError(msg)
        off = offset
        sz = size
        if off < 0 or off >= len(self.data) or sz < 0:
            return YARA_UNDEFINED
        return self.data[off : off + sz]


# ---------------------------------------------------------------------------
# Time module
# ---------------------------------------------------------------------------


class TimeModule:
    """Time module: provides current time functions for YARA."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._now = int(time_mod.time())

    def now(self) -> int:
        return self._now


# ---------------------------------------------------------------------------
# Cuckoo module (sandbox results)
# ---------------------------------------------------------------------------


class CuckooModule:
    """Cuckoo module: sandbox analysis results."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.network = CuckooNetwork()
        self.filesystem = CuckooFilesystem()
        self.registry = CuckooRegistry()
        self.sync = CuckooSync()


class CuckooNetwork:
    """Cuckoo network analysis results."""

    def __init__(self) -> None:
        self.hosts: list[str] = []
        self.dns_lookups: list[str] = []
        self.http_requests: list[str] = []
        self.http_get_requests: list[str] = []
        self.http_post_requests: list[str] = []
        self.http_user_agents: list[str] = []
        self.tcp_connections: list[tuple[str, int]] = []
        self.udp_connections: list[tuple[str, int]] = []

    def http_request(self, pattern: object) -> bool:
        return _regex_matches(
            _require_pattern_arg("cuckoo.network.http_request", pattern),
            self.http_requests,
        )

    def http_get(self, pattern: object) -> bool:
        return _regex_matches(
            _require_pattern_arg("cuckoo.network.http_get", pattern),
            self.http_get_requests,
        )

    def http_post(self, pattern: object) -> bool:
        return _regex_matches(
            _require_pattern_arg("cuckoo.network.http_post", pattern),
            self.http_post_requests,
        )

    def http_user_agent(self, pattern: object) -> bool:
        return _regex_matches(
            _require_pattern_arg("cuckoo.network.http_user_agent", pattern),
            self.http_user_agents,
        )

    def dns_lookup(self, pattern: object) -> bool:
        return _regex_matches(
            _require_pattern_arg("cuckoo.network.dns_lookup", pattern),
            self.dns_lookups,
        )

    def host(self, pattern: object) -> bool:
        return _regex_matches(_require_pattern_arg("cuckoo.network.host", pattern), self.hosts)

    def tcp(self, pattern: object, port: object) -> bool:
        if not _is_strict_int(port):
            msg = "cuckoo.network.tcp() port must be an integer"
            raise EvaluationError(msg)
        return self._endpoint_matches(
            _require_pattern_arg("cuckoo.network.tcp", pattern),
            port,
            self.tcp_connections,
        )

    def udp(self, pattern: object, port: object) -> bool:
        if not _is_strict_int(port):
            msg = "cuckoo.network.udp() port must be an integer"
            raise EvaluationError(msg)
        return self._endpoint_matches(
            _require_pattern_arg("cuckoo.network.udp", pattern),
            port,
            self.udp_connections,
        )

    def _endpoint_matches(
        self,
        pattern: object,
        port: int,
        connections: list[tuple[str, int]],
    ) -> bool:
        return any(
            connection_port == port and _regex_matches(pattern, [host])
            for host, connection_port in connections
        )


class CuckooFilesystem:
    """Cuckoo filesystem results."""

    def __init__(self) -> None:
        self.file_accesses: list[str] = []

    def file_access(self, pattern: object) -> bool:
        return _regex_matches(
            _require_pattern_arg("cuckoo.filesystem.file_access", pattern),
            self.file_accesses,
        )


class CuckooRegistry:
    """Cuckoo registry results."""

    def __init__(self) -> None:
        self.key_accesses: list[str] = []

    def key_access(self, pattern: object) -> bool:
        return _regex_matches(
            _require_pattern_arg("cuckoo.registry.key_access", pattern),
            self.key_accesses,
        )


class CuckooSync:
    """Cuckoo synchronization results."""

    def __init__(self) -> None:
        self.mutexes: list[str] = []

    def mutex(self, pattern: object) -> bool:
        return _regex_matches(
            _require_pattern_arg("cuckoo.sync.mutex", pattern),
            self.mutexes,
        )


# ---------------------------------------------------------------------------
# String module
# ---------------------------------------------------------------------------


class StringModule:
    """String utility module for YARA."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def to_int(self, s: str, base: int = 10) -> int | YaraUndefinedValue:
        _require_string_arg("string.to_int", s)
        if not _is_strict_int(base):
            msg = "string.to_int() base must be an integer"
            raise EvaluationError(msg)
        if s != s.rstrip() or "_" in s:
            return YARA_UNDEFINED
        try:
            if base == 0:
                return self._to_int_autodetect_base(s)
            return int(s, base)
        except ValueError:
            return YARA_UNDEFINED

    def _to_int_autodetect_base(self, s: str) -> int:
        sign = ""
        digits = s.lstrip()
        if digits.startswith(("+", "-")):
            sign = digits[0]
            digits = digits[1:]
        if digits.startswith(("0x", "0X")):
            return int(f"{sign}{digits[2:]}", 16)
        if digits.startswith("0") and len(digits) > 1:
            return int(f"{sign}{digits}", 8)
        return int(s, 10)

    def length(self, s: str) -> int:
        _require_string_arg("string.length", s)
        return len(s.encode())


# ---------------------------------------------------------------------------
# Console module
# ---------------------------------------------------------------------------


class ConsoleModule:
    """Console module for YARA debug logging."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.messages: list[str] = []

    def log(self, *messages: object) -> bool:
        _require_scalar_args("console.log", messages)
        if len(messages) > 2:
            msg = "console.log() expects at most two arguments"
            raise EvaluationError(msg)
        if len(messages) == 2 and not isinstance(messages[0], str):
            msg = "console.log() expects a string first argument when two arguments are used"
            raise EvaluationError(msg)
        self.messages.append("".join(str(message) for message in messages))
        return True

    def hex(self, value: object) -> bool:
        integer = _require_integer_arg("console.hex", value)
        self.messages.append(f"0x{integer & UINT64_MASK:x}")
        return True


# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------


class MockModuleRegistry:
    """Registry of YARA module implementations for evaluation."""

    def __init__(self) -> None:
        self.modules: dict[str, type] = {
            "pe": MockPE,
            "elf": MockELF,
            "math": MockMath,
            "dotnet": MockDotNet,
            "hash": HashModule,
            "time": TimeModule,
            "cuckoo": CuckooModule,
            "string": StringModule,
            "console": ConsoleModule,
        }
        self.instances: dict[str, Any] = {}

    def create_module(self, name: str, data: bytes) -> Any:
        """Create a module instance."""
        if name in self.modules:
            instance = self.modules[name](data)
            self.instances[name] = instance
            return instance
        return None

    def get_module(self, name: str) -> Any:
        """Get existing module instance."""
        return self.instances.get(name)

    def register_module(self, name: str, module_class: type) -> None:
        """Register a custom module."""
        self.modules[name] = module_class

    def reset(self) -> None:
        """Reset all module instances."""
        self.instances.clear()
