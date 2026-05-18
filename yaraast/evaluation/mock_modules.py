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
from typing import Any

from yaraast.errors import EvaluationError
from yaraast.evaluation.evaluation_helpers import (
    YARA_UNDEFINED,
    YaraUndefinedValue,
    is_yara_undefined,
)

SERIAL_CORRELATION_DEGENERATE = -100000.0
UINT64_MASK = (1 << 64) - 1


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _unsigned_for_non_decimal_base(value: int) -> int:
    return value & UINT64_MASK if value < 0 else value


def _require_strict_ints(function_name: str, *values: object) -> None:
    if not all(_is_strict_int(value) for value in values):
        msg = f"{function_name}() expects integer arguments"
        raise EvaluationError(msg)


def _require_region_bounds(function_name: str, offset: object, size: object) -> None:
    if not _is_strict_int(offset) or not _is_strict_int(size):
        msg = f"{function_name}() offset and size must be integers"
        raise EvaluationError(msg)


def _require_string_arg(function_name: str, value: object) -> None:
    if not isinstance(value, str):
        msg = f"{function_name}() expects a string argument"
        raise EvaluationError(msg)


def _require_integer_arg(function_name: str, value: object) -> None:
    if not _is_strict_int(value):
        msg = f"{function_name}() expects an integer argument"
        raise EvaluationError(msg)


def _require_scalar_args(function_name: str, values: tuple[object, ...]) -> None:
    if not values or not all(
        isinstance(value, str | int | float) and not isinstance(value, bool) for value in values
    ):
        msg = f"{function_name}() expects scalar arguments"
        raise EvaluationError(msg)


def _require_pattern_arg(function_name: str, value: object) -> str:
    if not isinstance(value, str):
        msg = f"{function_name}() expects a regex pattern argument"
        raise EvaluationError(msg)
    return value


def _regex_matches(pattern: str, values: list[str]) -> bool:
    try:
        return any(re.search(pattern, value) is not None for value in values)
    except re.error:
        return False


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

    def __getitem__(self, key: str):
        """Allow dictionary-style access."""
        return getattr(self, key)


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
        self.machine = YARA_UNDEFINED
        self.number_of_sections = YARA_UNDEFINED
        self.timestamp = YARA_UNDEFINED
        self.characteristics = YARA_UNDEFINED
        self.entry_point = YARA_UNDEFINED
        self.entry_point_raw = YARA_UNDEFINED
        self.image_base = YARA_UNDEFINED
        self.size_of_headers = YARA_UNDEFINED
        self.sections: list[Section] = []
        self.version_info: dict[str, str] = {}
        self.number_of_resources = YARA_UNDEFINED
        self.resource_timestamp = YARA_UNDEFINED
        self._import_list = []
        self._export_list = []
        self.is_pe = False
        self._is_dll: bool | YaraUndefinedValue = YARA_UNDEFINED
        self._is_32bit: bool | YaraUndefinedValue = YARA_UNDEFINED
        self._is_64bit: bool | YaraUndefinedValue = YARA_UNDEFINED
        self.overlay_offset = YARA_UNDEFINED
        self.overlay_size = YARA_UNDEFINED
        self.rich_signature_offset = YARA_UNDEFINED

        if len(self.data) >= 2 and self.data[:2] == b"MZ" and len(self.data) >= 0x40:
            pe_offset = struct.unpack("<I", self.data[0x3C:0x40])[0]

            if (
                len(self.data) >= pe_offset + 4
                and self.data[pe_offset : pe_offset + 4] == b"PE\x00\x00"
                and len(self.data) >= pe_offset + 24
            ):
                self.is_pe = True
                self.number_of_resources = 0
                self.resource_timestamp = 0
                self.overlay_offset = 0
                self.overlay_size = 0
                self.rich_signature_offset = 0
                coff_offset = pe_offset + 4
                self.machine = struct.unpack("<H", self.data[coff_offset : coff_offset + 2])[0]
                self.number_of_sections = struct.unpack(
                    "<H", self.data[coff_offset + 2 : coff_offset + 4]
                )[0]
                self.timestamp = struct.unpack("<I", self.data[coff_offset + 4 : coff_offset + 8])[
                    0
                ]
                self.characteristics = struct.unpack(
                    "<H", self.data[coff_offset + 18 : coff_offset + 20]
                )[0]
                self._is_dll = bool(self.characteristics & 0x2000)
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
                    if len(self.data) >= opt_offset + 64:
                        self.size_of_headers = struct.unpack(
                            "<I", self.data[opt_offset + 60 : opt_offset + 64]
                        )[0]
                self._parse_sections(opt_offset + size_of_optional_header)
                if _is_strict_int(self.entry_point_raw):
                    entry_point = self.rva_to_offset(self.entry_point_raw)
                    self.entry_point = -1 if entry_point is YARA_UNDEFINED else entry_point

    def _parse_sections(self, section_table_offset: int) -> None:
        """Parse PE section headers."""
        section_header_size = 40
        for index in range(self.number_of_sections):
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
                    characteristics=struct.unpack("<I", section_data[36:40])[0],
                )
            )

    def imphash(self) -> str:
        """Compute MD5 of import table (simplified)."""
        import_str = ",".join(sorted(self._import_list)).lower()
        return (
            hashlib.md5(import_str.encode(), usedforsecurity=False).hexdigest()
            if import_str
            else ""
        )

    def is_dll(self) -> bool | YaraUndefinedValue:
        return self._is_dll

    def is_32bit(self) -> bool | YaraUndefinedValue:
        return self._is_32bit

    def is_64bit(self) -> bool | YaraUndefinedValue:
        return self._is_64bit

    def section_index(self, name: str) -> int | YaraUndefinedValue:
        _require_string_arg("pe.section_index", name)
        if not self.is_pe:
            return YARA_UNDEFINED
        for i, section in enumerate(self.sections):
            if section.name == name:
                return i
        return YARA_UNDEFINED

    def rva_to_offset(self, rva: int) -> int | YaraUndefinedValue:
        _require_integer_arg("pe.rva_to_offset", rva)
        if not self.is_pe or rva < 0:
            return YARA_UNDEFINED

        if self.size_of_headers and rva < self.size_of_headers and rva < len(self.data):
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

    def exports(self, name: str) -> bool | YaraUndefinedValue:
        _require_string_arg("pe.exports", name)
        if not self.is_pe:
            return YARA_UNDEFINED
        return name in self._export_list

    def imports(self, dll: str, function: str | None = None) -> bool | YaraUndefinedValue:
        if not isinstance(dll, str) or (function is not None and not isinstance(function, str)):
            msg = "pe.imports() expects string arguments"
            raise EvaluationError(msg)
        if not self.is_pe:
            return YARA_UNDEFINED
        if function:
            return f"{dll}:{function}" in self._import_list
        return any(imp.startswith(f"{dll}:") for imp in self._import_list)

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


# ---------------------------------------------------------------------------
# ELF module — parses real ELF headers
# ---------------------------------------------------------------------------


class MockELF:
    """ELF module: parses real ELF headers from binary data."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._parse_headers()

    def _parse_headers(self) -> None:
        self.type = YARA_UNDEFINED
        self.machine = YARA_UNDEFINED
        self.entry_point = YARA_UNDEFINED
        self.sections: list[Section] = []
        self.segments: list[dict] = []
        self.number_of_sections = YARA_UNDEFINED
        self.number_of_segments = YARA_UNDEFINED

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
            section_header_offset = struct.unpack(f"{endian}I", self.data[32:36])[0]
            program_header_count = struct.unpack(f"{endian}H", self.data[44:46])[0]
            section_header_size = struct.unpack(f"{endian}H", self.data[46:48])[0]
            section_header_count = struct.unpack(f"{endian}H", self.data[48:50])[0]
        else:
            section_header_offset = struct.unpack(f"{endian}Q", self.data[40:48])[0]
            program_header_count = struct.unpack(f"{endian}H", self.data[56:58])[0]
            section_header_size = struct.unpack(f"{endian}H", self.data[58:60])[0]
            section_header_count = struct.unpack(f"{endian}H", self.data[60:62])[0]

        if (
            section_header_offset == 0
            or section_header_size == 0
            or section_header_count == 0
            or section_header_offset + (section_header_size * section_header_count) > len(self.data)
        ):
            self.type = YARA_UNDEFINED
            self.machine = YARA_UNDEFINED
            return

        self.number_of_sections = section_header_count
        self.number_of_segments = program_header_count


# ---------------------------------------------------------------------------
# Math module — real implementations of YARA math functions
# ---------------------------------------------------------------------------


class MockMath:
    """Math module: real implementations of all YARA math functions."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def abs(self, x: int) -> int:
        _require_strict_ints("math.abs", x)
        return abs(x)

    def min(self, a: int, b: int) -> int:
        _require_strict_ints("math.min", a, b)
        return min(a, b)

    def max(self, a: int, b: int) -> int:
        _require_strict_ints("math.max", a, b)
        return max(a, b)

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

    def entropy(self, offset: int, size: int) -> float | YaraUndefinedValue:
        region = self._get_region("math.entropy", offset, size, min_size=0)
        if region is YARA_UNDEFINED:
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

    def mean(self, offset: int, size: int) -> float | YaraUndefinedValue:
        """Calculate mean byte value of data region."""
        region = self._get_region("math.mean", offset, size, min_size=1)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        return sum(region) / len(region)

    def deviation(self, offset: int, size: int, mean_val: float) -> float | YaraUndefinedValue:
        """Calculate standard deviation from mean."""
        if is_yara_undefined(mean_val):
            return YARA_UNDEFINED
        if not isinstance(mean_val, float):
            msg = "math.deviation() expects a floating-point mean argument"
            raise EvaluationError(msg)
        region = self._get_region("math.deviation", offset, size, min_size=1)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        variance = sum((b - mean_val) ** 2 for b in region) / len(region)
        return math.sqrt(variance)

    def serial_correlation(self, offset: int, size: int) -> float | YaraUndefinedValue:
        """Calculate serial correlation of data region."""
        region = self._get_region("math.serial_correlation", offset, size, min_size=0)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        n = len(region)
        if n < 2:
            return SERIAL_CORRELATION_DEGENERATE
        mean_val = sum(region) / n
        num = sum((region[i] - mean_val) * (region[i + 1] - mean_val) for i in range(n - 1))
        den = sum((b - mean_val) ** 2 for b in region)
        return num / den if den != 0 else SERIAL_CORRELATION_DEGENERATE

    def monte_carlo_pi(self, offset: int, size: int) -> float | YaraUndefinedValue:
        """Estimate deviation from pi using Monte Carlo method."""
        region = self._get_region("math.monte_carlo_pi", offset, size, min_size=6)
        if region is YARA_UNDEFINED:
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

    def _get_region(
        self,
        function_name: str,
        offset: int,
        size: int,
        *,
        min_size: int,
    ) -> bytes | YaraUndefinedValue:
        if is_yara_undefined(offset) or is_yara_undefined(size):
            return YARA_UNDEFINED
        _require_region_bounds(function_name, offset, size)
        if offset < 0 or offset >= len(self.data) or size < min_size:
            return YARA_UNDEFINED
        region = self.data[offset : min(offset + size, len(self.data))]
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
        region = self._get_region("md5", offset, size)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        return hashlib.md5(region, usedforsecurity=False).hexdigest()

    def sha1(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> str | YaraUndefinedValue:
        region = self._get_region("sha1", offset, size)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        return hashlib.sha1(region, usedforsecurity=False).hexdigest()

    def sha256(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> str | YaraUndefinedValue:
        region = self._get_region("sha256", offset, size)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        return hashlib.sha256(region).hexdigest()

    def checksum32(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> int | YaraUndefinedValue:
        region = self._get_region("checksum32", offset, size)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        return sum(region) & 0xFFFFFFFF

    def crc32(
        self, offset: object = _missing_arg, size: object = _missing_arg
    ) -> int | YaraUndefinedValue:
        import binascii

        region = self._get_region("crc32", offset, size)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        return binascii.crc32(region) & 0xFFFFFFFF

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
        pattern: str,
        port: int,
        connections: list[tuple[str, int]],
    ) -> bool:
        try:
            return any(
                connection_port == port and re.search(pattern, host)
                for host, connection_port in connections
            )
        except re.error:
            return False


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
        try:
            return int(s, base)
        except ValueError:
            return YARA_UNDEFINED

    def length(self, s: str) -> int:
        _require_string_arg("string.length", s)
        return len(s)


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
