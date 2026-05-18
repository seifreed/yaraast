"""YARA module implementations for the yaraast evaluation engine.

These are real implementations that parse binary data (PE headers, ELF headers, etc.)
and provide YARA module semantics for condition evaluation without requiring yara-python.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import struct
import time as time_mod
from typing import Any

from yaraast.errors import EvaluationError
from yaraast.evaluation.evaluation_helpers import YARA_UNDEFINED, YaraUndefinedValue

SERIAL_CORRELATION_DEGENERATE = -100000.0
UINT64_MASK = (1 << 64) - 1


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _unsigned_for_non_decimal_base(value: int) -> int:
    return value & UINT64_MASK if value < 0 else value


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
        self.machine = 0x14C
        self.number_of_sections = 0
        self.timestamp = 0
        self.characteristics = 0
        self.entry_point = 0
        self.image_base = 0x400000
        self.size_of_headers = 0
        self.sections: list[Section] = []
        self.version_info: dict[str, str] = {}
        self.number_of_resources = 0
        self.resource_timestamp = 0
        self._import_list = []
        self._export_list = []
        self.is_pe = False
        self.is_dll = False
        self.is_32bit = True
        self.is_64bit = False
        self.overlay_offset = 0
        self.overlay_size = 0
        self.rich_signature_offset = 0

        if len(self.data) >= 2 and self.data[:2] == b"MZ":
            self.is_pe = True

            if len(self.data) >= 0x40:
                pe_offset = struct.unpack("<I", self.data[0x3C:0x40])[0]

                if (
                    len(self.data) >= pe_offset + 4
                    and self.data[pe_offset : pe_offset + 4] == b"PE\x00\x00"
                    and len(self.data) >= pe_offset + 24
                ):
                    coff_offset = pe_offset + 4
                    self.machine = struct.unpack("<H", self.data[coff_offset : coff_offset + 2])[0]
                    self.number_of_sections = struct.unpack(
                        "<H", self.data[coff_offset + 2 : coff_offset + 4]
                    )[0]
                    self.timestamp = struct.unpack(
                        "<I", self.data[coff_offset + 4 : coff_offset + 8]
                    )[0]
                    self.characteristics = struct.unpack(
                        "<H", self.data[coff_offset + 18 : coff_offset + 20]
                    )[0]
                    self.is_dll = bool(self.characteristics & 0x2000)
                    size_of_optional_header = struct.unpack(
                        "<H", self.data[coff_offset + 16 : coff_offset + 18]
                    )[0]

                    opt_offset = coff_offset + 20
                    if len(self.data) >= opt_offset + 2:
                        magic = struct.unpack("<H", self.data[opt_offset : opt_offset + 2])[0]
                        self.is_32bit = magic == 0x10B
                        self.is_64bit = magic == 0x20B

                        if self.is_32bit and len(self.data) >= opt_offset + 32:
                            self.entry_point = struct.unpack(
                                "<I", self.data[opt_offset + 16 : opt_offset + 20]
                            )[0]
                            self.image_base = struct.unpack(
                                "<I", self.data[opt_offset + 28 : opt_offset + 32]
                            )[0]
                        if len(self.data) >= opt_offset + 64:
                            self.size_of_headers = struct.unpack(
                                "<I", self.data[opt_offset + 60 : opt_offset + 64]
                            )[0]
                    self._parse_sections(opt_offset + size_of_optional_header)

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

    def section_index(self, name: str) -> int:
        for i, section in enumerate(self.sections):
            if section.name == name:
                return i
        return -1

    def rva_to_offset(self, rva: int) -> int | YaraUndefinedValue:
        if not isinstance(rva, int) or not self.is_pe or rva < 0:
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
                return section.raw_data_offset + (rva - section_start)

        return YARA_UNDEFINED

    def exports(self, name: str) -> bool:
        return name in self._export_list

    def imports(self, dll: str, function: str | None = None) -> bool:
        if function:
            return f"{dll}:{function}" in self._import_list
        return any(imp.startswith(f"{dll}:") for imp in self._import_list)

    def locale(self, locale_id: int) -> bool:
        return False

    def language(self, lang_id: int) -> bool:
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
        self.type = 2  # ET_EXEC
        self.machine = 3  # EM_386
        self.entry_point = 0x8048000
        self.sections: list[Section] = []
        self.segments: list[dict] = []
        self.number_of_sections = 0
        self.number_of_segments = 0

        if len(self.data) >= 20 and self.data[:4] == b"\x7fELF":
            self.type = struct.unpack("<H", self.data[16:18])[0]
            self.machine = struct.unpack("<H", self.data[18:20])[0]


# ---------------------------------------------------------------------------
# Math module — real implementations of YARA math functions
# ---------------------------------------------------------------------------


class MockMath:
    """Math module: real implementations of all YARA math functions."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def abs(self, x: int) -> int:
        return abs(x)

    def min(self, a: int, b: int) -> int:
        return min(a, b)

    def max(self, a: int, b: int) -> int:
        return max(a, b)

    def to_string(self, n: int, base: int = 10) -> str | YaraUndefinedValue:
        if not _is_strict_int(n) or not _is_strict_int(base):
            msg = "math.to_string() expects integer arguments"
            raise EvaluationError(msg)
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

    def log(self, x: float) -> float:
        return math.log(x) if x > 0 else float("-inf")

    def log2(self, x: float) -> float:
        return math.log2(x) if x > 0 else float("-inf")

    def log10(self, x: float) -> float:
        return math.log10(x) if x > 0 else float("-inf")

    def sqrt(self, x: float) -> float:
        return math.sqrt(x) if x >= 0 else float("nan")

    def entropy(self, offset: int, size: int) -> float | YaraUndefinedValue:
        region = self._get_region(offset, size, min_size=0)
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
        region = self._get_region(offset, size, min_size=1)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        return sum(region) / len(region)

    def deviation(self, offset: int, size: int, mean_val: float) -> float | YaraUndefinedValue:
        """Calculate standard deviation from mean."""
        region = self._get_region(offset, size, min_size=1)
        if region is YARA_UNDEFINED:
            return YARA_UNDEFINED
        variance = sum((b - mean_val) ** 2 for b in region) / len(region)
        return math.sqrt(variance)

    def serial_correlation(self, offset: int, size: int) -> float | YaraUndefinedValue:
        """Calculate serial correlation of data region."""
        region = self._get_region(offset, size, min_size=0)
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
        region = self._get_region(offset, size, min_size=6)
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

    def _get_region(self, offset: int, size: int, *, min_size: int) -> bytes | YaraUndefinedValue:
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
        self.version = ""
        self.module_name = ""
        self.streams: dict[str, Any] = {}
        self.guids: list[str] = []
        self.number_of_streams = 0
        self.number_of_guids = 0
        self.number_of_resources = 0
        self.number_of_user_strings = 0
        self.assembly: dict[str, Any] = {}
        self.assembly_refs: list[dict[str, Any]] = []
        self.resources: list[dict[str, Any]] = []
        self.user_strings: list[str] = []


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
        self.now = int(time_mod.time())


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
        self.dns_lookup: list[str] = []
        self.http_request: list[str] = []

    def dns_lookup_match(self, pattern: str) -> bool:
        return any(pattern in d for d in self.dns_lookup)

    def http_get(self, url: str) -> bool:
        return url in self.http_request


class CuckooFilesystem:
    """Cuckoo filesystem results."""

    def __init__(self) -> None:
        self.file_access: list[str] = []


class CuckooRegistry:
    """Cuckoo registry results."""

    def __init__(self) -> None:
        self.key_access: list[str] = []


class CuckooSync:
    """Cuckoo synchronization results."""

    def __init__(self) -> None:
        self.mutex: list[str] = []

    def mutex_match(self, pattern: str) -> bool:
        return any(pattern in m for m in self.mutex)


# ---------------------------------------------------------------------------
# String module
# ---------------------------------------------------------------------------


class StringModule:
    """String utility module for YARA."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def to_int(self, s: str, base: int = 10) -> int:
        try:
            return int(s, base)
        except (ValueError, TypeError):
            return 0

    def length(self, s: str) -> int:
        return len(s)


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
