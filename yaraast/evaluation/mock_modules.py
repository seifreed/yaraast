"""Mock module implementations for YARA evaluation."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any


@dataclass
class Section:
    """Mock PE/ELF section."""

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


class MockPE:
    """Mock PE module for testing."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._parse_headers()

    def _parse_headers(self) -> None:
        """Parse PE headers from data."""
        # Default values
        self.machine = 0x14C  # IMAGE_FILE_MACHINE_I386
        self.number_of_sections = 0
        self.timestamp = 0
        self.characteristics = 0
        self.entry_point = 0
        self.image_base = 0x400000
        self.sections = []
        self.version_info = {}
        self.number_of_resources = 0
        self.resource_timestamp = 0
        self.imports = []
        self.exports = []
        self.is_pe = False
        self.is_dll = False
        self.is_32bit = True
        self.is_64bit = False

        # Check MZ header
        if len(self.data) >= 2 and self.data[:2] == b"MZ":
            self.is_pe = True

            # Get PE header offset
            if len(self.data) >= 0x40:
                pe_offset = struct.unpack("<I", self.data[0x3C:0x40])[0]

                # Check PE signature
                if (
                    len(self.data) >= pe_offset + 4
                    and self.data[pe_offset : pe_offset + 4] == b"PE\x00\x00"
                    and len(self.data) >= pe_offset + 24
                ):
                    coff_offset = pe_offset + 4
                    self.machine = struct.unpack(
                        "<H",
                        self.data[coff_offset : coff_offset + 2],
                    )[0]
                    self.number_of_sections = struct.unpack(
                        "<H",
                        self.data[coff_offset + 2 : coff_offset + 4],
                    )[0]
                    self.timestamp = struct.unpack(
                        "<I",
                        self.data[coff_offset + 4 : coff_offset + 8],
                    )[0]
                    self.characteristics = struct.unpack(
                        "<H",
                        self.data[coff_offset + 18 : coff_offset + 20],
                    )[0]

                    # Check if DLL
                    self.is_dll = bool(self.characteristics & 0x2000)

                    # Parse optional header
                    opt_offset = coff_offset + 20
                    if len(self.data) >= opt_offset + 2:
                        magic = struct.unpack(
                            "<H",
                            self.data[opt_offset : opt_offset + 2],
                        )[0]
                        self.is_32bit = magic == 0x10B
                        self.is_64bit = magic == 0x20B

                        if self.is_32bit and len(self.data) >= opt_offset + 28:
                            self.entry_point = struct.unpack(
                                "<I",
                                self.data[opt_offset + 16 : opt_offset + 20],
                            )[0]
                            self.image_base = struct.unpack(
                                "<I",
                                self.data[opt_offset + 28 : opt_offset + 32],
                            )[0]

    def imphash(self) -> str:
        """Return import hash."""
        return "d41d8cd98f00b204e9800998ecf8427e"  # Empty MD5

    def section_index(self, name: str) -> int:
        """Get section index by name."""
        for i, section in enumerate(self.sections):
            if section.name == name:
                return i
        return -1

    def exports(self, name: str) -> bool:
        """Check if export exists."""
        return name in self.exports

    def imports(self, dll: str, function: str | None = None) -> bool:
        """Check if import exists."""
        if function:
            return f"{dll}:{function}" in self.imports
        return any(imp.startswith(f"{dll}:") for imp in self.imports)

    def locale(self, locale_id: int) -> bool:
        """Check if locale exists."""
        return False

    def language(self, lang_id: int) -> bool:
        """Check if language exists."""
        return False


class MockELF:
    """Mock ELF module for testing."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._parse_headers()

    def _parse_headers(self) -> None:
        """Parse ELF headers from data."""
        # Default values
        self.type = 2  # ET_EXEC
        self.machine = 3  # EM_386
        self.entry_point = 0x8048000
        self.sections = []
        self.segments = []

        # Check ELF magic
        if len(self.data) >= 20 and self.data[:4] == b"\x7fELF":
            self.type = struct.unpack("<H", self.data[16:18])[0]
            self.machine = struct.unpack("<H", self.data[18:20])[0]


class MockMath:
    """Mock math module for testing."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def abs(self, x: int) -> int:
        """Absolute value."""
        return abs(x)

    def min(self, a: int, b: int) -> int:
        """Minimum value."""
        return min(a, b)

    def max(self, a: int, b: int) -> int:
        """Maximum value."""
        return max(a, b)

    def to_string(self, n: int, base: int = 10) -> str:
        """Convert number to string."""
        if base == 16:
            return hex(n)[2:]
        if base == 8:
            return oct(n)[2:]
        if base == 2:
            return bin(n)[2:]
        return str(n)

    def to_number(self, s: str) -> int:
        """Convert string to number."""
        try:
            return int(s, 0)  # Auto-detect base
        except (ValueError, TypeError, AttributeError):
            return 0

    def log(self, x: float) -> float:
        """Natural logarithm."""
        return math.log(x) if x > 0 else float("-inf")

    def log2(self, x: float) -> float:
        """Base-2 logarithm."""
        return math.log2(x) if x > 0 else float("-inf")

    def log10(self, x: float) -> float:
        """Base-10 logarithm."""
        return math.log10(x) if x > 0 else float("-inf")

    def sqrt(self, x: float) -> float:
        """Square root."""
        return math.sqrt(x) if x >= 0 else float("nan")

    def entropy(self, offset: int, size: int) -> float:
        """Calculate entropy of data region."""
        if offset < 0 or size <= 0 or offset + size > len(self.data):
            return 0.0

        # Count byte frequencies
        freq = [0] * 256
        for i in range(offset, min(offset + size, len(self.data))):
            freq[self.data[i]] += 1

        # Calculate entropy
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / size
                entropy -= p * math.log2(p)

        return entropy


class MockDotNet:
    """Mock .NET module for testing."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.version = ""
        self.module_name = ""
        self.streams = {}
        self.guids = []
        self.number_of_streams = 0
        self.number_of_guids = 0
        self.number_of_resources = 0
        self.number_of_user_strings = 0
        self.assembly = {}
        self.assembly_refs = []
        self.resources = []
        self.user_strings = []


class MockModuleRegistry:
    """Registry of mock modules."""

    def __init__(self) -> None:
        self.modules = {
            "pe": MockPE,
            "elf": MockELF,
            "math": MockMath,
            "dotnet": MockDotNet,
        }
        self.instances = {}

    def create_module(self, name: str, data: bytes) -> Any:
        """Create a mock module instance."""
        if name in self.modules:
            instance = self.modules[name](data)
            self.instances[name] = instance
            return instance
        return None

    def get_module(self, name: str) -> Any:
        """Get existing module instance."""
        return self.instances.get(name)

    def register_module(self, name: str, module_class: type) -> None:
        """Register a custom mock module."""
        self.modules[name] = module_class

    def reset(self) -> None:
        """Reset all module instances."""
        self.instances.clear()
