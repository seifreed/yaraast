"""Additional real tests for evaluation mock modules."""

from __future__ import annotations

import struct

from yaraast.evaluation.mock_modules import (
    MockDotNet,
    MockELF,
    MockMath,
    MockModuleRegistry,
    MockPE,
    Section,
)


def _build_pe_data(*, dll: bool, magic: int) -> bytes:
    data = bytearray(b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00")
    if len(data) < 0x80:
        data.extend(b"\x00" * (0x80 - len(data)))
    data.extend(b"PE\x00\x00")
    data.extend(struct.pack("<H", 0x14C))  # machine
    data.extend(struct.pack("<H", 2))  # number_of_sections
    data.extend(struct.pack("<I", 1))  # timestamp
    data.extend(b"\x00" * 8)
    data.extend(struct.pack("<H", 0xE0))
    data.extend(struct.pack("<H", 0x2000 if dll else 0x0002))
    data.extend(struct.pack("<H", magic))
    data.extend(b"\x00" * 14)
    data.extend(struct.pack("<I", 0x1000))  # entry_point
    data.extend(b"\x00" * 8)
    if magic == 0x10B:
        data.extend(struct.pack("<I", 0x400000))
    return bytes(data)


def test_section_getitem_and_mock_pe_extended_branches() -> None:
    sec = Section(".text", 0x1000, 0x200, 0x400, 0x200)
    assert sec["name"] == ".text"

    pe32 = MockPE(_build_pe_data(dll=True, magic=0x10B))
    assert pe32.is_pe is True
    assert pe32.is_32bit is True
    assert pe32.is_64bit is False
    assert pe32.is_dll is True
    assert pe32.entry_point == 0x1000
    assert pe32.image_base == 0x400000

    pe64 = MockPE(_build_pe_data(dll=False, magic=0x20B))
    assert pe64.is_32bit is False
    assert pe64.is_64bit is True

    pe64.sections = [Section(".text", 0x1000, 0x200, 0x400, 0x200)]
    assert pe64.section_index(".text") == 0
    assert pe64.section_index(".rdata") == -1

    pe64.imports = ["kernel32.dll:CreateFileW", "user32.dll:MessageBoxW"]
    assert MockPE.imports(pe64, "kernel32.dll", "CreateFileW") is True
    assert MockPE.imports(pe64, "kernel32.dll", "CloseHandle") is False
    assert MockPE.imports(pe64, "user32.dll") is True

    pe64.exports = ["ExportedFn"]
    assert MockPE.exports(pe64, "ExportedFn") is True
    assert MockPE.exports(pe64, "Missing") is False
    assert pe64.locale(0x409) is False
    assert pe64.language(0x09) is False
    assert pe64.imphash()


def test_mock_elf_math_dotnet_and_registry_branches() -> None:
    elf_data = b"\x7fELF" + b"\x00" * 12 + struct.pack("<H", 3) + struct.pack("<H", 0x3E)
    elf = MockELF(elf_data)
    assert elf.type == 3
    assert elf.machine == 0x3E

    m = MockMath(b"\x00" * 10 + b"\xff" * 10)
    assert m.to_string(10) == "10"
    assert m.to_string(10, 2) == "1010"
    assert m.to_string(10, 8) == "12"
    assert m.to_number("bad") == 0
    assert m.log(0) == float("-inf")
    assert m.log2(0) == float("-inf")
    assert m.log10(0) == float("-inf")
    assert str(m.sqrt(-1)) == "nan"
    assert m.entropy(-1, 1) == 0.0
    assert m.entropy(0, 0) == 0.0
    assert m.entropy(1000, 5) == 0.0

    dotnet = MockDotNet(b"")
    assert dotnet.number_of_streams == 0
    assert dotnet.number_of_guids == 0

    registry = MockModuleRegistry()
    assert registry.create_module("missing", b"x") is None

    class _Custom:
        def __init__(self, data: bytes) -> None:
            self.data = data

    registry.register_module("custom", _Custom)
    custom = registry.create_module("custom", b"abc")
    assert isinstance(custom, _Custom)
    assert registry.get_module("custom") is custom
    registry.reset()
    assert registry.get_module("custom") is None
