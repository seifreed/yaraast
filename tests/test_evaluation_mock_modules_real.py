"""Additional real tests for evaluation mock modules."""

from __future__ import annotations

import struct

from yaraast.evaluation.evaluation_helpers import YARA_UNDEFINED
from yaraast.evaluation.mock_modules import (
    HashModule,
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

    pe64._import_list = ["kernel32.dll:CreateFileW", "user32.dll:MessageBoxW"]
    assert pe64.imports("kernel32.dll", "CreateFileW") is True
    assert pe64.imports("kernel32.dll", "CloseHandle") is False
    assert pe64.imports("user32.dll") is True

    pe64._export_list = ["ExportedFn"]
    assert pe64.exports("ExportedFn") is True
    assert pe64.exports("Missing") is False
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
    assert m.entropy(-1, 1) is YARA_UNDEFINED
    assert m.entropy(0, 0) == 0.0
    assert m.entropy(1000, 5) is YARA_UNDEFINED
    assert m.mean(-1, 1) is YARA_UNDEFINED
    assert m.mean(10, 100) == 255.0
    assert m.deviation(-1, 1, 0.0) is YARA_UNDEFINED
    assert m.serial_correlation(0, 1) is YARA_UNDEFINED
    assert m.monte_carlo_pi(0, 5) is YARA_UNDEFINED

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


def test_hash_module_respects_zero_length_regions() -> None:
    hash_module = HashModule(b"abc")

    assert hash_module.md5(0, 0) == "d41d8cd98f00b204e9800998ecf8427e"
    assert hash_module.sha1(0, 0) == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert (
        hash_module.sha256(0, 0) == "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )
    assert hash_module.checksum32(0, 0) == 0
    assert hash_module.crc32(0, 0) == 0


def test_hash_module_returns_undefined_for_invalid_regions() -> None:
    hash_module = HashModule(b"abc")

    assert hash_module.md5(-1, 1) is YARA_UNDEFINED
    assert hash_module.sha1(3, 0) is YARA_UNDEFINED
    assert hash_module.sha256(4, 1) is YARA_UNDEFINED
    assert hash_module.checksum32(1, -1) is YARA_UNDEFINED
    assert hash_module.crc32(-2, 100) is YARA_UNDEFINED
