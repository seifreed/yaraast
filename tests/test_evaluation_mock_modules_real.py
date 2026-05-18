"""Additional real tests for evaluation mock modules."""

from __future__ import annotations

import struct
from typing import Any, cast

import pytest

from yaraast.errors import EvaluationError
from yaraast.evaluation.evaluation_helpers import YARA_UNDEFINED
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.evaluation.mock_modules import (
    ConsoleModule,
    CuckooModule,
    HashModule,
    MockDotNet,
    MockELF,
    MockMath,
    MockModuleRegistry,
    MockPE,
    Section,
    StringModule,
)
from yaraast.parser import Parser


def _build_pe_data(*, dll: bool, magic: int, sections: list[Section] | None = None) -> bytes:
    sections = sections or []
    data = bytearray(b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00")
    if len(data) < 0x80:
        data.extend(b"\x00" * (0x80 - len(data)))
    data.extend(b"PE\x00\x00")
    data.extend(struct.pack("<H", 0x14C))  # machine
    data.extend(struct.pack("<H", len(sections)))  # number_of_sections
    data.extend(struct.pack("<I", 1))  # timestamp
    data.extend(b"\x00" * 8)
    data.extend(struct.pack("<H", 0xE0))
    data.extend(struct.pack("<H", 0x2000 if dll else 0x0002))
    optional_header = bytearray(0xE0)
    struct.pack_into("<H", optional_header, 0, magic)
    struct.pack_into("<I", optional_header, 16, 0x1000)  # entry_point
    struct.pack_into("<I", optional_header, 60, 0x200)  # size_of_headers
    if magic == 0x10B:
        struct.pack_into("<I", optional_header, 28, 0x400000)
    data.extend(optional_header)
    for section in sections:
        name = section.name.encode("ascii")[:8].ljust(8, b"\x00")
        data.extend(name)
        data.extend(struct.pack("<I", section.virtual_size))
        data.extend(struct.pack("<I", section.virtual_address))
        data.extend(struct.pack("<I", section.raw_data_size))
        data.extend(struct.pack("<I", section.raw_data_offset))
        data.extend(b"\x00" * 8)
        data.extend(struct.pack("<H", 0))
        data.extend(struct.pack("<H", 0))
        data.extend(struct.pack("<I", section.characteristics))
    if sections:
        raw_end = max(section.raw_data_offset + section.raw_data_size for section in sections)
        if len(data) < raw_end:
            data.extend(b"\x00" * (raw_end - len(data)))
    return bytes(data)


def test_section_getitem_and_mock_pe_extended_branches() -> None:
    sec = Section(".text", 0x1000, 0x200, 0x400, 0x200)
    assert sec["name"] == ".text"

    pe32 = MockPE(_build_pe_data(dll=True, magic=0x10B))
    assert pe32.is_pe is True
    assert pe32.is_32bit() is True
    assert pe32.is_64bit() is False
    assert pe32.is_dll() is True
    assert pe32.entry_point == -1
    assert pe32.entry_point_raw == 0x1000
    assert pe32.image_base == 0x400000

    pe64 = MockPE(_build_pe_data(dll=False, magic=0x20B))
    assert pe64.is_32bit() is False
    assert pe64.is_64bit() is True

    pe64.sections = [Section(".text", 0x1000, 0x200, 0x400, 0x200)]
    assert pe64.section_index(".text") == 0
    assert pe64.section_index(".rdata") is YARA_UNDEFINED
    with pytest.raises(EvaluationError, match=r"pe\.section_index\(\) expects a string argument"):
        pe64.section_index(cast(Any, True))

    pe64._import_list = ["kernel32.dll:CreateFileW", "user32.dll:MessageBoxW"]
    assert pe64.imports("kernel32.dll", "CreateFileW") is True
    assert pe64.imports("kernel32.dll", "CloseHandle") is False
    assert pe64.imports("user32.dll") is True
    with pytest.raises(EvaluationError, match=r"pe\.imports\(\) expects string arguments"):
        pe64.imports(cast(Any, True))
    with pytest.raises(EvaluationError, match=r"pe\.imports\(\) expects string arguments"):
        pe64.imports("kernel32.dll", cast(Any, True))

    pe64._export_list = ["ExportedFn"]
    assert pe64.exports("ExportedFn") is True
    assert pe64.exports("Missing") is False
    with pytest.raises(EvaluationError, match=r"pe\.exports\(\) expects a string argument"):
        pe64.exports(cast(Any, True))
    assert pe64.locale(0x409) is False
    assert pe64.language(0x09) is False
    with pytest.raises(EvaluationError, match=r"pe\.locale\(\) expects an integer argument"):
        pe64.locale(cast(Any, True))
    with pytest.raises(EvaluationError, match=r"pe\.language\(\) expects an integer argument"):
        pe64.language(cast(Any, True))
    assert pe64.imphash()


def test_mock_pe_parses_sections_and_resolves_rva_to_offset() -> None:
    data = _build_pe_data(
        dll=False,
        magic=0x10B,
        sections=[
            Section(".text", 0x1000, 0x180, 0x200, 0x200, 0x60000020),
            Section(".rdata", 0x2000, 0x100, 0x400, 0x100, 0x40000040),
        ],
    )

    pe = MockPE(data)

    assert pe.number_of_sections == 2
    assert pe.section_index(".text") == 0
    assert pe.sections[0] == Section(".text", 0x1000, 0x180, 0x200, 0x200, 0x60000020)
    assert pe.rva_to_offset(0x100) == 0x100
    assert pe.rva_to_offset(0x1000) == 0x200
    assert pe.rva_to_offset(0x11FF) == 0x3FF
    assert pe.rva_to_offset(0x1200) is YARA_UNDEFINED
    assert pe.rva_to_offset(-1) is YARA_UNDEFINED
    with pytest.raises(EvaluationError, match=r"pe\.rva_to_offset\(\) expects an integer argument"):
        pe.rva_to_offset(cast(Any, True))


def test_evaluator_supports_pe_rva_to_offset_function() -> None:
    data = _build_pe_data(
        dll=False,
        magic=0x10B,
        sections=[Section(".text", 0x1000, 0x180, 0x200, 0x200, 0x60000020)],
    )
    ast = Parser().parse("""
        import "pe"
        rule valid_pe_rva_to_offset {
            condition:
                pe.rva_to_offset(0x1000) == 0x200 and
                pe.entry_point == 0x200 and
                pe.entry_point_raw == 0x1000
        }

        rule invalid_pe_rva_to_offset {
            condition:
                pe.rva_to_offset(0x1200) == 0
        }
        """)

    assert YaraEvaluator(data=data).evaluate_file(ast) == {
        "valid_pe_rva_to_offset": True,
        "invalid_pe_rva_to_offset": False,
    }


def test_mock_elf_math_dotnet_and_registry_branches() -> None:
    elf_header = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    elf_header += struct.pack(
        "<HHIIIIIHHHHHH",
        3,
        0x3E,
        1,
        0,
        0,
        52,
        0,
        52,
        32,
        0,
        40,
        1,
        0,
    )
    elf_data = elf_header + (b"\x00" * 40)
    elf = MockELF(elf_data)
    assert elf.type == 3
    assert elf.machine == 0x3E
    assert elf.number_of_sections == 1
    assert elf.number_of_segments == 0

    m = MockMath(b"\x00" * 10 + b"\xff" * 10)
    assert m.to_string(10) == "10"
    assert m.to_string(10, 2) is YARA_UNDEFINED
    assert m.to_string(10, 8) == "12"
    assert m.to_string(-10, 16) == "fffffffffffffff6"
    assert m.to_string(-10, 8) == "1777777777777777777766"
    with pytest.raises(EvaluationError, match=r"math\.to_string\(\) expects integer arguments"):
        m.to_string(cast(Any, True))
    with pytest.raises(EvaluationError, match=r"math\.to_string\(\) expects integer arguments"):
        m.to_string(10, cast(Any, "16"))
    with pytest.raises(EvaluationError, match=r"math\.abs\(\) expects integer arguments"):
        m.abs(cast(Any, True))
    with pytest.raises(EvaluationError, match=r"math\.min\(\) expects integer arguments"):
        m.min(cast(Any, False), 2)
    with pytest.raises(EvaluationError, match=r"math\.max\(\) expects integer arguments"):
        m.max(1, cast(Any, True))
    assert m.to_number(True) == 1
    assert m.to_number(False) == 0
    with pytest.raises(EvaluationError, match=r"math\.to_number\(\) expects a boolean argument"):
        m.to_number(cast(Any, "bad"))
    assert m.entropy(-1, 1) is YARA_UNDEFINED
    assert m.entropy(0, 0) == 0.0
    assert m.entropy(1000, 5) is YARA_UNDEFINED
    assert m.mean(-1, 1) is YARA_UNDEFINED
    assert m.mean(10, 100) == 255.0
    assert m.deviation(-1, 1, 0.0) is YARA_UNDEFINED
    with pytest.raises(EvaluationError, match=r"math\.mean\(\) offset and size must be integers"):
        m.mean(cast(Any, True), 1)
    with pytest.raises(
        EvaluationError, match=r"math\.entropy\(\) offset and size must be integers"
    ):
        m.entropy(0, cast(Any, False))
    with pytest.raises(
        EvaluationError,
        match=r"math\.deviation\(\) expects a floating-point mean argument",
    ):
        m.deviation(0, 1, cast(Any, 0))
    assert m.serial_correlation(0, 0) == -100000.0
    assert m.serial_correlation(0, 1) == -100000.0
    assert m.serial_correlation(0, 10) == -100000.0
    assert m.monte_carlo_pi(0, 5) is YARA_UNDEFINED

    dotnet = MockDotNet(b"")
    assert dotnet.version is YARA_UNDEFINED
    assert dotnet.module_name is YARA_UNDEFINED
    assert dotnet.number_of_streams is YARA_UNDEFINED
    assert dotnet.number_of_guids is YARA_UNDEFINED

    registry = MockModuleRegistry()
    assert registry.create_module("missing", b"x") is None
    console = registry.create_module("console", b"abc")
    assert isinstance(console, ConsoleModule)
    assert console.log("x", 1, 1.5) is True
    with pytest.raises(EvaluationError, match=r"console\.log\(\) expects scalar arguments"):
        console.log(cast(Any, True))

    string = StringModule(b"abc")
    assert string.to_int("10") == 10
    assert string.to_int("10", 16) == 16
    assert string.to_int("0x10", 0) == 16
    assert string.to_int("x") is YARA_UNDEFINED
    assert string.to_int("10", 1) is YARA_UNDEFINED
    with pytest.raises(EvaluationError, match=r"string\.to_int\(\) expects a string argument"):
        string.to_int(cast(Any, True))
    with pytest.raises(EvaluationError, match=r"string\.to_int\(\) base must be an integer"):
        string.to_int("10", cast(Any, True))
    with pytest.raises(EvaluationError, match=r"string\.length\(\) expects a string argument"):
        string.length(cast(Any, 1))

    cuckoo = CuckooModule(b"abc")
    cuckoo.network.http_requests = ["http://evil.example/path"]
    cuckoo.network.http_get_requests = ["http://evil.example/path"]
    cuckoo.network.http_post_requests = ["http://post.example/path"]
    cuckoo.network.http_user_agents = ["BadAgent/1.0"]
    cuckoo.network.dns_lookups = ["evil.example"]
    cuckoo.network.hosts = ["192.168.1.1"]
    cuckoo.network.tcp_connections = [("192.168.1.1", 443)]
    cuckoo.network.udp_connections = [("8.8.8.8", 53)]
    cuckoo.registry.key_accesses = [r"\\Software\\Bad"]
    cuckoo.filesystem.file_accesses = [r"C:\\autoexec.bat"]
    cuckoo.sync.mutexes = ["EvilMutexName"]
    assert cuckoo.network.http_request(r"evil\.example") is True
    assert cuckoo.network.http_get(r"evil\.example") is True
    assert cuckoo.network.http_post(r"post\.example") is True
    assert cuckoo.network.http_user_agent("BadAgent") is True
    assert cuckoo.network.dns_lookup(r"evil\.example") is True
    assert cuckoo.network.host(r"192\.168\.1\.1") is True
    assert cuckoo.network.tcp(r"192\.168\.1\.1", 443) is True
    assert cuckoo.network.udp(r"8\.8\.8\.8", 53) is True
    assert cuckoo.registry.key_access("Bad") is True
    assert cuckoo.filesystem.file_access(r"autoexec\.bat") is True
    assert cuckoo.sync.mutex("EvilMutex") is True
    with pytest.raises(EvaluationError, match=r"cuckoo\.network\.tcp\(\) port"):
        cuckoo.network.tcp("host", cast(Any, True))

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
