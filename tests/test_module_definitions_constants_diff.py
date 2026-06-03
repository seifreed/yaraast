"""Differential regression tests for module constants and fields.

These cover false positives where the TypeChecker rejected module
constants/fields that real libyara accepts (e.g. ``pe.MACHINE_AMD64``,
``elf.ET_EXEC``, ``math.MEAN_BYTES``, ``dotnet.is_dotnet``). When
yara-python is installed the same accesses are cross-checked against
libyara to guarantee the spec stays aligned with the engine.
"""

from __future__ import annotations

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE
from yaraast.parser import Parser
from yaraast.types import TypeChecker

# (module, access expression) pairs that libyara accepts and real rules use.
ACCEPTED_ACCESSES: list[tuple[str, str]] = [
    # pe machine / subsystem / characteristics constants
    ("pe", "pe.MACHINE_AMD64"),
    ("pe", "pe.MACHINE_I386"),
    ("pe", "pe.MACHINE_ARM64"),
    ("pe", "pe.SUBSYSTEM_WINDOWS_GUI"),
    ("pe", "pe.SUBSYSTEM_NATIVE"),
    ("pe", "pe.DLL"),
    ("pe", "pe.EXECUTABLE_IMAGE"),
    ("pe", "pe.RELOCS_STRIPPED"),
    # pe section / resource / directory / import constants
    ("pe", "pe.SECTION_MEM_EXECUTE"),
    ("pe", "pe.SECTION_CNT_CODE"),
    ("pe", "pe.RESOURCE_TYPE_VERSION"),
    ("pe", "pe.RESOURCE_TYPE_MANIFEST"),
    ("pe", "pe.IMAGE_DIRECTORY_ENTRY_IMPORT"),
    ("pe", "pe.IMPORT_DELAYED"),
    ("pe", "pe.DYNAMIC_BASE"),
    # pe fields
    ("pe", "pe.checksum"),
    ("pe", "pe.subsystem"),
    ("pe", "pe.dll_characteristics"),
    ("pe", "pe.size_of_image"),
    ("pe", "pe.size_of_code"),
    ("pe", "pe.pdb_path"),
    ("pe", "pe.dll_name"),
    ("pe", "pe.export_timestamp"),
    ("pe", "pe.number_of_imports"),
    ("pe", "pe.number_of_imported_functions"),
    ("pe", "pe.number_of_delayed_imports"),
    ("pe", "pe.number_of_version_infos"),
    ("pe", "pe.opthdr_magic"),
    ("pe", "pe.win32_version_value"),
    ("pe", "pe.loader_flags"),
    ("pe", "pe.base_of_code"),
    ("pe", "pe.size_of_headers"),
    ("pe", "pe.size_of_stack_reserve"),
    ("pe", "pe.linker_version.major"),
    ("pe", "pe.os_version.major"),
    ("pe", "pe.image_version.major"),
    ("pe", "pe.subsystem_version.major"),
    ("pe", "pe.resources[0].length"),
    ("pe", "pe.resources[0].type"),
    ("pe", "pe.resources[0].id"),
    ("pe", "pe.resources[0].language"),
    ("pe", "pe.data_directories[0].virtual_address"),
    ("pe", "pe.data_directories[0].size"),
    ("pe", "pe.version_info_list[0].key"),
    ("pe", "pe.version_info_list[0].value"),
    # elf type / machine / section / segment / dynamic / symbol constants
    ("elf", "elf.ET_EXEC"),
    ("elf", "elf.ET_DYN"),
    ("elf", "elf.EM_X86_64"),
    ("elf", "elf.EM_ARM"),
    ("elf", "elf.SHT_SYMTAB"),
    ("elf", "elf.SHF_EXECINSTR"),
    ("elf", "elf.PT_LOAD"),
    ("elf", "elf.DT_NEEDED"),
    ("elf", "elf.STT_FUNC"),
    ("elf", "elf.STB_GLOBAL"),
    # elf entry-count fields
    ("elf", "elf.symtab_entries"),
    ("elf", "elf.dynsym_entries"),
    ("elf", "elf.dynamic_section_entries"),
    # math constant
    ("math", "math.MEAN_BYTES"),
    # dotnet fields
    ("dotnet", "dotnet.is_dotnet"),
    ("dotnet", "dotnet.typelib"),
    ("dotnet", "dotnet.number_of_classes"),
    ("dotnet", "dotnet.number_of_assembly_refs"),
    ("dotnet", "dotnet.number_of_modulerefs"),
    ("dotnet", "dotnet.number_of_field_offsets"),
    ("dotnet", "dotnet.number_of_constants"),
    ("dotnet", "dotnet.classes[0].name"),
    ("dotnet", "dotnet.classes[0].namespace"),
    ("dotnet", "dotnet.classes[0].fullname"),
    ("dotnet", "dotnet.field_offsets[0]"),
    ("dotnet", "dotnet.constants[0]"),
    ("dotnet", "dotnet.modulerefs[0]"),
]

# Accesses that are genuinely undefined: the validator must keep rejecting
# them so the fix does not introduce false negatives.
REJECTED_ACCESSES: list[tuple[str, str]] = [
    ("pe", "pe.zzz_not_a_field"),
    ("pe", "pe.MACHINE_NOPE"),
    ("elf", "elf.NOPE_X"),
    ("math", "math.NOPE"),
    ("dotnet", "dotnet.not_a_field"),
]


def _attribute_errors(module: str, access: str) -> list[str]:
    source = f'import "{module}"\nrule t {{ condition: ({access}) == ({access}) }}'
    ast = Parser().parse(source)
    errors = TypeChecker().check(ast)
    return [
        e for e in errors if "has no attribute" in e or "no field" in e or "Unknown module" in e
    ]


@pytest.mark.parametrize(("module", "access"), ACCEPTED_ACCESSES)
def test_common_module_access_is_accepted(module: str, access: str) -> None:
    assert _attribute_errors(module, access) == []


@pytest.mark.parametrize(("module", "access"), REJECTED_ACCESSES)
def test_undefined_module_access_is_still_rejected(module: str, access: str) -> None:
    assert _attribute_errors(module, access) != []


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
@pytest.mark.parametrize(("module", "access"), ACCEPTED_ACCESSES)
def test_accepted_access_matches_libyara(module: str, access: str) -> None:
    import yara

    source = f'import "{module}"\nrule t {{ condition: ({access}) == ({access}) }}'
    yara.compile(source=source)
    assert _attribute_errors(module, access) == []
