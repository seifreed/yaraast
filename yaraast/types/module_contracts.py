"""Shared module definition contracts for the YARA type system."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._registry_base import YaraType


@dataclass
class FunctionDefinition:
    """Definition of a module function."""

    name: str
    return_type: YaraType
    parameters: list[tuple[str, YaraType]] = field(default_factory=list)


@dataclass
class ModuleDefinition:
    """Definition of a YARA module."""

    name: str
    attributes: dict[str, YaraType] = field(default_factory=dict)
    functions: dict[str, FunctionDefinition] = field(default_factory=dict)
    constants: dict[str, YaraType] = field(default_factory=dict)
