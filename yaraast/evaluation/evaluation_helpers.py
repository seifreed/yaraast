"""Helper utilities for evaluator."""

from __future__ import annotations

from collections.abc import Callable
import struct


class YaraUndefinedValue:
    """Value returned for YARA expressions whose runtime value is undefined."""

    def __bool__(self) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        return False

    def __ne__(self, other: object) -> bool:
        return False

    def __repr__(self) -> str:
        return "YARA_UNDEFINED"

    __hash__ = object.__hash__


YARA_UNDEFINED = YaraUndefinedValue()


def is_yara_undefined(value: object) -> bool:
    return value is YARA_UNDEFINED


def read_struct(data: bytes, fmt: str, offset: int, size: int) -> int | YaraUndefinedValue:
    if offset < 0 or offset + size > len(data):
        return YARA_UNDEFINED
    return int(struct.unpack(fmt, data[offset : offset + size])[0])


def _read_uint8(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, "B", offset, 1)


def _read_uint16(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, "<H", offset, 2)


def _read_uint32(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, "<I", offset, 4)


def _read_int8(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, "b", offset, 1)


def _read_int16(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, "<h", offset, 2)


def _read_int32(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, "<i", offset, 4)


def _read_uint16_be(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, ">H", offset, 2)


def _read_uint32_be(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, ">I", offset, 4)


def _read_int16_be(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, ">h", offset, 2)


def _read_int32_be(data: bytes, offset: int) -> int | YaraUndefinedValue:
    return read_struct(data, ">i", offset, 4)


BUILTIN_READERS: dict[str, Callable[[bytes, int], int | YaraUndefinedValue]] = {
    "uint8": _read_uint8,
    "uint16": _read_uint16,
    "uint32": _read_uint32,
    "int8": _read_int8,
    "int16": _read_int16,
    "int32": _read_int32,
    "uint8be": _read_uint8,
    "uint16be": _read_uint16_be,
    "uint32be": _read_uint32_be,
    "int8be": _read_int8,
    "int16be": _read_int16_be,
    "int32be": _read_int32_be,
}

LITTLE_ENDIAN_ALIASES: dict[str, str] = {
    "uint16le": "uint16",
    "uint32le": "uint32",
    "int16le": "int16",
    "int32le": "int32",
}
