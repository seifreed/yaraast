# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests guarding ExternImport whitespace validation.

The redundant ``.strip()`` re-checks in ``convert_extern_import_to_protobuf``
and ``protobuf_to_extern_import`` were removed because the shared validators
(``_protobuf_required_nonempty_string`` / ``_protobuf_nonempty_string_list``)
already reject whitespace-only values for these non-regex contexts. These
tests pin that behaviour so the validator stays the single enforcement point.
"""

from __future__ import annotations

import pytest

from yaraast.ast.extern import ExternImport
from yaraast.errors import SerializationError
from yaraast.serialization import yara_ast_pb2
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.protobuf_conversion import (
    convert_extern_import_to_protobuf,
    protobuf_to_extern_import,
)
from yaraast.serialization.simple_roundtrip_helpers import (
    deserialize_node,
    serialize_node,
)


class TestSerializeExternImportWhitespace:
    """Serializing an ExternImport with whitespace-only fields must raise."""

    def test_module_path_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="   ", alias=None, rules=["good"])
        pb = yara_ast_pb2.ExternImport()
        with pytest.raises(SerializationError, match="module_path must not be empty"):
            convert_extern_import_to_protobuf(obj, pb)

    def test_alias_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="mod", alias="   ", rules=["good"])
        pb = yara_ast_pb2.ExternImport()
        with pytest.raises(SerializationError, match="alias must not be empty"):
            convert_extern_import_to_protobuf(obj, pb)

    def test_rule_item_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="mod", alias=None, rules=["   "])
        pb = yara_ast_pb2.ExternImport()
        with pytest.raises(SerializationError, match="rules item must not be empty"):
            convert_extern_import_to_protobuf(obj, pb)

    def test_valid_extern_import_roundtrips(self) -> None:
        obj = ExternImport(module_path="mod", alias="al", rules=["r1", "r2"])
        pb = yara_ast_pb2.ExternImport()
        convert_extern_import_to_protobuf(obj, pb)
        assert pb.module_path == "mod"
        assert pb.alias == "al"
        assert list(pb.rules) == ["r1", "r2"]


class TestDeserializeExternImportWhitespace:
    """Deserializing a protobuf ExternImport with whitespace fields must raise."""

    def test_module_path_whitespace_raises(self) -> None:
        pb = yara_ast_pb2.ExternImport()
        pb.module_path = "   "
        pb.rules.append("good")
        with pytest.raises(SerializationError, match="module_path must not be empty"):
            protobuf_to_extern_import(pb)

    def test_rule_item_whitespace_raises(self) -> None:
        pb = yara_ast_pb2.ExternImport()
        pb.module_path = "mod"
        pb.rules.append("   ")
        with pytest.raises(SerializationError, match="rules item must not be empty"):
            protobuf_to_extern_import(pb)

    def test_alias_whitespace_raises(self) -> None:
        # The deserialize alias check is the only reachable whitespace guard
        # (alias bypasses _protobuf_required_nonempty_string via "or None").
        pb = yara_ast_pb2.ExternImport()
        pb.module_path = "mod"
        pb.alias = "   "
        pb.rules.append("good")
        with pytest.raises(SerializationError, match="alias must not be empty"):
            protobuf_to_extern_import(pb)

    def test_valid_protobuf_roundtrips(self) -> None:
        pb = yara_ast_pb2.ExternImport()
        pb.module_path = "mod"
        pb.alias = "al"
        pb.rules.extend(["r1", "r2"])
        result = protobuf_to_extern_import(pb)
        assert result.module_path == "mod"
        assert result.alias == "al"
        assert list(result.rules) == ["r1", "r2"]


class TestJsonRoundtripExternImportWhitespace:
    """JSON serialize/deserialize must reject whitespace-only ExternImport fields.

    The redundant ``.strip()`` guards in ``simple_roundtrip_helpers`` were
    removed; the shared ``_serialize_*`` / ``_deserialize_*`` nonempty helpers
    are the single enforcement point.
    """

    def test_serialize_module_path_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="  ", alias=None, rules=["good"])
        with pytest.raises(SerializationError, match="module_path must not be empty"):
            serialize_node(obj)

    def test_serialize_alias_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="mod", alias="  ", rules=["good"])
        with pytest.raises(SerializationError, match="alias must not be empty"):
            serialize_node(obj)

    def test_serialize_rule_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="mod", alias=None, rules=["  "])
        with pytest.raises(SerializationError, match="rules must contain non-empty"):
            serialize_node(obj)

    def test_deserialize_module_path_whitespace_raises(self) -> None:
        data = {"type": "ExternImport", "module_path": "  ", "alias": None, "rules": ["good"]}
        with pytest.raises(SerializationError, match="module_path must not be empty"):
            deserialize_node(data)

    def test_deserialize_alias_whitespace_raises(self) -> None:
        data = {"type": "ExternImport", "module_path": "mod", "alias": "  ", "rules": ["good"]}
        with pytest.raises(SerializationError, match="alias must not be empty"):
            deserialize_node(data)

    def test_deserialize_rule_whitespace_raises(self) -> None:
        data = {"type": "ExternImport", "module_path": "mod", "alias": None, "rules": ["  "]}
        with pytest.raises(SerializationError, match="rules must contain non-empty"):
            deserialize_node(data)

    def test_valid_json_roundtrips(self) -> None:
        obj = ExternImport(module_path="mod", alias="al", rules=["r1", "r2"])
        restored = deserialize_node(serialize_node(obj))
        assert isinstance(restored, ExternImport)
        assert restored.module_path == "mod"
        assert restored.alias == "al"
        assert list(restored.rules) == ["r1", "r2"]


class TestJsonSerializerExternImportWhitespace:
    """JsonSerializer.visit_extern_import must reject whitespace-only fields.

    The redundant ``.strip()`` guards were removed; the shared
    ``_serialize_*nonempty*`` helpers reject whitespace via
    ``_is_empty_nonempty_text`` for non-regex contexts.
    """

    def test_module_path_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="  ", alias=None, rules=["good"])
        with pytest.raises(SerializationError, match="module_path must not be empty"):
            JsonSerializer().visit_extern_import(obj)

    def test_alias_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="mod", alias="  ", rules=["good"])
        with pytest.raises(SerializationError, match="alias must not be empty"):
            JsonSerializer().visit_extern_import(obj)

    def test_rule_whitespace_raises(self) -> None:
        obj = ExternImport(module_path="mod", alias=None, rules=["  "])
        with pytest.raises(SerializationError, match="rules must contain non-empty"):
            JsonSerializer().visit_extern_import(obj)

    def test_valid_serializes(self) -> None:
        obj = ExternImport(module_path="mod", alias="al", rules=["r1", "r2"])
        result = JsonSerializer().visit_extern_import(obj)
        assert result["type"] == "ExternImport"
        assert result["module_path"] == "mod"
        assert result["alias"] == "al"
        assert result["rules"] == ["r1", "r2"]
