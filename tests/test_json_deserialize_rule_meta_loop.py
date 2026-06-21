# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for Rule meta deserialization.

The dead ``else: meta = []`` branch was removed from ``_deserialize_rule``:
``_deserialize_required_field(data, "meta", ...)`` already raises when the
"meta" key is absent, so the "meta" key is always present afterwards and a
non-dict/non-list value is always an error (never silently treated as empty).
"""

from __future__ import annotations

from typing import Any

import pytest

from yaraast.errors import SerializationError
from yaraast.parser.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer


def _rule_payload() -> dict[str, Any]:
    ast = Parser('rule r { meta: a = "b" strings: $s = "x" condition: $s }').parse()
    return JsonSerializer().visit_rule(ast.rules[0])


def test_meta_as_list_deserializes() -> None:
    rule = JsonSerializer()._deserialize_rule(_rule_payload())
    assert [(m.key, m.value) for m in rule.meta] == [("a", "b")]


def test_meta_as_dict_deserializes() -> None:
    payload = _rule_payload()
    payload["meta"] = {"k": "v"}
    rule = JsonSerializer()._deserialize_rule(payload)
    assert [(m.key, m.value) for m in rule.meta] == [("k", "v")]


@pytest.mark.parametrize("bad_meta", [None, 5, "x"])
def test_meta_non_list_or_dict_raises(bad_meta: object) -> None:
    payload = _rule_payload()
    payload["meta"] = bad_meta
    with pytest.raises(SerializationError, match="Rule meta must be a list or dictionary"):
        JsonSerializer()._deserialize_rule(payload)


def test_missing_meta_key_raises() -> None:
    payload = _rule_payload()
    del payload["meta"]
    with pytest.raises(SerializationError, match="Rule meta is required"):
        JsonSerializer()._deserialize_rule(payload)
