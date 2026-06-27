"""Coverage for YARA-L AST node validation helpers and rule classification."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.yaral import ast_nodes as nodes
from yaraast.yaral.parser import YaraLParser


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda: nodes._require_yaral_node(123, "f", nodes.MetaEntry, "MetaEntry"), "must be a"),
        (
            lambda: nodes._require_yaral_node_sequence("x", "f", nodes.MetaEntry, "MetaEntry"),
            "must be a list",
        ),
        (lambda: nodes._require_yaral_string_sequence("x", "f"), "must be a list"),
        (lambda: nodes._require_yaral_int(True, "f"), "must be an integer"),
        (lambda: nodes._require_yaral_int("x", "f"), "must be an integer"),
        (lambda: nodes._validate_yaral_value(object(), "f"), "must be a YARA-L value"),
    ],
)
def test_yaral_validation_helpers_reject_bad_types(
    call: Callable[[], object],
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        call()


def test_meta_entry_rejects_non_scalar_value() -> None:
    with pytest.raises(TypeError, match="must be a string, integer, or boolean"):
        nodes.MetaEntry(key="k", value=cast(Any, [1, 2])).validate_structure()


def test_rule_type_without_events_is_single_event() -> None:
    assert nodes.YaraLRule(name="x").rule_type == "single_event"


def test_rule_type_single_and_multi_event() -> None:
    single = YaraLParser(
        'rule s {\n  events:\n    $e.metadata.event_type = "A"\n  condition:\n    $e\n}'
    ).parse()
    assert single.rules[0].rule_type == "single_event"

    multi = YaraLParser(
        "rule m {\n"
        "  events:\n"
        '    $e1.metadata.event_type = "A"\n'
        '    $e2.metadata.event_type = "B"\n'
        "  condition:\n"
        "    $e1 and $e2\n"
        "}"
    ).parse()
    assert multi.rules[0].rule_type == "multi_event"
