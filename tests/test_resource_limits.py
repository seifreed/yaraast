"""Regression tests for untrusted-input parsing limits."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

import yaraast
from yaraast.api import DialectName
from yaraast.errors import ParseCancelledError, ResourceLimitError
import yaraast.limits as limits_module
from yaraast.limits import ResourceLimits
from yaraast.lsp.document_context import DocumentContext
from yaraast.parser import Parser
from yaraast.resolution.include_resolver import IncludeResolver


def test_input_token_and_nesting_limits_stop_before_unbounded_parse() -> None:
    with pytest.raises(ResourceLimitError, match="max_input_bytes"):
        yaraast.parse(
            "rule r { condition: true }", resource_limits=ResourceLimits(max_input_bytes=8)
        )

    with pytest.raises(ResourceLimitError, match="max_tokens"):
        yaraast.parse("rule r { condition: true }", resource_limits=ResourceLimits(max_tokens=3))

    with pytest.raises(ResourceLimitError, match="max_nesting_depth"):
        yaraast.parse(
            "rule r { condition: (((true))) }",
            resource_limits=ResourceLimits(max_nesting_depth=2),
        )


@pytest.mark.parametrize(
    ("dialect", "source"),
    [
        ("yara", "rule r { condition: true }"),
        ("yara-x", "rule r { condition: with x = 1: x == 1 }"),
        ("yara-l", 'rule r { events: $e.metadata.event_type = "x" condition: $e }'),
    ],
)
def test_token_limit_is_enforced_by_every_dialect_lexer(dialect: DialectName, source: str) -> None:
    with pytest.raises(ResourceLimitError, match="max_tokens"):
        yaraast.parse(source, dialect=dialect, resource_limits=ResourceLimits(max_tokens=2))


def test_rule_string_regex_and_hex_limits_are_enforced() -> None:
    with pytest.raises(ResourceLimitError, match="max_rules"):
        yaraast.parse(
            "rule one { condition: true } rule two { condition: true }",
            resource_limits=ResourceLimits(max_rules=1),
        )

    with pytest.raises(ResourceLimitError, match="max_strings_per_rule"):
        yaraast.parse(
            'rule r { strings: $a = "a" $b = "b" condition: any of them }',
            resource_limits=ResourceLimits(max_strings_per_rule=1),
        )

    with pytest.raises(ResourceLimitError, match="max_regex_length"):
        yaraast.parse(
            "rule r { strings: $a = /abcdef/ condition: $a }",
            resource_limits=ResourceLimits(max_regex_length=3),
        )

    with pytest.raises(ResourceLimitError, match="max_hex_pattern_length"):
        yaraast.parse(
            "rule r { strings: $a = { 01 02 03 04 } condition: $a }",
            resource_limits=ResourceLimits(max_hex_pattern_length=3),
        )


def test_cancellation_and_deadline_are_cooperative(monkeypatch: pytest.MonkeyPatch) -> None:
    token = yaraast.CancellationToken()
    token.cancel()
    with pytest.raises(ParseCancelledError, match="cancelled"):
        yaraast.parse("rule r { condition: true }", cancellation_token=token)

    ticks = iter([0.0, 2.0])
    monkeypatch.setattr(limits_module, "monotonic", lambda: next(ticks))
    with pytest.raises(ResourceLimitError, match="parse_deadline"):
        yaraast.parse(
            "rule r { condition: true }",
            resource_limits=ResourceLimits(parse_deadline=1.0),
        )


def test_reusable_parser_resets_the_per_operation_budget() -> None:
    parser = Parser(resource_limits=ResourceLimits(max_tokens=10))

    assert len(parser.parse("rule one { condition: true }").rules) == 1
    assert len(parser.parse("rule two { condition: true }").rules) == 1


def test_include_depth_limit_stops_recursive_resolution(tmp_path: Path) -> None:
    (tmp_path / "root.yar").write_text(
        'include "one.yar"\nrule root { condition: true }', encoding="utf-8"
    )
    (tmp_path / "one.yar").write_text(
        'include "two.yar"\nrule one { condition: true }', encoding="utf-8"
    )
    (tmp_path / "two.yar").write_text("rule two { condition: true }", encoding="utf-8")

    resolver = IncludeResolver([str(tmp_path)], resource_limits=ResourceLimits(max_include_depth=1))
    with pytest.raises(ResourceLimitError, match="max_include_depth"):
        resolver.resolve_file("root.yar")


def test_reused_include_resolver_starts_a_new_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "rule.yar").write_text("rule ok { condition: true }", encoding="utf-8")
    now = [0.0]
    monkeypatch.setattr(limits_module, "monotonic", lambda: now[0])
    resolver = IncludeResolver([str(tmp_path)], resource_limits=ResourceLimits(parse_deadline=1.0))

    now[0] = 2.0
    assert resolver.resolve_file("rule.yar").ast.rules[0].name == "ok"


def test_lsp_limit_failure_does_not_publish_a_partial_ast() -> None:
    document = DocumentContext(
        "file:///untrusted.yar",
        "rule too_large { condition: true }",
        resource_limits=ResourceLimits(max_input_bytes=8),
    )

    assert document.ast() is None
    assert isinstance(document.parse_error(), ResourceLimitError)
    assert document.get_cached("analysis") is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_tokens": -1},
        {"max_rules": True},
        {"parse_deadline": 0},
        {"parse_deadline": "soon"},
    ],
)
def test_resource_limits_reject_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        ResourceLimits(**cast(Any, kwargs))
