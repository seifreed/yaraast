"""Additional tests for enhanced YAML serializer (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import yaml

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, MetaScope
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString, RegexString
from yaraast.serialization.roundtrip_serializer import (
    EnhancedYamlSerializer,
)


def _sample_ast() -> YaraFile:
    rule = Rule(
        name="r1",
        modifiers=["private"],
        tags=[Tag(name="t1")],
        meta={"author": "me"},
        strings=[
            PlainString(identifier="$a", value="x"),
            RegexString(identifier="$b", regex="ab.*"),
        ],
        condition=BooleanLiteral(value=True),
    )
    return YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="inc.yar")],
        rules=[rule],
    )


def test_enhanced_yaml_pipeline_serialization() -> None:
    ast = _sample_ast()
    serializer = EnhancedYamlSerializer(include_pipeline_metadata=True)

    yaml_str = serializer.serialize_for_pipeline(ast, pipeline_info={"build": "1"})
    assert yaml_str.startswith("---")
    assert yaml_str.strip().endswith("...")

    data = yaml.safe_load(yaml_str)
    assert data["pipeline_metadata"]["format"] == "yaraast-pipeline-yaml"
    assert data["statistics"]["total_rules"] == 1


def test_rules_manifest_and_helpers() -> None:
    ast = _sample_ast()

    manifest_yaml = EnhancedYamlSerializer().serialize_rules_manifest(ast)
    manifest = yaml.safe_load(manifest_yaml)

    assert manifest["summary"]["total_rules"] == 1
    assert manifest["rules"][0]["name"] == "r1"

    pipeline_yaml = EnhancedYamlSerializer(include_pipeline_metadata=True).serialize_for_pipeline(
        ast,
        {"env": "ci"},
    )
    pipeline = yaml.safe_load(pipeline_yaml)
    assert pipeline["pipeline_metadata"]["env"] == "ci"


def test_rules_manifest_preserves_meta_scopes() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="scoped_meta",
                meta=[MetaEntry.from_key_value("classification", "restricted", "private")],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    manifest_yaml = EnhancedYamlSerializer().serialize_rules_manifest(ast)
    manifest = yaml.safe_load(manifest_yaml)

    assert manifest["rules"][0]["meta"] == [
        {"key": "classification", "value": "restricted", "scope": "private"}
    ]
    assert "meta_scopes" not in manifest["rules"][0]


def test_rules_manifest_preserves_scoped_meta_float_values() -> None:
    scoped_meta = Meta("score", cast(Any, 1.5))
    cast(Any, scoped_meta).scope = MetaScope.PRIVATE
    ast = YaraFile(
        rules=[
            Rule(
                name="scoped_meta_float",
                meta=[scoped_meta],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    manifest_yaml = EnhancedYamlSerializer().serialize_rules_manifest(ast)
    manifest = yaml.safe_load(manifest_yaml)

    assert manifest["rules"][0]["meta"] == [{"key": "score", "value": 1.5, "scope": "private"}]


def test_rules_manifest_preserves_duplicate_meta_entries() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_meta",
                meta=[
                    MetaEntry.from_key_value("author", "alice"),
                    MetaEntry.from_key_value("author", "bob", "private"),
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    manifest_yaml = EnhancedYamlSerializer().serialize_rules_manifest(ast)
    manifest = yaml.safe_load(manifest_yaml)

    assert manifest["manifest_version"] == "2.0"
    assert manifest["rules"][0]["meta"] == [
        {"key": "author", "value": "alice", "scope": "public"},
        {"key": "author", "value": "bob", "scope": "private"},
    ]
