"""Builder pattern for constructing YARA rules programmatically."""

from yaraast.builder.ast_transformer import (
    CloneTransformer,
    RuleTransformer,
    YaraFileTransformer,
    clone_rule,
    clone_yara_file,
    transform_rule,
    transform_yara_file,
)
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.expression_builder import ExpressionBuilder
from yaraast.builder.file_builder import YaraFileBuilder
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.builder.fluent_file_builder import FluentYaraFileBuilder, yara_file
from yaraast.builder.fluent_rule_builder import FluentRuleBuilder
from yaraast.builder.fluent_rule_presets import (
    document_rule,
    example_rules,
    malware_rule,
    network_rule,
    packed_rule,
    rule,
    trojan_rule,
)
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.builder.rule_builder import RuleBuilder

__all__ = [
    "ConditionBuilder",
    "ExpressionBuilder",
    "FluentConditionBuilder",
    "FluentRuleBuilder",
    "FluentStringBuilder",
    "FluentYaraFileBuilder",
    "HexStringBuilder",
    "RuleBuilder",
    "YaraFileBuilder",
    "clone_rule",
    "clone_yara_file",
    "document_rule",
    "example_rules",
    "malware_rule",
    "network_rule",
    "packed_rule",
    "rule",
    "transform_rule",
    "transform_yara_file",
    "trojan_rule",
    "yara_file",
]
