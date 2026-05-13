"""YARA-X services for CLI (logic without IO)."""

from __future__ import annotations

import re

from yaraast.cli.utils import parse_yara_file
from yaraast.codegen.generator import CodeGenerator
from yaraast.dialects import _strip_string_literals
from yaraast.parser.parser import Parser
from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.generator import YaraXGenerator
from yaraast.yarax.parser import YaraXParser


def parse_yarax_content(content: str):
    parser = YaraXParser(content)
    ast = parser.parse()
    generator = YaraXGenerator()
    return ast, generator.generate(ast)


def parse_yara_file_ast(file_path: str):
    return parse_yara_file(file_path)


def check_yarax_compatibility(ast, strict: bool):
    features = YaraXFeatures.yarax_strict() if strict else YaraXFeatures.yarax_compatible()
    checker = YaraXCompatibilityChecker(features)
    return checker.check(ast)


def convert_yara_to_yarax(content: str) -> str:
    parser = Parser(content)
    ast = parser.parse()
    generator = YaraXGenerator()
    return generator.generate(ast)


def convert_yarax_to_yara(content: str) -> str:
    parser = YaraXParser(content)
    ast = parser.parse()
    checker = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    blocking_features = [
        issue
        for issue in checker.check(ast)
        if issue.issue_type == "yarax_feature" and issue.severity == "error"
    ]
    if blocking_features:
        features = sorted(
            {
                issue.message.split(": ", 1)[1] if ": " in issue.message else issue.message
                for issue in blocking_features
            }
        )
        msg = "Cannot convert YARA-X-only syntax to standard YARA: " + ", ".join(features)
        raise ValueError(msg)
    generator = CodeGenerator()
    return generator.generate(ast)


def detect_yarax_features(content: str) -> list[str]:
    scan_content = _strip_string_literals(content)
    features = []

    if re.search(r"\bwith\s+\$?\w+\s*=", scan_content, re.IGNORECASE):
        features.append("with statements")
    if re.search(r"\[[^\]]+\bfor\s+\w+\s+in\s+[^\]]+\]", scan_content, re.IGNORECASE):
        features.append("array comprehensions")
    if re.search(
        r"\{[^{}:]+:[^{}]+\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+[^{}]+\}",
        scan_content,
        re.IGNORECASE,
    ):
        features.append("dict comprehensions")
    if re.search(r"\blambda(?:\s+\w+(?:\s*,\s*\w+)*)?\s*:", scan_content, re.IGNORECASE):
        features.append("lambda expressions")
    if re.search(r"\bmatch\s+[^{}]+\{[^{}]*=>", scan_content, re.IGNORECASE | re.DOTALL):
        features.append("pattern matching")
    if re.search(r"(?<!\.)\.\.\.(?!\.)|\*\*", scan_content):
        features.append("spread operators")

    return features


def get_default_playground_code() -> str:
    return """
rule yarax_demo {
    meta:
        description = "YARA-X feature demonstration"

    strings:
        $str1 = "test"
        $str2 = /pattern/i

    condition:
        // With statement for local variables
        with $count = #str1, $threshold = 5:
            $count > $threshold and

            // Array comprehension
            any of [s for s in ($str1, $str2) if s]
}
""".lstrip()


def detect_playground_features(content: str) -> list[str]:
    scan_content = _strip_string_literals(content)
    features = []
    if re.search(r"\bwith\s+\$?\w+\s*=", scan_content, re.IGNORECASE):
        features.append("with statements")
    if re.search(r"\[[^\]]+\bfor\s+\w+\s+in\s+[^\]]+\]", scan_content, re.IGNORECASE):
        features.append("comprehensions")
    if re.search(r"\blambda(?:\s+\w+(?:\s*,\s*\w+)*)?\s*:", scan_content, re.IGNORECASE):
        features.append("lambda expressions")
    return features
