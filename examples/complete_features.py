#!/usr/bin/env python3
"""Example demonstrating all YARAAST features."""

import json
import os
from pathlib import Path

from yaraast import (
    YARA_SYNTAX_VERSION,
    YARAAST_VERSION,
    HexStringBuilder,
    Parser,
    RuleBuilder,
    get_version_info,
)
from yaraast.analysis import RuleAnalyzer
from yaraast.codegen.advanced_generator import AdvancedCodeGenerator
from yaraast.codegen.formatting import FormattingConfig
from yaraast.optimization import RuleOptimizer
from yaraast.types.module_loader import ModuleLoader
from yaraast.yarax import YaraXCompatibilityChecker, YaraXSyntaxAdapter


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def demo_version_info():
    """Demonstrate version information."""
    print_section("Version Information")

    print(f"YARAAST Version: {YARAAST_VERSION}")
    print(f"YARA Syntax Version: {YARA_SYNTAX_VERSION}")
    print()
    print("Detailed version info:")
    info = get_version_info()
    for component, details in info.items():
        print(f"\n{component}:")
        for key, value in details.items():
            print(f"  {key}: {value}")


def demo_module_loading():
    """Demonstrate JSON module loading."""
    print_section("Module Loading from JSON")

    # Create a custom module JSON
    custom_module = {
        "name": "demo_module",
        "description": "Demo module for example",
        "attributes": {
            "version": "string",
            "config": {
                "type": "struct",
                "fields": {
                    "enabled": "bool",
                    "threshold": "int"
                }
            }
        },
        "functions": {
            "analyze": {
                "return": "int",
                "parameters": [
                    {"name": "data", "type": "string"},
                    {"name": "mode", "type": "int"}
                ]
            }
        },
        "constants": {
            "MAX_SIZE": "int",
            "VERSION": "string"
        }
    }

    # Save to temporary file
    with open("demo_module.json", "w") as f:
        json.dump(custom_module, f, indent=2)

    # Load module
    os.environ["YARAAST_MODULE_SPEC_PATH"] = "."
    loader = ModuleLoader()

    print("Available modules:")
    for module_name in loader.list_modules():
        print(f"  - {module_name}")

    # Check if our module was loaded
    if "demo_module" in loader.modules:
        module = loader.get_module("demo_module")
        print(f"\nDemo module loaded successfully!")
        print(f"  Attributes: {list(module.attributes.keys())}")
        print(f"  Functions: {list(module.functions.keys())}")
        print(f"  Constants: {list(module.constants.keys())}")

    # Clean up
    os.remove("demo_module.json")
    del os.environ["YARAAST_MODULE_SPEC_PATH"]


def demo_complete_features():
    """Demonstrate all features in one comprehensive example."""
    print_section("Complete Feature Demonstration")

    # 1. Build a complex rule using fluent API
    rule = (RuleBuilder()
        .with_name("comprehensive_malware_detector")
        .private()
        .global_()
        .with_tags(["malware", "trojan", "advanced"])
        .with_meta("author", "YARAAST Demo")
        .with_meta("description", "Demonstrates all YARAAST features")
        .with_meta("version", 1)
        .with_plain_string("$mz", "MZ", ascii=True, wide=True)
        .with_plain_string("$suspicious", "malicious", nocase=True)
        .with_hex_string("$hex_pattern",
            HexStringBuilder()
                .add_bytes(0x4D, 0x5A)  # MZ
                .nibble("F?")           # High nibble
                .wildcard(4)            # ?? ?? ?? ??
                .jump(10, 20)           # [10-20]
                .alternative(
                    [0x50, 0x45],     # PE
                    [0x4E, 0x45]      # NE
                )
        )
        .with_regex_string("$url", r"https?://[a-z0-9\.\-]+", nocase=True)
        .with_condition("""
            $mz at 0 and
            $hex_pattern and
            (#suspicious > 5 or @suspicious[1] < 100) and
            $url and
            pe.number_of_sections > 3 and
            defined pe.version_info["CompanyName"] and
            pe.version_info["CompanyName"] icontains "microsoft"
        """)
        .build()
    )

    # Convert to YARA file format
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Import

    yara_file = YaraFile(
        imports=[Import(module="pe"), Import(module="math")],
        rules=[rule]
    )

    # 2. Analyze the rule
    print("\n--- Rule Analysis ---")
    analyzer = RuleAnalyzer()
    analysis = analyzer.analyze(yara_file)

    print(f"Total strings: {analysis['summary']['total_strings']}")
    print(f"String usage efficiency: {analysis['quality_metrics']['string_usage_efficiency']:.0%}")
    print(f"Quality score: {analysis['quality_metrics']['overall_quality_score']}/100")

    # 3. Optimize the rule
    print("\n--- Optimization ---")
    optimizer = RuleOptimizer()
    optimized, stats = optimizer.optimize(yara_file)
    print(f"Optimizations performed: {stats['total_optimizations']}")

    # 4. Check YARA-X compatibility
    print("\n--- YARA-X Compatibility ---")
    checker = YaraXCompatibilityChecker()
    issues = checker.check(optimized)
    report = checker.get_report()

    print(f"Compatible with YARA-X: {report['compatible']}")
    print(f"Total issues: {report['total_issues']}")
    print(f"Migration difficulty: {report['migration_difficulty']}")

    # 5. Generate code with different formats
    print("\n--- Code Generation (Multiple Styles) ---")

    # Compact style
    print("\nCompact Style:")
    compact_gen = AdvancedCodeGenerator(FormattingConfig.compact())
    print(compact_gen.generate(optimized))

    # Expanded style
    print("\nExpanded Style:")
    expanded_gen = AdvancedCodeGenerator(FormattingConfig.expanded())
    print(expanded_gen.generate(optimized))

    # Custom style with sorting
    print("\nCustom Style (sorted):")
    custom_config = FormattingConfig(
        indent_size=2,
        sort_imports=True,
        sort_strings=True,
        sort_meta=True,
        string_style=FormattingConfig.StringStyle.TABULAR
    )
    custom_gen = AdvancedCodeGenerator(custom_config)
    print(custom_gen.generate(optimized))


def demo_optimization():
    """Demonstrate optimization capabilities."""
    print_section("Expression Optimization")

    # Create a rule with optimizable expressions
    yara_code = """
rule optimization_demo {
    strings:
        $used = "used"
        $unused1 = "not used"
        $unused2 = { 00 01 02 }

    condition:
        (true and $used) and          // true and X => X
        (false or $used) and          // false or X => X
        not (not $used) and           // not not X => X
        (2 + 3 == 5) and             // constant folding
        (10 > 5) and                 // constant comparison
        ($used or false)             // X or false => X
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    print("Original rule:")
    gen = AdvancedCodeGenerator()
    print(gen.generate(ast))

    # Optimize
    optimizer = RuleOptimizer()
    optimized, stats = optimizer.optimize(ast)

    print("\nOptimized rule:")
    print(gen.generate(optimized))

    print(f"\nOptimization statistics:")
    print(f"  Expression optimizations: {stats['expression_optimizations']}")
    print(f"  Dead code eliminations: {stats['dead_code_eliminations']}")
    print(f"  Total optimizations: {stats['total_optimizations']}")


def main():
    """Run all demonstrations."""
    print("YARAAST - Complete Feature Demonstration")
    print("========================================")

    # Show version info
    demo_version_info()

    # Show module loading
    demo_module_loading()

    # Show complete features
    demo_complete_features()

    # Show optimization
    demo_optimization()

    print("\n✅ All features demonstrated successfully!")


if __name__ == "__main__":
    main()
