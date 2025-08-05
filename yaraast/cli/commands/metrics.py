"""CLI commands for metrics and visualization."""

import contextlib
import json
from pathlib import Path

import click

from yaraast.metrics import (
    ComplexityAnalyzer,
    DependencyGraphGenerator,
    HtmlTreeGenerator,
    StringDiagramGenerator,
)
from yaraast.parser import Parser


@click.group()
def metrics():
    """Analyze and visualize YARA AST metrics."""


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file for metrics report")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
@click.option("--quality-gate", type=int, default=70, help="Quality gate threshold (0-100)")
def complexity(yara_file: str, output: str | None, format: str, quality_gate: int):
    """Analyze YARA rule complexity metrics."""
    with Path(yara_file).open() as f:
        content = f.read()
    parser = Parser()
    ast = parser.parse(content)

    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)

    if format == "json":
        result = metrics.to_dict()
        result["quality_score"] = metrics.get_quality_score()
        result["quality_grade"] = metrics.get_complexity_grade()

        output_text = json.dumps(result, indent=2)
    else:
        output_text = _format_complexity_text(metrics)

    if output:
        with Path(output).open("w") as f:
            f.write(output_text)
        click.echo(f"Complexity metrics written to {output}")
    else:
        click.echo(output_text)

    # Quality gate check
    quality_score = metrics.get_quality_score()
    if quality_score < quality_gate:
        click.echo(f"\n⚠️  Quality gate warning: {quality_score:.1f} < {quality_gate}", err=True)
        # Don't exit with error - just warn
    else:
        click.echo(f"\n✅ Quality gate passed: {quality_score:.1f} >= {quality_gate}")


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["svg", "png", "pdf", "dot"]),
    default="svg",
    help="Output format",
)
@click.option(
    "--type",
    "-t",
    type=click.Choice(["full", "rules", "modules", "complexity"]),
    default="full",
    help="Graph type to generate",
)
@click.option(
    "--engine",
    type=click.Choice(["dot", "neato", "fdp", "circo"]),
    default="dot",
    help="GraphViz layout engine",
)
def graph(yara_file: str, output: str | None, format: str, type: str, engine: str):
    """Generate dependency graphs with GraphViz."""
    with Path(yara_file).open() as f:
        content = f.read()
    parser = Parser()
    ast = parser.parse(content)

    generator = DependencyGraphGenerator()

    # Determine output path
    if not output:
        base_name = Path(yara_file).stem
        output = f"{base_name}_graph_{type}.{format}"

    try:
        if type == "full":
            result_path = generator.generate_graph(ast, output, format, engine)
        elif type == "rules":
            result_path = generator.generate_rule_graph(ast, output, format)
        elif type == "modules":
            result_path = generator.generate_module_graph(ast, output, format)
        elif type == "complexity":
            # Need complexity metrics first
            analyzer = ComplexityAnalyzer()
            metrics = analyzer.analyze(ast)
            result_path = generator.generate_complexity_graph(
                ast, metrics.cyclomatic_complexity, output, format
            )

        if isinstance(result_path, str) and Path(result_path).exists():
            click.echo(f"Dependency graph generated: {result_path}")

            # Show stats
            stats = generator.get_dependency_stats()
            click.echo("\n📊 Graph Statistics:")
            click.echo(f"  Rules: {stats['total_rules']}")
            click.echo(f"  Imports: {stats['total_imports']}")
            click.echo(f"  Rules with strings: {stats['rules_with_strings']}")
            click.echo(f"  Rules using modules: {stats['rules_using_modules']}")
    except Exception as e:
        if (
            "No such file or directory: PosixPath('dot')" in str(e)
            or "ExecutableNotFound" in str(e)
            or "failed to execute PosixPath('dot')" in str(e)
        ):
            # Graphviz not installed, generate text representation
            click.echo("⚠️ Graphviz not installed. Generating text representation instead...\n")

            # Analyze dependencies
            generator.visit(ast)
            stats = generator.get_dependency_stats()

            click.echo("📊 Dependency Analysis (Text Mode):")
            click.echo("=" * 50)
            click.echo(f"\n📁 File: {yara_file}")
            click.echo(f"  Total Rules: {stats['total_rules']}")
            click.echo(f"  Total Imports: {stats['total_imports']}")
            click.echo(f"  Rules with strings: {stats['rules_with_strings']}")
            click.echo(f"  Rules using modules: {stats['rules_using_modules']}")

            if generator.dependencies:
                click.echo("\n🔗 Rule Dependencies:")
                for rule, deps in generator.dependencies.items():
                    if deps:
                        click.echo(f"  {rule} → {', '.join(deps)}")

            if generator.module_references:
                click.echo("\n📦 Module Usage:")
                for rule, modules in generator.module_references.items():
                    if modules:
                        click.echo(f"  {rule} uses: {', '.join(modules)}")

            click.echo("\n💡 To generate visual graphs, install Graphviz:")
            click.echo("  macOS: brew install graphviz")
            click.echo("  Ubuntu: apt-get install graphviz")
            click.echo("  Windows: https://graphviz.org/download/")
        else:
            raise
    else:
        click.echo("Graph source:")
        click.echo(result_path)


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output HTML file path")
@click.option("--interactive", is_flag=True, help="Generate interactive HTML with search")
@click.option("--title", default="YARA AST Visualization", help="Page title")
@click.option("--no-metadata", is_flag=True, help="Exclude metadata from visualization")
@click.option("--collapsible", is_flag=True, help="Generate collapsible tree")
def tree(
    yara_file: str,
    output: str | None,
    interactive: bool,
    title: str,
    no_metadata: bool,
    collapsible: bool,
):
    """Generate HTML collapsible tree visualization."""
    with Path(yara_file).open() as f:
        content = f.read()
    parser = Parser()
    ast = parser.parse(content)

    generator = HtmlTreeGenerator(include_metadata=not no_metadata)

    # Determine output path
    if not output:
        base_name = Path(yara_file).stem
        suffix = "interactive" if interactive else "tree"
        output = f"{base_name}_{suffix}.html"

    if interactive:
        generator.generate_interactive_html(ast, output, title)
    else:
        generator.generate_html(ast, output, title)

    click.echo(f"HTML tree visualization generated: {output}")

    # Show file size
    if Path(output).exists():
        size = Path(output).stat().st_size
        click.echo(f"File size: {size:,} bytes")


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--type",
    "-t",
    type=click.Choice(["flow", "complexity", "similarity", "hex"]),
    default="flow",
    help="Diagram type to generate",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["svg", "png", "pdf", "dot"]),
    default="svg",
    help="Output format",
)
@click.option("--stats", is_flag=True, help="Show pattern statistics")
def patterns(yara_file: str, output: str | None, type: str, format: str, stats: bool):
    """Generate string pattern analysis diagrams."""
    with Path(yara_file).open() as f:
        content = f.read()
    parser = Parser()
    ast = parser.parse(content)

    generator = StringDiagramGenerator()

    # Determine output path
    if not output:
        base_name = Path(yara_file).stem
        output = f"{base_name}_patterns_{type}.{format}"

    try:
        if type == "flow":
            result_path = generator.generate_pattern_flow_diagram(ast, output, format)
        elif type == "complexity":
            result_path = generator.generate_pattern_complexity_diagram(ast, output, format)
        elif type == "similarity":
            result_path = generator.generate_pattern_similarity_diagram(ast, output, format)
        elif type == "hex":
            result_path = generator.generate_hex_pattern_diagram(ast, output, format)

        if isinstance(result_path, str) and Path(result_path).exists():
            click.echo(f"Pattern diagram generated: {result_path}")
        else:
            click.echo("Diagram source:")
            click.echo(result_path)
    except Exception as e:
        if (
            "No such file or directory: PosixPath('dot')" in str(e)
            or "ExecutableNotFound" in str(e)
            or "failed to execute PosixPath('dot')" in str(e)
        ):
            # Graphviz not installed, generate text representation
            click.echo("⚠️ Graphviz not installed. Generating text analysis instead...\n")

            # Analyze patterns
            generator._analyze_patterns(ast)

            click.echo("📊 String Pattern Analysis (Text Mode):")
            click.echo("=" * 50)

            # Show pattern breakdown
            plain_count = 0
            hex_count = 0
            regex_count = 0

            for rule in ast.rules:
                if rule.strings:
                    click.echo(f"\n📁 Rule: {rule.name}")
                    for string_def in rule.strings:
                        if hasattr(string_def, "value"):  # Plain string
                            plain_count += 1
                            click.echo(
                                f'  📝 {string_def.identifier}: "{string_def.value[:30]}..."'
                                if len(str(string_def.value)) > 30
                                else f'  📝 {string_def.identifier}: "{string_def.value}"'
                            )
                        elif hasattr(string_def, "tokens"):  # Hex string
                            hex_count += 1
                            click.echo(
                                f"  🔢 {string_def.identifier}: HEX pattern ({len(string_def.tokens)} tokens)"
                            )
                        elif hasattr(string_def, "regex"):  # Regex string
                            regex_count += 1
                            click.echo(f"  🔍 {string_def.identifier}: /{string_def.regex}/")

            click.echo("\n📈 Summary:")
            click.echo(f"  Total strings: {plain_count + hex_count + regex_count}")
            click.echo(f"  Plain strings: {plain_count}")
            click.echo(f"  Hex patterns: {hex_count}")
            click.echo(f"  Regex patterns: {regex_count}")

            click.echo("\n💡 To generate visual diagrams, install Graphviz:")
            click.echo("  macOS: brew install graphviz")
            click.echo("  Ubuntu: apt-get install graphviz")
            click.echo("  Windows: https://graphviz.org/download/")
        else:
            raise

    # Show pattern statistics if requested
    if stats:
        try:
            pattern_stats = generator.get_pattern_statistics()
            if pattern_stats:
                click.echo("\n📊 Pattern Statistics:")
                click.echo(f"  Total patterns: {pattern_stats['total_patterns']}")
                click.echo(f"  By type: {pattern_stats['by_type']}")
                click.echo(f"  Complexity distribution: {pattern_stats['complexity_distribution']}")

                if pattern_stats.get("pattern_lengths"):
                    lengths = pattern_stats["pattern_lengths"]
                    click.echo(
                        f"  Length stats: min={lengths['min']}, max={lengths['max']}, avg={lengths['avg']:.1f}"
                    )
        except Exception:
            pass  # Statistics might not be available without full analysis


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output-dir", "-d", type=click.Path(), help="Output directory for all reports")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["svg", "png"]),
    default="svg",
    help="Image format for graphs",
)
def report(yara_file: str, output_dir: str | None, format: str):
    """Generate comprehensive metrics report with all visualizations."""
    with Path(yara_file).open() as f:
        content = f.read()
    parser = Parser()
    ast = parser.parse(content)

    # Setup output directory
    if not output_dir:
        output_dir = Path(yara_file).stem + "_metrics_report"

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    base_name = Path(yara_file).stem

    click.echo(f"Generating comprehensive metrics report in {output_path}/")

    # 1. Complexity Analysis
    click.echo("📊 Analyzing complexity...")
    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)

    # Save complexity report
    complexity_report = metrics.to_dict()
    complexity_report["quality_score"] = metrics.get_quality_score()
    complexity_report["quality_grade"] = metrics.get_complexity_grade()

    with Path(output_path / f"{base_name}_complexity.json").open("w") as f:
        json.dump(complexity_report, f, indent=2)

    with Path(output_path / f"{base_name}_complexity.txt").open("w") as f:
        f.write(_format_complexity_text(metrics))

    # 2. Dependency Graphs
    click.echo("🕸️  Generating dependency graphs...")
    dep_generator = DependencyGraphGenerator()

    dep_generator.generate_graph(
        ast, str(output_path / f"{base_name}_dependencies.{format}"), format
    )
    dep_generator.generate_rule_graph(ast, str(output_path / f"{base_name}_rules.{format}"), format)
    dep_generator.generate_complexity_graph(
        ast,
        metrics.cyclomatic_complexity,
        str(output_path / f"{base_name}_complexity_graph.{format}"),
        format,
    )

    # 3. HTML Tree
    click.echo("🌳 Generating HTML tree...")
    tree_generator = HtmlTreeGenerator()
    tree_generator.generate_interactive_html(ast, str(output_path / f"{base_name}_tree.html"))

    # 4. Pattern Diagrams
    click.echo("🧩 Generating pattern diagrams...")
    pattern_generator = StringDiagramGenerator()

    pattern_generator.generate_pattern_flow_diagram(
        ast, str(output_path / f"{base_name}_pattern_flow.{format}"), format
    )
    pattern_generator.generate_pattern_complexity_diagram(
        ast, str(output_path / f"{base_name}_pattern_complexity.{format}"), format
    )

    # Try hex patterns (may be empty)
    with contextlib.suppress(BaseException):
        pattern_generator.generate_hex_pattern_diagram(
            ast, str(output_path / f"{base_name}_hex_patterns.{format}"), format
        )

    # 5. Summary Report
    click.echo("📋 Creating summary report...")
    summary = {
        "file": yara_file,
        "generated_files": [
            f"{base_name}_complexity.json",
            f"{base_name}_complexity.txt",
            f"{base_name}_dependencies.{format}",
            f"{base_name}_rules.{format}",
            f"{base_name}_complexity_graph.{format}",
            f"{base_name}_tree.html",
            f"{base_name}_pattern_flow.{format}",
            f"{base_name}_pattern_complexity.{format}",
        ],
        "metrics": {
            "quality_score": metrics.get_quality_score(),
            "quality_grade": metrics.get_complexity_grade(),
            "total_rules": metrics.total_rules,
            "total_strings": metrics.total_strings,
            "max_condition_depth": metrics.max_condition_depth,
            "complex_rules": metrics.complex_rules,
        },
    }

    with Path(output_path / "summary.json").open("w") as f:
        json.dump(summary, f, indent=2)

    click.echo(f"\n✅ Comprehensive report generated in {output_path}/")
    click.echo(
        f"📊 Quality Score: {metrics.get_quality_score():.1f} (Grade: {metrics.get_complexity_grade()})"
    )
    click.echo(f"📁 Generated {len(summary['generated_files'])} files")


def _format_complexity_text(metrics) -> str:
    """Format complexity metrics as readable text."""
    lines = [
        "YARA Rule Complexity Analysis",
        "=" * 35,
        "",
        f"📊 Overall Quality Score: {metrics.get_quality_score():.1f}/100 (Grade: {metrics.get_complexity_grade()})",
        "",
        "📁 File Metrics:",
        f"  Total Rules: {metrics.total_rules}",
        f"  Total Imports: {metrics.total_imports}",
        f"  Total Includes: {metrics.total_includes}",
        "",
        "📋 Rule Metrics:",
        f"  Rules with strings: {metrics.rules_with_strings}",
        f"  Rules with meta: {metrics.rules_with_meta}",
        f"  Rules with tags: {metrics.rules_with_tags}",
        f"  Private rules: {metrics.private_rules}",
        f"  Global rules: {metrics.global_rules}",
        "",
        "🧵 String Metrics:",
        f"  Total strings: {metrics.total_strings}",
        f"  Plain strings: {metrics.plain_strings}",
        f"  Hex strings: {metrics.hex_strings}",
        f"  Regex strings: {metrics.regex_strings}",
        f"  Strings with modifiers: {metrics.strings_with_modifiers}",
        "",
        "🔄 Condition Complexity:",
        f"  Max condition depth: {metrics.max_condition_depth}",
        f"  Avg condition depth: {metrics.avg_condition_depth:.2f}",
        f"  Binary operations: {metrics.total_binary_ops}",
        f"  Unary operations: {metrics.total_unary_ops}",
        f"  For expressions: {metrics.for_expressions}",
        f"  For-of expressions: {metrics.for_of_expressions}",
        f"  Of expressions: {metrics.of_expressions}",
        "",
        "🎯 Pattern Complexity:",
        f"  Hex wildcards: {metrics.hex_wildcards}",
        f"  Hex jumps: {metrics.hex_jumps}",
        f"  Hex alternatives: {metrics.hex_alternatives}",
        f"  Regex groups: {metrics.regex_groups}",
        f"  Regex quantifiers: {metrics.regex_quantifiers}",
        "",
    ]

    if metrics.cyclomatic_complexity:
        lines.extend(
            [
                "🧮 Cyclomatic Complexity by Rule:",
                *[
                    f"  {rule}: {complexity}"
                    for rule, complexity in metrics.cyclomatic_complexity.items()
                ],
                "",
            ]
        )

    if metrics.complex_rules:
        lines.extend(
            [
                "⚠️  Complex Rules (require attention):",
                *[f"  - {rule}" for rule in metrics.complex_rules],
                "",
            ]
        )

    if metrics.unused_strings:
        lines.extend(
            [
                "🔍 Unused Strings:",
                *[
                    f"  - {string_ref}" for string_ref in metrics.unused_strings[:10]
                ],  # Limit to first 10
                (
                    ""
                    if len(metrics.unused_strings) <= 10
                    else f"  ... and {len(metrics.unused_strings) - 10} more"
                ),
                "",
            ]
        )

    if metrics.module_usage:
        lines.extend(
            [
                "📦 Module Usage:",
                *[f"  {module}: {usage} times" for module, usage in metrics.module_usage.items()],
                "",
            ]
        )

    return "\n".join(lines)


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
def strings(yara_file: str, output: str | None, format: str):
    """Analyze string patterns in YARA rules."""
    with Path(yara_file).open() as f:
        content = f.read()
    parser = Parser()
    ast = parser.parse(content)

    # Analyze strings
    analysis = {
        "total_strings": 0,
        "type_distribution": {"plain": 0, "hex": 0, "regex": 0},
        "length_stats": {"min": float("inf"), "max": 0, "avg": 0},
        "rules": {},
        "modifiers": {},
        "patterns": {"short_strings": 0, "hex_patterns": 0},
    }

    lengths = []

    for rule in ast.rules:
        if rule.strings:
            rule_info = {
                "string_count": len(rule.strings),
                "types": [],
                "identifiers": [],
            }

            for string_def in rule.strings:
                analysis["total_strings"] += 1
                rule_info["identifiers"].append(string_def.identifier)

                if hasattr(string_def, "value"):  # Plain string
                    analysis["type_distribution"]["plain"] += 1
                    rule_info["types"].append("plain")
                    str_len = len(string_def.value)
                    lengths.append(str_len)
                    if str_len < 4:
                        analysis["patterns"]["short_strings"] += 1

                    # Count modifiers
                    if hasattr(string_def, "modifiers"):
                        for mod in string_def.modifiers:
                            mod_name = mod.name if hasattr(mod, "name") else str(mod)
                            analysis["modifiers"][mod_name] = (
                                analysis["modifiers"].get(mod_name, 0) + 1
                            )

                elif hasattr(string_def, "tokens"):  # Hex string
                    analysis["type_distribution"]["hex"] += 1
                    rule_info["types"].append("hex")
                    analysis["patterns"]["hex_patterns"] += 1

                elif hasattr(string_def, "regex"):  # Regex string
                    analysis["type_distribution"]["regex"] += 1
                    rule_info["types"].append("regex")

            analysis["rules"][rule.name] = rule_info

    # Calculate length statistics
    if lengths:
        analysis["length_stats"]["min"] = min(lengths)
        analysis["length_stats"]["max"] = max(lengths)
        analysis["length_stats"]["avg"] = sum(lengths) / len(lengths)
    else:
        analysis["length_stats"]["min"] = 0
        analysis["length_stats"]["max"] = 0
        analysis["length_stats"]["avg"] = 0

    # Format output
    if format == "json":
        output_text = json.dumps(analysis, indent=2)
    else:
        output_text = _format_strings_text(analysis)

    if output:
        with Path(output).open("w") as f:
            f.write(output_text)
        click.echo(f"String analysis written to {output}")
    else:
        click.echo(output_text)


def _format_strings_text(analysis: dict) -> str:
    """Format string analysis as readable text."""
    lines = [
        "YARA String Analysis",
        "=" * 20,
        "",
        f"📊 Total Strings: {analysis['total_strings']}",
        "",
        "📝 Type Distribution:",
        f"  Plain strings: {analysis['type_distribution']['plain']}",
        f"  Hex patterns: {analysis['type_distribution']['hex']}",
        f"  Regex patterns: {analysis['type_distribution']['regex']}",
        "",
    ]

    if analysis["total_strings"] > 0:
        lines.extend(
            [
                "📏 Length Statistics (plain strings):",
                f"  Min: {analysis['length_stats']['min']}",
                f"  Max: {analysis['length_stats']['max']}",
                f"  Avg: {analysis['length_stats']['avg']:.1f}",
                "",
            ]
        )

    if analysis["modifiers"]:
        lines.extend(
            [
                "🔧 String Modifiers:",
                *[f"  {mod}: {count}" for mod, count in analysis["modifiers"].items()],
                "",
            ]
        )

    if analysis["patterns"]["short_strings"] > 0 or analysis["patterns"]["hex_patterns"] > 0:
        lines.extend(
            [
                "🎯 Pattern Analysis:",
                f"  Short strings (<4 chars): {analysis['patterns']['short_strings']}",
                f"  Hex patterns: {analysis['patterns']['hex_patterns']}",
                "",
            ]
        )

    if analysis["rules"]:
        lines.extend(
            [
                "📁 Rules with Strings:",
                *[
                    f"  {rule}: {info['string_count']} strings ({', '.join(set(info['types']))})"
                    for rule, info in analysis["rules"].items()
                ],
            ]
        )

    return "\n".join(lines)


def _get_text_graph(stats: dict, dependencies: dict) -> str:
    """Format dependency graph as text."""
    lines = [
        "Dependency Analysis",
        "=" * 19,
        "",
        f"Total rules: {stats['total_rules']}",
        f"Total imports: {stats['total_imports']}",
        f"Rules with strings: {stats['rules_with_strings']}",
        f"Rules using modules: {stats['rules_using_modules']}",
        "",
    ]

    if dependencies:
        lines.extend(
            [
                "Rule Dependencies:",
                *[f"  {rule} → {', '.join(deps)}" for rule, deps in dependencies.items() if deps],
            ]
        )

    return "\n".join(lines)
