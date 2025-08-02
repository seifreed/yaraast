"""CLI interface for YARA AST."""

import json
from difflib import unified_diff
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree

from yaraast import CodeGenerator, Parser
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
    StringModifier,
)
from yaraast.visitor import ASTVisitor

console = Console()


class ASTDumper(ASTVisitor[dict]):
    """Dump AST to dictionary format."""

    def visit_yara_file(self, node: YaraFile) -> dict:
        return {
            "type": "YaraFile",
            "imports": [self.visit(imp) for imp in node.imports],
            "includes": [self.visit(inc) for inc in node.includes],
            "rules": [self.visit(rule) for rule in node.rules],
        }

    def visit_import(self, node: Import) -> dict:
        return {"type": "Import", "module": node.module}

    def visit_include(self, node: Include) -> dict:
        return {"type": "Include", "path": node.path}

    def visit_rule(self, node: Rule) -> dict:
        return {
            "type": "Rule",
            "name": node.name,
            "modifiers": node.modifiers,
            "tags": [self.visit(tag) for tag in node.tags],
            "meta": node.meta,
            "strings": [self.visit(s) for s in node.strings],
            "condition": self.visit(node.condition) if node.condition else None,
        }

    def visit_tag(self, node: Tag) -> dict:
        return {"type": "Tag", "name": node.name}

    def visit_string_definition(self, node: StringDefinition) -> dict:
        return {"type": "StringDefinition", "identifier": node.identifier}

    def visit_plain_string(self, node: PlainString) -> dict:
        return {
            "type": "PlainString",
            "identifier": node.identifier,
            "value": node.value,
            "modifiers": [self.visit(mod) for mod in node.modifiers],
        }

    def visit_hex_string(self, node: HexString) -> dict:
        return {
            "type": "HexString",
            "identifier": node.identifier,
            "tokens": [self.visit(token) for token in node.tokens],
            "modifiers": [self.visit(mod) for mod in node.modifiers],
        }

    def visit_regex_string(self, node: RegexString) -> dict:
        return {
            "type": "RegexString",
            "identifier": node.identifier,
            "regex": node.regex,
            "modifiers": [self.visit(mod) for mod in node.modifiers],
        }

    def visit_string_modifier(self, node: StringModifier) -> dict:
        return {"type": "StringModifier", "name": node.name, "value": node.value}

    def visit_hex_token(self, node: HexToken) -> dict:
        return {"type": "HexToken"}

    def visit_hex_byte(self, node: HexByte) -> dict:
        return {"type": "HexByte", "value": node.value}

    def visit_hex_wildcard(self, node: HexWildcard) -> dict:
        return {"type": "HexWildcard"}

    def visit_hex_jump(self, node: HexJump) -> dict:
        return {"type": "HexJump", "min_jump": node.min_jump, "max_jump": node.max_jump}

    def visit_hex_alternative(self, node: HexAlternative) -> dict:
        return {
            "type": "HexAlternative",
            "alternatives": [[self.visit(token) for token in alt] for alt in node.alternatives],
        }

    def visit_expression(self, node: Expression) -> dict:
        return {"type": "Expression"}

    def visit_identifier(self, node: Identifier) -> dict:
        return {"type": "Identifier", "name": node.name}

    def visit_string_identifier(self, node: StringIdentifier) -> dict:
        return {"type": "StringIdentifier", "name": node.name}

    def visit_string_count(self, node: StringCount) -> dict:
        return {"type": "StringCount", "string_id": node.string_id}

    def visit_string_offset(self, node: StringOffset) -> dict:
        return {
            "type": "StringOffset",
            "string_id": node.string_id,
            "index": self.visit(node.index) if node.index else None,
        }

    def visit_string_length(self, node: StringLength) -> dict:
        return {
            "type": "StringLength",
            "string_id": node.string_id,
            "index": self.visit(node.index) if node.index else None,
        }

    def visit_integer_literal(self, node: IntegerLiteral) -> dict:
        return {"type": "IntegerLiteral", "value": node.value}

    def visit_double_literal(self, node: DoubleLiteral) -> dict:
        return {"type": "DoubleLiteral", "value": node.value}

    def visit_string_literal(self, node: StringLiteral) -> dict:
        return {"type": "StringLiteral", "value": node.value}

    def visit_boolean_literal(self, node: BooleanLiteral) -> dict:
        return {"type": "BooleanLiteral", "value": node.value}

    def visit_binary_expression(self, node: BinaryExpression) -> dict:
        return {
            "type": "BinaryExpression",
            "left": self.visit(node.left),
            "operator": node.operator,
            "right": self.visit(node.right),
        }

    def visit_unary_expression(self, node: UnaryExpression) -> dict:
        return {
            "type": "UnaryExpression",
            "operator": node.operator,
            "operand": self.visit(node.operand),
        }

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> dict:
        return {"type": "ParenthesesExpression", "expression": self.visit(node.expression)}

    def visit_set_expression(self, node: SetExpression) -> dict:
        return {"type": "SetExpression", "elements": [self.visit(elem) for elem in node.elements]}

    def visit_range_expression(self, node: RangeExpression) -> dict:
        return {
            "type": "RangeExpression",
            "low": self.visit(node.low),
            "high": self.visit(node.high),
        }

    def visit_function_call(self, node: FunctionCall) -> dict:
        return {
            "type": "FunctionCall",
            "function": node.function,
            "arguments": [self.visit(arg) for arg in node.arguments],
        }

    def visit_array_access(self, node: ArrayAccess) -> dict:
        return {
            "type": "ArrayAccess",
            "array": self.visit(node.array),
            "index": self.visit(node.index),
        }

    def visit_member_access(self, node: MemberAccess) -> dict:
        return {"type": "MemberAccess", "object": self.visit(node.object), "member": node.member}

    def visit_condition(self, node: Condition) -> dict:
        return {"type": "Condition"}

    def visit_for_expression(self, node: ForExpression) -> dict:
        return {
            "type": "ForExpression",
            "quantifier": node.quantifier,
            "variable": node.variable,
            "iterable": self.visit(node.iterable),
            "body": self.visit(node.body),
        }

    def visit_for_of_expression(self, node: ForOfExpression) -> dict:
        return {
            "type": "ForOfExpression",
            "quantifier": node.quantifier,
            "string_set": self.visit(node.string_set),
            "condition": self.visit(node.condition) if node.condition else None,
        }

    def visit_at_expression(self, node: AtExpression) -> dict:
        return {
            "type": "AtExpression",
            "string_id": node.string_id,
            "offset": self.visit(node.offset),
        }

    def visit_in_expression(self, node: InExpression) -> dict:
        return {
            "type": "InExpression",
            "string_id": node.string_id,
            "range": self.visit(node.range),
        }

    def visit_of_expression(self, node: OfExpression) -> dict:
        return {
            "type": "OfExpression",
            "quantifier": self.visit(node.quantifier),
            "string_set": self.visit(node.string_set),
        }

    def visit_meta(self, node: Meta) -> dict:
        return {"type": "Meta", "key": node.key, "value": node.value}


class ASTTreeBuilder(ASTVisitor[Tree]):
    """Build Rich tree visualization of AST."""

    def visit_yara_file(self, node: YaraFile) -> Tree:
        tree = Tree("🗂️  YARA File")

        if node.imports:
            imports_tree = tree.add("📦 Imports")
            for imp in node.imports:
                imports_tree.add(f'"{imp.module}"')

        if node.includes:
            includes_tree = tree.add("📁 Includes")
            for inc in node.includes:
                includes_tree.add(f'"{inc.path}"')

        if node.rules:
            rules_tree = tree.add("📜 Rules")
            for rule in node.rules:
                rules_tree.add(self.visit(rule))

        return tree

    def visit_rule(self, node: Rule) -> Tree:
        name_with_modifiers = node.name
        if node.modifiers:
            name_with_modifiers = f"[{'|'.join(node.modifiers)}] {name_with_modifiers}"

        rule_tree = Tree(f"🔖 {name_with_modifiers}")

        if node.tags:
            tags_tree = rule_tree.add("🏷️  Tags")
            for tag in node.tags:
                tags_tree.add(tag.name)

        if node.meta:
            meta_tree = rule_tree.add("ℹ️  Meta")
            for key, value in node.meta.items():
                if isinstance(value, str):
                    meta_tree.add(f'{key} = "{value}"')
                else:
                    meta_tree.add(f"{key} = {value}")

        if node.strings:
            strings_tree = rule_tree.add("🔤 Strings")
            for string in node.strings:
                string_type = string.__class__.__name__
                value_preview = ""
                if isinstance(string, PlainString):
                    value_preview = (
                        f' = "{string.value[:30]}{"..." if len(string.value) > 30 else ""}"'
                    )
                elif isinstance(string, RegexString):
                    value_preview = (
                        f' = /{string.regex[:30]}{"..." if len(string.regex) > 30 else ""}/'
                    )
                strings_tree.add(f"{string.identifier}{value_preview} [{string_type}]")

        if node.condition:
            condition_tree = rule_tree.add("✅ Condition")
            condition_preview = CodeGenerator().generate(node.condition).strip()
            if len(condition_preview) > 60:
                condition_preview = condition_preview[:60] + "..."
            condition_tree.add(condition_preview)

        return rule_tree

    # Minimal implementations for other visit methods
    def visit_import(self, node):
        return Tree("")

    def visit_include(self, node):
        return Tree("")

    def visit_tag(self, node):
        return Tree("")

    def visit_string_definition(self, node):
        return Tree("")

    def visit_plain_string(self, node):
        return Tree("")

    def visit_hex_string(self, node):
        return Tree("")

    def visit_regex_string(self, node):
        return Tree("")

    def visit_string_modifier(self, node):
        return Tree("")

    def visit_hex_token(self, node):
        return Tree("")

    def visit_hex_byte(self, node):
        return Tree("")

    def visit_hex_wildcard(self, node):
        return Tree("")

    def visit_hex_jump(self, node):
        return Tree("")

    def visit_hex_alternative(self, node):
        return Tree("")

    def visit_expression(self, node):
        return Tree("")

    def visit_identifier(self, node):
        return Tree("")

    def visit_string_identifier(self, node):
        return Tree("")

    def visit_string_count(self, node):
        return Tree("")

    def visit_string_offset(self, node):
        return Tree("")

    def visit_string_length(self, node):
        return Tree("")

    def visit_integer_literal(self, node):
        return Tree("")

    def visit_double_literal(self, node):
        return Tree("")

    def visit_string_literal(self, node):
        return Tree("")

    def visit_boolean_literal(self, node):
        return Tree("")

    def visit_binary_expression(self, node):
        return Tree("")

    def visit_unary_expression(self, node):
        return Tree("")

    def visit_parentheses_expression(self, node):
        return Tree("")

    def visit_set_expression(self, node):
        return Tree("")

    def visit_range_expression(self, node):
        return Tree("")

    def visit_function_call(self, node):
        return Tree("")

    def visit_array_access(self, node):
        return Tree("")

    def visit_member_access(self, node):
        return Tree("")

    def visit_condition(self, node):
        return Tree("")

    def visit_for_expression(self, node):
        return Tree("")

    def visit_for_of_expression(self, node):
        return Tree("")

    def visit_at_expression(self, node):
        return Tree("")

    def visit_in_expression(self, node):
        return Tree("")

    def visit_of_expression(self, node):
        return Tree("")

    def visit_meta(self, node):
        return Tree("")


@click.group()
@click.version_option(version="0.1.0", prog_name="yaraast")
def cli():
    """YARA AST - Parse and manipulate YARA rules."""


# Add workspace commands
from yaraast.cli.commands.workspace import workspace

cli.add_command(workspace)

# Add validation commands
from yaraast.cli.commands.validate import validate

cli.add_command(validate)

# Add analysis commands
from yaraast.cli.commands.analyze import analyze

cli.add_command(analyze)

# Add serialization commands
from yaraast.cli.commands.serialize import serialize

cli.add_command(serialize)

# Add metrics commands
from yaraast.cli.commands.metrics import metrics

cli.add_command(metrics)

# Add performance commands
from yaraast.cli.commands.performance import performance

cli.add_command(performance)

# Add semantic validation commands
from yaraast.cli.commands.semantic import semantic

cli.add_command(semantic)

# Add fluent API commands
from yaraast.cli.commands.fluent import fluent

cli.add_command(fluent)

# Add round-trip serialization commands
from yaraast.cli.commands.roundtrip import roundtrip

cli.add_command(roundtrip)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output file (default: stdout)")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["yara", "json", "tree"]),
    default="yara",
    help="Output format",
)
def parse(input_file: str, output: str | None, format: str):
    """Parse a YARA file and output in various formats."""
    try:
        # Read input file
        with open(input_file) as f:
            content = f.read()

        # Parse YARA file
        parser = Parser()
        ast = parser.parse(content)

        # Generate output based on format
        if format == "yara":
            generator = CodeGenerator()
            result = generator.generate(ast)
            if output:
                with open(output, "w") as f:
                    f.write(result)
                console.print(f"✅ Generated YARA code written to {output}")
            else:
                syntax = Syntax(result, "yara", theme="monokai", line_numbers=True)
                console.print(syntax)

        elif format == "json":
            dumper = ASTDumper()
            result = dumper.visit(ast)
            json_str = json.dumps(result, indent=2)
            if output:
                with open(output, "w") as f:
                    f.write(json_str)
                console.print(f"✅ AST JSON written to {output}")
            else:
                syntax = Syntax(json_str, "json", theme="monokai")
                console.print(syntax)

        elif format == "tree":
            builder = ASTTreeBuilder()
            tree = builder.visit(ast)
            if output:
                console.save_text(output)
                console.print(tree)
                console.print(f"✅ AST tree written to {output}")
            else:
                console.print(tree)

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
def validate(input_file: str):
    """Validate a YARA file for syntax errors."""
    try:
        with open(input_file) as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Count rules
        rule_count = len(ast.rules)
        import_count = len(ast.imports)

        console.print(
            Panel(
                f"[green]✅ Valid YARA file[/green]\n\n"
                f"📊 Statistics:\n"
                f"  • Rules: {rule_count}\n"
                f"  • Imports: {import_count}",
                title=f"Validation Result: {Path(input_file).name}",
                border_style="green",
            )
        )

    except Exception as e:
        console.print(
            Panel(
                f"[red]❌ Invalid YARA file[/red]\n\n" f"Error: {e}",
                title=f"Validation Result: {Path(input_file).name}",
                border_style="red",
            )
        )
        raise click.Abort


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
def format(input_file: str, output_file: str):
    """Format a YARA file with consistent style."""
    try:
        with open(input_file) as f:
            content = f.read()

        # Parse and regenerate
        parser = Parser()
        ast = parser.parse(content)

        generator = CodeGenerator()
        formatted = generator.generate(ast)

        with open(output_file, "w") as f:
            f.write(formatted)

        console.print(f"✅ Formatted YARA file written to {output_file}")

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort


@cli.group()
def libyara():
    """LibYARA integration commands for compilation and scanning."""


@libyara.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output compiled rules file")
@click.option("--optimize", is_flag=True, help="Enable AST optimizations")
@click.option("--debug", is_flag=True, help="Enable debug mode with source generation")
@click.option("--stats", is_flag=True, help="Show compilation statistics")
def compile(input_file: str, output: str | None, optimize: bool, debug: bool, stats: bool):
    """Compile YARA file using direct AST compilation."""
    try:
        from yaraast.libyara import YARA_AVAILABLE, DirectASTCompiler

        if not YARA_AVAILABLE:
            console.print("[red]❌ yara-python is not installed[/red]")
            console.print("Install with: pip install yara-python")
            raise click.Abort

        # Parse YARA file
        with open(input_file) as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Create direct compiler
        compiler = DirectASTCompiler(enable_optimization=optimize, debug_mode=debug)

        # Compile AST
        result = compiler.compile_ast(ast)

        if result.success:
            console.print("[green]✅ Compilation successful[/green]")

            if result.optimized:
                console.print("[blue]🔧 Optimizations applied:[/blue]")
                if result.optimization_stats:
                    opt_stats = result.optimization_stats
                    console.print(f"  • Rules optimized: {opt_stats.rules_optimized}")
                    console.print(f"  • Strings optimized: {opt_stats.strings_optimized}")
                    console.print(f"  • Conditions simplified: {opt_stats.conditions_simplified}")
                    console.print(f"  • Constants folded: {opt_stats.constant_folded}")

            if stats:
                console.print("[blue]📊 Compilation Stats:[/blue]")
                console.print(f"  • Compilation time: {result.compilation_time:.3f}s")
                console.print(f"  • AST nodes: {result.ast_node_count}")

                comp_stats = compiler.get_compilation_stats()
                console.print(f"  • Total compilations: {comp_stats['total_compilations']}")
                console.print(
                    f"  • Success rate: {comp_stats['successful_compilations']}/{comp_stats['total_compilations']}"
                )

            # Save compiled rules if output specified
            if output and result.compiled_rules:
                result.compiled_rules.save(output)
                console.print(f"[green]💾 Compiled rules saved to {output}[/green]")

            if debug and result.generated_source:
                console.print("[dim]🔍 Generated source (first 200 chars):[/dim]")
                console.print(f"[dim]{result.generated_source[:200]}...[/dim]")

        else:
            console.print("[red]❌ Compilation failed[/red]")
            for error in result.errors:
                console.print(f"[red]  • {error}[/red]")
            raise click.Abort

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort


@libyara.command()
@click.argument("rules_file", type=click.Path(exists=True))
@click.argument("target", type=click.Path(exists=True))
@click.option("--optimize", is_flag=True, help="Use optimized AST compilation")
@click.option("--timeout", type=int, help="Scan timeout in seconds")
@click.option("--fast", is_flag=True, help="Fast mode (stop on first match)")
@click.option("--stats", is_flag=True, help="Show scan statistics")
def scan(
    rules_file: str, target: str, optimize: bool, timeout: int | None, fast: bool, stats: bool
):
    """Scan file using optimized AST-based matcher."""
    try:
        from yaraast.libyara import YARA_AVAILABLE, DirectASTCompiler, OptimizedMatcher

        if not YARA_AVAILABLE:
            console.print("[red]❌ yara-python is not installed[/red]")
            console.print("Install with: pip install yara-python")
            raise click.Abort

        # Parse and compile rules
        with open(rules_file) as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Compile with optimization if requested
        compiler = DirectASTCompiler(enable_optimization=optimize)
        compile_result = compiler.compile_ast(ast)

        if not compile_result.success:
            console.print("[red]❌ Rule compilation failed[/red]")
            for error in compile_result.errors:
                console.print(f"[red]  • {error}[/red]")
            raise click.Abort

        # Create optimized matcher
        matcher = OptimizedMatcher(compile_result.compiled_rules, ast)

        # Perform scan
        scan_result = matcher.scan(Path(target), timeout=timeout, fast_mode=fast)

        if scan_result["success"]:
            matches = scan_result["matches"]
            console.print("[green]✅ Scan completed[/green]")
            console.print("[blue]📊 Results:[/blue]")
            console.print(f"  • Matches found: {len(matches)}")
            console.print(f"  • Scan time: {scan_result['scan_time']:.3f}s")
            console.print(f"  • Data size: {scan_result['data_size']} bytes")

            if scan_result.get("ast_enhanced"):
                console.print("  • AST-enhanced: ✅")
                console.print(f"  • Rule count: {scan_result['rule_count']}")

            # Show matches
            if matches:
                console.print("\n[yellow]🔍 Matches:[/yellow]")
                for match in matches:
                    console.print(f"  🎯 [bold]{match['rule']}[/bold]")
                    if match.get("tags"):
                        console.print(f"     Tags: {', '.join(match['tags'])}")
                    if match.get("strings"):
                        console.print(f"     Strings: {len(match['strings'])} found")

                    # Show AST context if available
                    if match.get("ast_context"):
                        ctx = match["ast_context"]
                        console.print(f"     Complexity: {ctx.get('condition_complexity', 'N/A')}")

            # Show optimization hints
            if scan_result.get("optimization_hints"):
                console.print("\n[dim]💡 Optimization Hints:[/dim]")
                for hint in scan_result["optimization_hints"]:
                    console.print(f"[dim]  • {hint}[/dim]")

            if stats:
                matcher_stats = matcher.get_scan_stats()
                console.print("\n[blue]📈 Scan Statistics:[/blue]")
                console.print(f"  • Total scans: {matcher_stats['total_scans']}")
                console.print(f"  • Success rate: {matcher_stats['success_rate']:.1%}")
                console.print(f"  • Average scan time: {matcher_stats['average_scan_time']:.3f}s")

        else:
            console.print(f"[red]❌ Scan failed: {scan_result.get('error', 'Unknown error')}[/red]")
            raise click.Abort

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort


@libyara.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--show-optimizations", is_flag=True, help="Show applied optimizations")
def optimize(input_file: str, show_optimizations: bool):
    """Optimize YARA rules using AST analysis."""
    try:
        from yaraast.libyara import ASTOptimizer

        # Parse YARA file
        with open(input_file) as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Create optimizer
        optimizer = ASTOptimizer()
        optimized_ast = optimizer.optimize(ast)

        # Generate optimized code
        generator = CodeGenerator()
        optimized_code = generator.generate(optimized_ast)

        console.print("[green]✅ Optimization completed[/green]")
        console.print("[blue]📊 Optimization Stats:[/blue]")
        console.print(f"  • Rules optimized: {optimizer.stats.rules_optimized}")
        console.print(f"  • Strings optimized: {optimizer.stats.strings_optimized}")
        console.print(f"  • Conditions simplified: {optimizer.stats.conditions_simplified}")
        console.print(f"  • Constants folded: {optimizer.stats.constant_folded}")

        if show_optimizations and optimizer.optimizations_applied:
            console.print("\n[yellow]🔧 Applied Optimizations:[/yellow]")
            for opt in optimizer.optimizations_applied:
                console.print(f"  • {opt}")

        console.print("\n[dim]📝 Optimized YARA code:[/dim]")
        syntax = Syntax(optimized_code, "yara", theme="monokai", line_numbers=True)
        console.print(syntax)

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output file (default: overwrite input)")
@click.option(
    "--style",
    type=click.Choice(["default", "compact", "pretty", "verbose"]),
    default="default",
    help="Formatting style",
)
@click.option("--check", is_flag=True, help="Check if file needs formatting (don't modify)")
@click.option("--diff", is_flag=True, help="Show formatting changes as diff")
def fmt(input_file: str, output: str | None, style: str, check: bool, diff: bool):
    """Format YARA file using AST-based formatting (like black for Python)."""
    try:
        from yaraast.cli.ast_tools import AST_Formatter

        input_path = Path(input_file)
        output_path = Path(output) if output else input_path

        formatter = AST_Formatter()

        if check:
            # Check formatting without modifying
            needs_format, issues = formatter.check_format(input_path)

            if needs_format:
                console.print(f"[yellow]📝 {input_path.name} needs formatting[/yellow]")
                if issues:
                    for issue in issues[:5]:  # Show first 5 issues
                        console.print(f"[dim]  • {issue}[/dim]")
                    if len(issues) > 5:
                        console.print(f"[dim]  • ... and {len(issues) - 5} more issues[/dim]")
                raise click.Abort
            console.print(f"[green]✅ {input_path.name} is already formatted[/green]")
            return

        if diff:
            # Show what would change
            with open(input_path) as f:
                original = f.read()

            success, formatted = formatter.format_file(input_path, None, style)
            if not success:
                console.print(f"[red]❌ {formatted}[/red]")
                raise click.Abort

            if original.strip() != formatted.strip():
                console.print(f"[blue]📋 Formatting changes for {input_path.name}:[/blue]")

                diff_lines = unified_diff(
                    original.splitlines(keepends=True),
                    formatted.splitlines(keepends=True),
                    fromfile=f"{input_path.name} (original)",
                    tofile=f"{input_path.name} (formatted)",
                    lineterm="",
                )

                for line in diff_lines:
                    if line.startswith(("+++", "---")):
                        console.print(f"[bold]{line.rstrip()}[/bold]")
                    elif line.startswith("@@"):
                        console.print(f"[cyan]{line.rstrip()}[/cyan]")
                    elif line.startswith("+"):
                        console.print(f"[green]{line.rstrip()}[/green]")
                    elif line.startswith("-"):
                        console.print(f"[red]{line.rstrip()}[/red]")
                    else:
                        console.print(f"[dim]{line.rstrip()}[/dim]")
            else:
                console.print("[green]✅ No formatting changes needed[/green]")
                return

        else:
            # Format file
            success, result = formatter.format_file(input_path, output_path, style)

            if success:
                if output_path == input_path:
                    console.print(f"[green]✅ Formatted {input_path.name} ({style} style)[/green]")
                else:
                    console.print(f"[green]✅ Formatted file written to {output_path}[/green]")
            else:
                console.print(f"[red]❌ {result}[/red]")
                raise click.Abort

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort


@cli.command()
@click.argument("file1", type=click.Path(exists=True))
@click.argument("file2", type=click.Path(exists=True))
@click.option("--logical-only", is_flag=True, help="Show only logical changes (ignore style)")
@click.option("--summary", is_flag=True, help="Show summary of changes only")
@click.option("--no-style", is_flag=True, help="Don't analyze style changes")
def diff(file1: str, file2: str, logical_only: bool, summary: bool, no_style: bool):
    """Show AST-based diff highlighting logical vs stylistic changes."""
    try:
        from yaraast.cli.ast_tools import ASTDiffer

        file1_path = Path(file1)
        file2_path = Path(file2)

        differ = ASTDiffer()
        result = differ.diff_files(file1_path, file2_path)

        if not result.has_changes:
            console.print(
                f"[green]✅ No differences found between {file1_path.name} and {file2_path.name}[/green]"
            )
            return

        console.print(f"[blue]📊 AST Diff: {file1_path.name} → {file2_path.name}[/blue]")
        console.print("=" * 60)

        if summary:
            # Show summary only
            console.print("[yellow]📋 Change Summary:[/yellow]")
            for change_type, count in result.change_summary.items():
                if count > 0:
                    console.print(f"  • {change_type.replace('_', ' ').title()}: {count}")
            return

        # Show detailed changes
        if result.added_rules:
            console.print(f"\n[green]➕ Added Rules ({len(result.added_rules)}):[/green]")
            for rule in result.added_rules:
                console.print(f"  + {rule}")

        if result.removed_rules:
            console.print(f"\n[red]➖ Removed Rules ({len(result.removed_rules)}):[/red]")
            for rule in result.removed_rules:
                console.print(f"  - {rule}")

        if result.modified_rules:
            console.print(f"\n[yellow]🔄 Modified Rules ({len(result.modified_rules)}):[/yellow]")
            for rule in result.modified_rules:
                console.print(f"  ~ {rule}")

        if result.logical_changes:
            console.print(f"\n[red]🧠 Logical Changes ({len(result.logical_changes)}):[/red]")
            for change in result.logical_changes:
                console.print(f"  • {change}")

        if result.structural_changes:
            console.print(
                f"\n[blue]🏗️  Structural Changes ({len(result.structural_changes)}):[/blue]"
            )
            for change in result.structural_changes:
                console.print(f"  • {change}")

        if not logical_only and not no_style and result.style_only_changes:
            console.print(f"\n[dim]🎨 Style-Only Changes ({len(result.style_only_changes)}):[/dim]")
            for change in result.style_only_changes[:10]:  # Limit style changes shown
                console.print(f"[dim]  • {change}[/dim]")
            if len(result.style_only_changes) > 10:
                console.print(
                    f"[dim]  • ... and {len(result.style_only_changes) - 10} more style changes[/dim]"
                )

        # Show change significance
        total_logical = (
            len(result.logical_changes) + len(result.added_rules) + len(result.removed_rules)
        )
        total_style = len(result.style_only_changes)

        if total_logical > 0:
            console.print(
                f"\n[yellow]⚠️  This diff contains {total_logical} logical changes that affect rule behavior[/yellow]"
            )
        elif total_style > 0:
            console.print(
                f"\n[green]✨ This diff contains only {total_style} style changes (no logic changes)[/green]"
            )

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True), required=True)
@click.option(
    "--operations",
    type=click.Choice(["parse", "codegen", "roundtrip", "all"]),
    default="all",
    help="Operations to benchmark",
)
@click.option("--iterations", type=int, default=10, help="Number of iterations per test")
@click.option("--output", type=click.Path(), help="Output benchmark results to JSON file")
@click.option("--compare", is_flag=True, help="Compare performance across files")
def bench(files: tuple[str], operations: str, iterations: int, output: str | None, compare: bool):
    """Performance benchmarks for AST operations."""
    try:
        import json

        from yaraast.cli.ast_tools import ASTBenchmarker

        file_paths = [Path(f) for f in files]
        benchmarker = ASTBenchmarker()

        console.print("[blue]🏃 Running AST Performance Benchmarks[/blue]")
        console.print(f"Files: {len(file_paths)}, Iterations: {iterations}")
        console.print("=" * 60)

        all_results = []

        for file_path in file_paths:
            console.print(f"\n[yellow]📁 Benchmarking {file_path.name}...[/yellow]")

            # Determine operations to run
            ops_to_run = []
            if operations == "all":
                ops_to_run = ["parse", "codegen", "roundtrip"]
            elif operations == "roundtrip":
                ops_to_run = ["roundtrip"]
            else:
                ops_to_run = [operations]

            file_results = {}

            for op in ops_to_run:
                if op == "parse":
                    result = benchmarker.benchmark_parsing(file_path, iterations)
                elif op == "codegen":
                    result = benchmarker.benchmark_codegen(file_path, iterations)
                elif op == "roundtrip":
                    results = benchmarker.benchmark_roundtrip(file_path, iterations)
                    result = results[0] if results else None

                if result and result.success:
                    file_results[op] = result
                    console.print(
                        f"  ✅ {op:10s}: {result.execution_time*1000:6.2f}ms "
                        f"({result.rules_count} rules, {result.ast_nodes} nodes)"
                    )
                elif result:
                    console.print(f"  ❌ {op:10s}: {result.error}")

            all_results.append(
                {"file": str(file_path), "file_name": file_path.name, "results": file_results}
            )

        # Show summary
        summary = benchmarker.get_benchmark_summary()

        console.print("\n[green]📊 Benchmark Summary:[/green]")
        console.print("=" * 60)

        for operation, stats in summary.items():
            console.print(f"\n[bold]{operation.upper()}:[/bold]")
            console.print(f"  • Average time: {stats['avg_time']*1000:.2f}ms")
            console.print(f"  • Min time: {stats['min_time']*1000:.2f}ms")
            console.print(f"  • Max time: {stats['max_time']*1000:.2f}ms")
            console.print(f"  • Files processed: {stats['total_files_processed']}")
            console.print(f"  • Rules processed: {stats['total_rules_processed']}")
            console.print(f"  • Rules/second: {stats['avg_rules_per_second']:.1f}")

        if compare and len(file_paths) > 1:
            console.print("\n[blue]🔍 Performance Comparison:[/blue]")
            console.print("=" * 60)

            # Compare parsing times
            parse_results = [
                (r["file_name"], r["results"].get("parse"))
                for r in all_results
                if "parse" in r["results"]
            ]

            if parse_results:
                parse_results.sort(key=lambda x: x[1].execution_time if x[1] else float("inf"))
                console.print("\n[yellow]Parsing Performance (fastest to slowest):[/yellow]")

                for i, (filename, result) in enumerate(parse_results):
                    if result:
                        throughput = (
                            result.rules_count / result.execution_time
                            if result.execution_time > 0
                            else 0
                        )
                        console.print(
                            f"  {i+1:2d}. {filename:20s} "
                            f"{result.execution_time*1000:6.2f}ms "
                            f"({throughput:.1f} rules/sec)"
                        )

        # Save results if requested
        if output:
            benchmark_data = {
                "timestamp": time.time(),
                "iterations": iterations,
                "operations": operations,
                "files": all_results,
                "summary": summary,
            }

            with open(output, "w") as f:
                json.dump(benchmark_data, f, indent=2, default=str)

            console.print(f"\n[green]💾 Benchmark results saved to {output}[/green]")

        console.print("\n✅ Benchmarking completed!")

    except ImportError as e:
        console.print(f"[red]❌ Import error: {e}[/red]")
        raise click.Abort
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort


if __name__ == "__main__":
    cli()
