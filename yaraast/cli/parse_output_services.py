"""Output helpers for parse CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.syntax import Syntax

from yaraast import CodeGenerator
from yaraast.cli.utils import format_json, write_text
from yaraast.cli.visitors import ASTDumper, ASTTreeBuilder

console = Console()


def _report_parsing_errors(lexer_errors: list, parser_errors: list, ast) -> None:
    """Report lexer and parser errors."""
    total_errors = len(lexer_errors) + len(parser_errors)

    if lexer_errors or parser_errors:
        console.print(f"\\n[yellow]Found {total_errors} issue(s) in the file:[/yellow]")

        if lexer_errors:
            _display_lexer_errors(lexer_errors)

        if parser_errors:
            _display_parser_errors(parser_errors)

        if not ast:
            console.print("\\n[red]Could not parse file due to critical errors[/red]")
            raise click.Abort from None

        console.print("\\n[green]Partial parse successful despite errors[/green]\\n")


def _display_lexer_errors(lexer_errors: list) -> None:
    """Display lexer errors."""
    console.print(f"\\n[yellow]Lexer Issues ({len(lexer_errors)}):[/yellow]")
    for error in lexer_errors[:5]:
        console.print(error.format_error())

    if len(lexer_errors) > 5:
        console.print(f"\\n[dim]... and {len(lexer_errors) - 5} more lexer issues[/dim]")


def _display_parser_errors(parser_errors: list) -> None:
    """Display parser errors."""
    console.print(f"\\n[yellow]Parser Issues ({len(parser_errors)}):[/yellow]")
    for error in parser_errors[:5]:
        console.print(error.format_error())

    if len(parser_errors) > 5:
        console.print(f"\\n[dim]... and {len(parser_errors) - 5} more parser issues[/dim]")


def _generate_output_by_format(ast, output_format: str, output: str | None) -> None:
    """Generate output based on specified format."""
    if output_format == "yara":
        _generate_yara_output(ast, output)
    elif output_format == "json":
        _generate_json_output(ast, output)
    elif output_format == "yaml":
        _generate_yaml_output(ast, output)
    elif output_format == "tree":
        _generate_tree_output(ast, output)


def _generate_yara_output(ast, output: str | None) -> None:
    """Generate YARA code output."""
    generator = CodeGenerator()
    result = generator.generate(ast)

    if output:
        write_text(output, result)
        console.print(f"Generated YARA code written to {output}")
    else:
        syntax = Syntax(result, "yara", theme="monokai", line_numbers=True)
        console.print(syntax)


def _generate_json_output(ast, output: str | None) -> None:
    """Generate JSON AST output."""
    dumper = ASTDumper()
    result = dumper.visit(ast)
    json_str = format_json(result)

    if output:
        write_text(output, json_str)
        console.print(f"AST JSON written to {output}")
    else:
        click.echo(json_str)


def _generate_yaml_output(ast, output: str | None) -> None:
    """Generate YAML AST output."""
    try:
        import yaml
    except ImportError:
        console.print(
            "[red]Error: PyYAML is not installed. Install it with: pip install pyyaml[/red]"
        )
        raise click.Abort from None

    dumper = ASTDumper()
    result = dumper.visit(ast)
    yaml_str = yaml.dump(
        result,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )

    if output:
        write_text(output, yaml_str)
        console.print(f"AST YAML written to {output}")
    else:
        click.echo(yaml_str)


def _generate_tree_output(ast, output: str | None) -> None:
    """Generate tree visualization output."""
    builder = ASTTreeBuilder()
    tree = builder.visit(ast)

    if output:
        from rich.console import Console as RichConsole

        with Path(output).open("w", encoding="utf-8") as f:
            file_console = RichConsole(file=f, width=80)
            file_console.print(tree)
        console.print(f"AST tree written to {output}")
    else:
        console.print(tree)
