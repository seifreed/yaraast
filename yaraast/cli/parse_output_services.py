"""Output helpers for parse CLI (logic without IO)."""

from __future__ import annotations

import click
from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax

from yaraast.cli.utils import format_json, write_text
from yaraast.cli.visitors import ASTDumper, ASTTreeBuilder
from yaraast.yaral.ast_nodes import YaraLFile
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yarax.generator import YaraXGenerator

console = Console()

_OUTPUT_FORMATS = frozenset({"json", "tree", "yaml", "yara"})


def _is_missing_yaml_import(exc: ImportError) -> bool:
    return (exc.name or "") == "yaml"


def _require_output_format(output_format: object) -> str:
    if not isinstance(output_format, str):
        raise TypeError("output format must be a string")
    if output_format not in _OUTPUT_FORMATS:
        valid = ", ".join(sorted(_OUTPUT_FORMATS))
        raise ValueError(f"output format must be one of: {valid}")
    return output_format


def _report_parsing_errors(
    lexer_errors: list,
    parser_errors: list,
    ast,
    output_console: Console | None = None,
) -> None:
    """Report lexer and parser errors."""
    target_console = output_console or console
    total_errors = len(lexer_errors) + len(parser_errors)

    if lexer_errors or parser_errors:
        target_console.print(f"\n[yellow]Found {total_errors} issue(s) in the file:[/yellow]")

        if lexer_errors:
            _display_lexer_errors(lexer_errors, target_console)

        if parser_errors:
            _display_parser_errors(parser_errors, target_console)

        if ast is None:
            target_console.print("\n[red]Could not parse file due to critical errors[/red]")
            raise click.Abort from None

        target_console.print("\n[green]Partial parse successful despite errors[/green]\n")


def _display_lexer_errors(lexer_errors: list, output_console: Console = console) -> None:
    """Display lexer errors."""
    output_console.print(f"\n[yellow]Lexer Issues ({len(lexer_errors)}):[/yellow]")
    for error in lexer_errors[:5]:
        output_console.print(escape(error.format_error()))

    if len(lexer_errors) > 5:
        output_console.print(f"\n[dim]... and {len(lexer_errors) - 5} more lexer issues[/dim]")


def _display_parser_errors(parser_errors: list, output_console: Console = console) -> None:
    """Display parser errors."""
    output_console.print(f"\n[yellow]Parser Issues ({len(parser_errors)}):[/yellow]")
    for error in parser_errors[:5]:
        output_console.print(escape(error.format_error()))

    if len(parser_errors) > 5:
        output_console.print(f"\n[dim]... and {len(parser_errors) - 5} more parser issues[/dim]")


def _generate_output_by_format(ast, output_format: object, output: str | None) -> None:
    """Generate output based on specified format."""
    output_format = _require_output_format(output_format)
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
    if isinstance(ast, YaraLFile):
        result = YaraLGenerator().generate(ast)
    else:
        result = YaraXGenerator().generate(ast)

    if output is not None:
        write_text(output, result)
        console.print(f"Generated YARA code written to {escape(output)}")
    else:
        syntax = Syntax(result, "yara", theme="monokai", line_numbers=True)
        console.print(syntax)


def _generate_json_output(ast, output: str | None) -> None:
    """Generate JSON AST output."""
    dumper = ASTDumper()
    result = dumper.visit(ast)
    json_str = format_json(result)

    if output is not None:
        write_text(output, json_str)
        console.print(f"AST JSON written to {escape(output)}")
    else:
        click.echo(json_str)


def _generate_yaml_output(ast, output: str | None) -> None:
    """Generate YAML AST output."""
    try:
        import yaml
    except ImportError as exc:
        if not _is_missing_yaml_import(exc):
            raise
        console.print(
            "[red]Error: PyYAML is not installed. Install it with: pip install pyyaml[/red]"
        )
        raise click.Abort from exc

    dumper = ASTDumper()
    result = dumper.visit(ast)
    yaml_str = yaml.safe_dump(
        result,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )

    if output is not None:
        write_text(output, yaml_str)
        console.print(f"AST YAML written to {escape(output)}")
    else:
        click.echo(yaml_str)


def _generate_tree_output(ast, output: str | None) -> None:
    """Generate tree visualization output."""
    builder = ASTTreeBuilder()
    tree = builder.visit(ast)

    if output is not None:
        from rich.console import Console as RichConsole

        file_console = RichConsole(record=True, width=80)
        file_console.print(tree)
        write_text(output, file_console.export_text())
        console.print(f"AST tree written to {escape(output)}")
    else:
        console.print(tree)
