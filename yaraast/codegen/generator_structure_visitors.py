"""Structure-level visitors for the YARA code generator."""

from __future__ import annotations

from typing import Any

from yaraast.codegen.generator_formatting import (
    format_nonempty_quoted_value,
    reject_import_alias,
    validate_extern_rule_identifiers,
    validate_rule_collections,
    validate_rule_identifiers,
    validate_rule_tag_name,
    validate_yara_file_collections,
    validate_yara_identifier,
)


def _emit_comments(generator: Any, node: Any) -> None:
    """Emit leading comments for an AST node."""
    if hasattr(node, "leading_comments") and node.leading_comments:
        for comment in node.leading_comments:
            generator._writeline(generator.visit(comment))


def _emit_trailing(generator: Any, node: Any) -> None:
    """Emit trailing comment for an AST node."""
    if hasattr(node, "trailing_comment") and node.trailing_comment:
        generator._write(f"  {generator.visit(node.trailing_comment)}")


def _emit_top_level_line(generator: Any, node: Any) -> None:
    _emit_comments(generator, node)
    rendered = generator.visit(node)
    if rendered:
        generator._write(rendered)
    generator._writeline()


def _emit_top_level_section(generator: Any, nodes: list[Any] | tuple[Any, ...]) -> bool:
    if not nodes:
        return False
    for node in nodes:
        _emit_top_level_line(generator, node)
    generator._writeline()
    return True


def visit_yara_file(generator: Any, node: Any) -> str:
    validate_yara_file_collections(node)
    validate_rule_identifiers(node.rules)
    validate_extern_rule_identifiers(node.rules, node.extern_rules, node.namespaces)
    _emit_top_level_section(generator, node.pragmas)
    _emit_top_level_section(generator, node.imports)
    _emit_top_level_section(generator, node.extern_imports)
    _emit_top_level_section(generator, node.includes)
    _emit_top_level_section(generator, node.namespaces)
    _emit_top_level_section(generator, node.extern_rules)
    for index, rule in enumerate(node.rules):
        if index > 0:
            generator._writeline()
        _emit_comments(generator, rule)
        generator.visit(rule)
    return str(generator.buffer.getvalue())


def validate_required_module_imports(node: Any) -> None:
    imported_modules = {getattr(import_node, "module", None) for import_node in node.imports}
    required_modules: set[str] = set()
    for rule in node.rules:
        _collect_required_module_imports(getattr(rule, "condition", None), required_modules)
    missing_modules = sorted(
        module for module in required_modules if module not in imported_modules
    )
    if not missing_modules:
        return
    missing = ", ".join(missing_modules)
    msg = f"Module imports are required for libyara output: {missing}"
    raise ValueError(msg)


def _collect_required_module_imports(value: Any, modules: set[str]) -> None:
    from yaraast.ast.expressions import FunctionCall
    from yaraast.ast.modules import ModuleReference
    from yaraast.types.module_definitions import load_builtin_modules

    if value is None:
        return
    if isinstance(value, ModuleReference):
        modules.add(value.module)
        return
    if isinstance(value, FunctionCall):
        resolved = value.module_and_function()
        if resolved is not None:
            module_name, _function_name = resolved
            if module_name in load_builtin_modules():
                modules.add(module_name)
        _collect_required_module_imports(getattr(value, "receiver", None), modules)
        for argument in value.arguments:
            _collect_required_module_imports(argument, modules)
        return
    if isinstance(value, list | tuple | set):
        for item in value:
            _collect_required_module_imports(item, modules)
        return
    if not hasattr(value, "__dict__"):
        return
    for field_name, field_value in vars(value).items():
        if field_name in {"location", "leading_comments", "trailing_comment"}:
            continue
        _collect_required_module_imports(field_value, modules)


def visit_import(node: Any) -> str:
    value = f"import \"{format_nonempty_quoted_value(node.module, 'Import module')}\""
    reject_import_alias(getattr(node, "alias", None))
    return value


def visit_include(node: Any) -> str:
    return f"include \"{format_nonempty_quoted_value(node.path, 'Include path')}\""


def visit_rule(generator: Any, node: Any) -> str:
    validate_rule_collections(node)
    generator._write_rule_header(node)
    generator._writeline(" {")
    generator._indent()
    generator._write_meta_section(node.meta)
    _write_in_rule_pragmas(generator, node, "before_strings")
    generator._write_strings_section(node.strings, has_condition=node.condition is not None)
    _write_in_rule_pragmas(generator, node, "after_strings")
    _write_in_rule_pragmas(generator, node, "before_condition")
    generator._write_condition_section(node.condition)
    generator._dedent()
    generator._write("}")
    _emit_trailing(generator, node)
    generator._writeline()
    return ""


def visit_tag(node: Any) -> str:
    return validate_yara_identifier(validate_rule_tag_name(node), "tag")


def visit_string_definition(_node: Any) -> str:
    return ""


def _write_in_rule_pragmas(generator: Any, node: Any, position: str) -> None:
    for pragma in getattr(node, "pragmas", []):
        if pragma.position == position:
            generator._writeline(generator.visit(pragma))
