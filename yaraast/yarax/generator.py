"""YARA-X code generator for new syntax features."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from yaraast.codegen.generator import CodeGenerator as BaseGenerator
from yaraast.codegen.generator_expression_visitors import (
    render_function_call_callee,
    render_postfix_index_target,
    validate_expression_collection,
    validate_slice_target,
    validate_tuple_indexing_target,
)
from yaraast.codegen.generator_formatting import (
    contextual_local_identifier_names,
    contextual_local_identifiers,
    escape_string_literal,
    format_meta_key,
    format_yarax_local_identifier,
    validate_yara_identifier,
)
from yaraast.codegen.generator_helpers import format_integer_literal

if TYPE_CHECKING:
    from yaraast.ast.expressions import Expression
    from yaraast.yarax.ast_nodes import (
        ArrayComprehension,
        DictComprehension,
        DictExpression,
        DictItem,
        LambdaExpression,
        ListExpression,
        MatchCase,
        PatternMatch,
        SliceExpression,
        SpreadOperator,
        TupleExpression,
        TupleIndexing,
        WithDeclaration,
        WithStatement,
    )


class YaraXGenerator(BaseGenerator):
    """Code generator for YARA-X with support for new syntax features."""

    def visit_meta(self, node: Any) -> str:
        key = format_meta_key(node.key, getattr(node, "scope", None))
        return f"{key} = {self._format_yarax_meta_literal(node.value)}"

    def _write_meta_section(self, meta: object) -> None:
        if not meta:
            return
        if not isinstance(meta, dict | list | tuple):
            msg = "Rule meta must be a dictionary, list, or tuple for YARA-X output"
            raise TypeError(msg)
        self._writeline("meta:")
        self._indent()
        if isinstance(meta, dict):
            for key, value in meta.items():
                self._writeline(self._format_meta_value(key, value))
        else:
            for item in meta:
                if not (hasattr(item, "key") and hasattr(item, "value")):
                    msg = "Rule meta must contain meta entries for YARA-X output"
                    raise TypeError(msg)
                self._emit_yarax_meta_comments(item)
                self._writeline(
                    self._format_meta_value(item.key, item.value, getattr(item, "scope", None))
                )
        self._dedent()
        self._writeline()

    def _emit_yarax_meta_comments(self, item: Any) -> None:
        for comment in getattr(item, "leading_comments", []) or []:
            self._writeline(self.visit(comment))

    def _format_meta_value(self, key: str, value: Any, scope: object | None = None) -> str:
        rendered_key = format_meta_key(key, scope)
        return f"{rendered_key} = {self._format_yarax_meta_literal(value)}"

    def _format_yarax_meta_literal(self, value: Any) -> str:
        if isinstance(value, str):
            return f'"{escape_string_literal(value)}"'
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int):
            return format_integer_literal(value)
        if isinstance(value, float) and math.isfinite(value):
            return str(value)
        msg = f"Invalid YARA-X meta value type '{type(value).__name__}'"
        raise TypeError(msg)

    def _render_local_identifier(self, identifier: str, field_name: str) -> str:
        return format_yarax_local_identifier(identifier, field_name)

    def _require_expression(self, expression: Expression | None, field_name: str) -> Expression:
        if expression is None:
            msg = f"{field_name} is required for YARA-X code generation"
            raise ValueError(msg)
        return expression

    def _visit_required_expression(self, expression: Expression | None, field_name: str) -> str:
        return self.visit(self._require_expression(expression, field_name))

    def visit_with_statement(self, node: WithStatement) -> str:
        """Generate code for with statement."""
        # Generate declarations
        validate_expression_collection(node.declarations, "WithStatement declarations")
        declarations = []
        for decl in node.declarations:
            declarations.append(self.visit(decl))

        decl_str = ", ".join(declarations)

        # Generate body
        local_names = contextual_local_identifier_names(
            *(declaration.identifier for declaration in node.declarations)
        )
        with contextual_local_identifiers(self, local_names):
            body_str = self.visit(node.body)

        return f"with {decl_str}: {body_str}"

    def visit_with_declaration(self, node: WithDeclaration) -> str:
        """Generate code for with declaration."""
        identifier = self._render_local_identifier(node.identifier, "local variable")
        value_str = self.visit(node.value)
        return f"{identifier} = {value_str}"

    def visit_array_comprehension(self, node: ArrayComprehension) -> str:
        """Generate code for array comprehension."""
        expression = self._require_expression(node.expression, "Array comprehension expression")
        iter_str = self._visit_required_expression(node.iterable, "Array comprehension iterable")

        variable = validate_yara_identifier(node.variable, "local variable")
        local_names = contextual_local_identifier_names(node.variable)
        with contextual_local_identifiers(self, local_names):
            expr_str = self.visit(expression)
            cond_str = self.visit(node.condition) if node.condition is not None else None

        result = f"[{expr_str} for {variable} in {iter_str}"

        if cond_str is not None:
            result += f" if {cond_str}"

        result += "]"
        return result

    def visit_dict_comprehension(self, node: DictComprehension) -> str:
        """Generate code for dict comprehension."""
        key_expression = self._require_expression(node.key_expression, "Dict comprehension key")
        value_expression = self._require_expression(
            node.value_expression, "Dict comprehension value"
        )
        iter_str = self._visit_required_expression(node.iterable, "Dict comprehension iterable")

        key_variable = validate_yara_identifier(node.key_variable, "local variable")
        if node.value_variable is not None:
            # Two variables (k, v pattern)
            value_variable = validate_yara_identifier(node.value_variable, "local variable")
            var_str = f"{key_variable}, {value_variable}"
        else:
            # Single variable
            var_str = key_variable
        local_names = contextual_local_identifier_names(node.key_variable, node.value_variable)
        with contextual_local_identifiers(self, local_names):
            key_str = self.visit(key_expression)
            value_str = self.visit(value_expression)
            cond_str = self.visit(node.condition) if node.condition is not None else None

        result = f"{{{key_str}: {value_str} for {var_str} in {iter_str}"

        if cond_str is not None:
            result += f" if {cond_str}"

        result += "}"
        return result

    def visit_tuple_expression(self, node: TupleExpression) -> str:
        """Generate code for tuple expression."""
        validate_expression_collection(node.elements, "TupleExpression elements")
        if not node.elements:
            return "()"

        elements = [self.visit(elem) for elem in node.elements]

        # Single element tuple needs trailing comma
        if len(elements) == 1:
            return f"({elements[0]},)"

        return f"({', '.join(elements)})"

    def visit_tuple_indexing(self, node: TupleIndexing) -> str:
        """Generate code for tuple indexing."""
        validate_tuple_indexing_target(node.tuple_expr)
        tuple_str = render_postfix_index_target(self, node.tuple_expr)
        index_str = self.visit(node.index)
        from yaraast.ast.expressions import FunctionCall, Identifier, ParenthesesExpression
        from yaraast.yarax.ast_nodes import TupleExpression

        if isinstance(
            node.tuple_expr, FunctionCall | Identifier | TupleExpression | ParenthesesExpression
        ):
            return f"{tuple_str}[{index_str}]"
        return f"({tuple_str})[{index_str}]"

    def visit_function_call(self, node: Any) -> str:
        """Generate YARA-X function calls without libyara function whitelisting."""
        validate_expression_collection(node.arguments, "FunctionCall arguments")
        callee = render_function_call_callee(self, node)
        arguments = ", ".join(self.visit(argument) for argument in node.arguments)
        return f"{callee}({arguments})"

    def visit_list_expression(self, node: ListExpression) -> str:
        """Generate code for list expression."""
        validate_expression_collection(node.elements, "ListExpression elements")
        elements = []
        for elem in node.elements:
            # Handle all elements (including spread operators) uniformly
            elements.append(self.visit(elem))

        return f"[{', '.join(elements)}]"

    def visit_dict_expression(self, node: DictExpression) -> str:
        """Generate code for dict expression."""
        from yaraast.yarax.ast_nodes import SpreadOperator

        validate_expression_collection(node.items, "DictExpression items")
        items = []
        for item in node.items:
            # Check for spread operator (special case)
            if isinstance(item.value, SpreadOperator):
                items.append(self.visit(item.value))
            else:
                items.append(self.visit(item))

        return f"{{{', '.join(items)}}}"

    def visit_dict_item(self, node: DictItem) -> str:
        """Generate code for dict item."""
        key_str = self.visit(node.key)
        value_str = self.visit(node.value)
        return f"{key_str}: {value_str}"

    def visit_slice_expression(self, node: SliceExpression) -> str:
        """Generate code for slice expression."""
        validate_slice_target(node.target)
        target_str = render_postfix_index_target(self, node.target)
        from yaraast.ast.expressions import FunctionCall, Identifier, ParenthesesExpression
        from yaraast.yarax.ast_nodes import ListExpression, TupleExpression

        if not isinstance(
            node.target,
            FunctionCall | Identifier | ListExpression | ParenthesesExpression | TupleExpression,
        ):
            target_str = f"({target_str})"

        slice_parts = [
            self.visit(node.start) if node.start is not None else "",
            self.visit(node.stop) if node.stop is not None else "",
        ]

        if node.step is not None:
            slice_parts.append(self.visit(node.step))

        slice_str = ":".join(slice_parts)

        return f"{target_str}[{slice_str}]"

    def visit_lambda_expression(self, node: LambdaExpression) -> str:
        """Generate code for lambda expression."""
        validate_expression_collection(node.parameters, "LambdaExpression parameters")
        params = ", ".join(
            validate_yara_identifier(parameter, "local variable") for parameter in node.parameters
        )
        local_names = contextual_local_identifier_names(*node.parameters)
        with contextual_local_identifiers(self, local_names):
            body_str = self.visit(node.body)

        if params:
            return f"lambda {params}: {body_str}"
        return f"lambda: {body_str}"

    def visit_pattern_match(self, node: PatternMatch) -> str:
        """Generate code for pattern match."""
        value_str = self.visit(node.value)

        lines = [f"match {value_str} {{"]
        case_indent = " " * self.indent_size

        # Generate cases
        validate_expression_collection(node.cases, "PatternMatch cases")
        for case in node.cases:
            case_str = self.visit(case)
            lines.append(f"{case_indent}{case_str},")

        # Generate default case if present
        if node.default is not None:
            default_str = self._indent_continuation_lines(self.visit(node.default))
            lines.append(f"{case_indent}_ => {default_str},")

        lines.append("}")

        return "\n".join(lines)

    def visit_match_case(self, node: MatchCase) -> str:
        """Generate code for match case."""
        pattern_str = self.visit(node.pattern)
        result_str = self._indent_continuation_lines(self.visit(node.result))
        return f"{pattern_str} => {result_str}"

    def _indent_continuation_lines(self, text: str) -> str:
        continuation_indent = " " * self.indent_size
        return text.replace("\n", f"\n{continuation_indent}")

    def visit_spread_operator(self, node: SpreadOperator) -> str:
        """Generate code for spread operator."""
        expr_str = self.visit(node.expression)

        if node.is_dict:
            return f"**{expr_str}"
        return f"...{expr_str}"
