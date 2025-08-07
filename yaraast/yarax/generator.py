"""YARA-X code generator for new syntax features."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast import CodeGenerator as BaseGenerator

if TYPE_CHECKING:
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

    def visit_with_statement(self, node: WithStatement) -> str:
        """Generate code for with statement."""
        # Generate declarations
        declarations = []
        for decl in node.declarations:
            declarations.append(self.visit(decl))

        decl_str = ", ".join(declarations)

        # Generate body
        body_str = self.visit(node.body)

        return f"with {decl_str}: {body_str}"

    def visit_with_declaration(self, node: WithDeclaration) -> str:
        """Generate code for with declaration."""
        value_str = self.visit(node.value)
        return f"{node.identifier} = {value_str}"

    def visit_array_comprehension(self, node: ArrayComprehension) -> str:
        """Generate code for array comprehension."""
        expr_str = self.visit(node.expression)
        iter_str = self.visit(node.iterable)

        result = f"[{expr_str} for {node.variable} in {iter_str}"

        if node.condition:
            cond_str = self.visit(node.condition)
            result += f" if {cond_str}"

        result += "]"
        return result

    def visit_dict_comprehension(self, node: DictComprehension) -> str:
        """Generate code for dict comprehension."""
        key_str = self.visit(node.key_expression)
        value_str = self.visit(node.value_expression)
        iter_str = self.visit(node.iterable)

        if node.value_variable:
            # Two variables (k, v pattern)
            var_str = f"{node.key_variable}, {node.value_variable}"
        else:
            # Single variable
            var_str = node.key_variable

        result = f"{{{key_str}: {value_str} for {var_str} in {iter_str}"

        if node.condition:
            cond_str = self.visit(node.condition)
            result += f" if {cond_str}"

        result += "}"
        return result

    def visit_tuple_expression(self, node: TupleExpression) -> str:
        """Generate code for tuple expression."""
        if not node.elements:
            return "()"

        elements = [self.visit(elem) for elem in node.elements]

        # Single element tuple needs trailing comma
        if len(elements) == 1:
            return f"({elements[0]},)"

        return f"({', '.join(elements)})"

    def visit_tuple_indexing(self, node: TupleIndexing) -> str:
        """Generate code for tuple indexing."""
        tuple_str = self.visit(node.tuple_expr)
        index_str = self.visit(node.index)

        # If tuple_expr is a function call or identifier, don't add extra parens
        from yaraast.ast.expressions import FunctionCall, Identifier

        if isinstance(node.tuple_expr, FunctionCall | Identifier | TupleExpression):
            return f"{tuple_str}[{index_str}]"

        # Otherwise wrap in parens to be safe
        return f"({tuple_str})[{index_str}]"

    def visit_list_expression(self, node: ListExpression) -> str:
        """Generate code for list expression."""
        elements = []
        for elem in node.elements:
            # Handle all elements (including spread operators) uniformly
            elements.append(self.visit(elem))

        return f"[{', '.join(elements)}]"

    def visit_dict_expression(self, node: DictExpression) -> str:
        """Generate code for dict expression."""
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
        target_str = self.visit(node.target)

        # Build slice notation
        slice_parts = []

        # Start
        if node.start:
            slice_parts.append(self.visit(node.start))
        else:
            slice_parts.append("")

        # Stop
        if node.stop:
            slice_parts.append(self.visit(node.stop))
        else:
            slice_parts.append("")

        # Step (only include if present)
        if node.step:
            slice_parts.append(self.visit(node.step))
        elif len(slice_parts) == 2 and not slice_parts[1]:
            # Remove trailing empty stop if no step
            slice_parts = slice_parts[:1]

        slice_str = ":".join(slice_parts)

        return f"{target_str}[{slice_str}]"

    def visit_lambda_expression(self, node: LambdaExpression) -> str:
        """Generate code for lambda expression."""
        params = ", ".join(node.parameters)
        body_str = self.visit(node.body)

        if params:
            return f"lambda {params}: {body_str}"
        return f"lambda: {body_str}"

    def visit_pattern_match(self, node: PatternMatch) -> str:
        """Generate code for pattern match."""
        value_str = self.visit(node.value)

        lines = [f"match {value_str} {{"]

        # Generate cases
        for case in node.cases:
            case_str = self.visit(case)
            lines.append(f"    {case_str},")

        # Generate default case if present
        if node.default:
            default_str = self.visit(node.default)
            lines.append(f"    _ => {default_str},")

        lines.append("}")

        return "\n".join(lines)

    def visit_match_case(self, node: MatchCase) -> str:
        """Generate code for match case."""
        pattern_str = self.visit(node.pattern)
        result_str = self.visit(node.result)
        return f"{pattern_str} => {result_str}"

    def visit_spread_operator(self, node: SpreadOperator) -> str:
        """Generate code for spread operator."""
        expr_str = self.visit(node.expression)

        if node.is_dict:
            return f"**{expr_str}"
        return f"...{expr_str}"
