"""String formatter helpers for CLI AST output."""

from yaraast.cli.visitors.formatters_helpers import format_int_literal, truncate_string


class ConditionStringFormatter:
    """Helper class to format condition strings with reduced complexity."""

    ELLIPSIS_PARENTHESES = "(...)"

    def format_condition(self, condition, depth=0) -> str:
        """Main entry point for condition formatting."""
        if depth > 3:
            return "..."

        if not hasattr(condition, "__class__"):
            return "true"

        class_name = condition.__class__.__name__

        formatters = {
            "BooleanLiteral": self._format_boolean_literal,
            "OfExpression": self._format_of_expression,
            "BinaryExpression": lambda c, d: self._format_binary_expression(c, d),
            "Identifier": self._format_identifier,
            "StringIdentifier": self._format_string_identifier,
            "StringCount": self._format_string_count,
            "StringOffset": self._format_string_offset,
            "StringLength": self._format_string_length,
            "FunctionCall": lambda c, d: self._format_function_call(c, d),
            "ParenthesesExpression": lambda c, d: self._format_parentheses(c, d),
            "IntegerLiteral": self._format_integer_literal,
            "StringLiteral": self._format_string_literal,
            "MemberAccess": lambda c, d: self._format_member_access(c, d),
            "ArrayAccess": lambda c, d: self._format_array_access(c, d),
            "ForExpression": self._format_for_expression,
            "ForOfExpression": lambda c, d: "for ... of ...",
        }

        formatter = formatters.get(class_name, lambda c, d: f"<{class_name}>")
        return formatter(condition, depth)

    def _format_boolean_literal(self, condition, _depth):
        return str(condition.value).lower() if hasattr(condition, "value") else "true"

    def _format_of_expression(self, condition, _depth):
        quantifier = getattr(condition, "quantifier", "any")
        string_set = "them"
        if hasattr(condition, "string_set") and hasattr(condition.string_set, "name"):
            string_set = condition.string_set.name
        return f"{quantifier} of {string_set}"

    def _format_binary_expression(self, condition, depth):
        op = getattr(condition, "operator", "and")

        if depth == 0:
            return self._format_top_level_binary(condition, op, depth)
        return self._format_nested_binary(condition, op, depth)

    def _format_top_level_binary(self, condition, op, depth):
        if op in ["and", "or"]:
            return self._format_logical_expression(condition, op)
        return self._format_simple_binary(condition, op, depth)

    def _format_logical_expression(self, condition, op):
        parts = []
        self._collect_binary_parts(condition, op, parts, 0)
        parts = [p for p in parts if p and p != "..."]

        if not parts:
            return self._format_simple_binary(condition, op, 0)

        return self._format_parts_list(parts, op)

    def _format_parts_list(self, parts, op):
        """Format a list of expression parts."""
        hash_prefix = "hash."
        is_hash_condition = any(hash_prefix in p and "==" in p for p in parts[:3] if p)

        if is_hash_condition:
            return self._format_hash_condition(parts, op)
        if len(parts) > 8:
            return self._format_long_condition(parts, op)
        return f" {op} ".join(parts)

    def _format_hash_condition(self, parts, op):
        """Format hash comparison conditions."""
        if len(parts) <= 15:
            return f" {op} ".join(parts)
        if len(parts) <= 25:
            return f" {op} ".join(parts[:10]) + f" {op} ..."
        return f" {op} ".join(parts[:8]) + f" {op} ... {op} " + f" {op} ".join(parts[-2:])

    def _format_long_condition(self, parts, op):
        """Format very long conditions."""
        return f" {op} ".join(parts[:5]) + f" {op} ... {op} " + f" {op} ".join(parts[-2:])

    def _format_simple_binary(self, condition, op, _depth):
        left = self._expr_to_str(condition.left, 0) if hasattr(condition, "left") else "?"
        right = self._expr_to_str(condition.right, 0) if hasattr(condition, "right") else "?"
        return f"{left} {op} {right}"

    def _format_nested_binary(self, condition, op, depth):
        left_str = (
            self.format_condition(condition.left, depth + 1)
            if hasattr(condition, "left")
            else "..."
        )
        right_str = (
            self.format_condition(condition.right, depth + 1)
            if hasattr(condition, "right")
            else "..."
        )
        return f"{left_str} {op} {right_str}"

    def _format_identifier(self, condition, _depth):
        return getattr(condition, "name", "identifier")

    def _format_string_identifier(self, condition, _depth):
        return getattr(condition, "name", "$string")

    def _format_string_count(self, condition, _depth):
        name = getattr(condition, "name", "string")
        return f"#{name}"

    def _format_string_offset(self, condition, _depth):
        name = getattr(condition, "name", "string")
        return f"@{name}"

    def _format_string_length(self, condition, _depth):
        name = getattr(condition, "name", "string")
        return f"!{name}"

    def _format_function_call(self, condition, depth):
        func = getattr(condition, "function", "func")
        args = self._format_function_args(condition, depth)
        return f"{func}({args})"

    def _format_function_args(self, condition, depth):
        if not (hasattr(condition, "arguments") and condition.arguments):
            return ""

        arg_strs = []
        for arg in condition.arguments[:2]:
            arg_strs.append(self.format_condition(arg, depth + 1))
        args = ", ".join(arg_strs)

        if len(condition.arguments) > 2:
            args += ", ..."
        return args

    def _format_parentheses(self, condition, depth):
        if hasattr(condition, "expression"):
            inner = self.format_condition(condition.expression, depth + 1)
            return f"({inner})"
        return self.ELLIPSIS_PARENTHESES

    def _format_integer_literal(self, condition, _depth):
        return format_int_literal(getattr(condition, "value", 0))

    def _format_string_literal(self, condition, _depth):
        val = truncate_string(getattr(condition, "value", ""), 20)
        return f'"{val}"'

    def _format_member_access(self, condition, depth):
        obj = (
            self.format_condition(condition.object, depth + 1)
            if hasattr(condition, "object")
            else "obj"
        )
        member = getattr(condition, "member", "member")
        return f"{obj}.{member}"

    def _format_array_access(self, condition, depth):
        arr = (
            self.format_condition(condition.array, depth + 1)
            if hasattr(condition, "array")
            else "arr"
        )
        idx = (
            self.format_condition(condition.index, depth + 1)
            if hasattr(condition, "index")
            else "0"
        )
        return f"{arr}[{idx}]"

    def _format_for_expression(self, condition, _depth):
        var = getattr(condition, "identifier", "i")
        return f"for {var} of ..."

    def _collect_binary_parts(self, expr, target_op, parts, depth):
        """Collect parts of a binary expression with the same operator."""
        if depth > 500:
            parts.append("...")
            return

        if not hasattr(expr, "__class__"):
            parts.append("...")
            return

        class_name = expr.__class__.__name__
        if (
            class_name == "BinaryExpression"
            and hasattr(expr, "operator")
            and expr.operator == target_op
        ):
            if hasattr(expr, "left"):
                self._collect_binary_parts(expr.left, target_op, parts, depth + 1)
            if hasattr(expr, "right"):
                self._collect_binary_parts(expr.right, target_op, parts, depth + 1)
        else:
            expr_str = self._expr_to_str(expr, 0)
            parts.append(expr_str)

    def _expr_to_str(self, expr, depth=0) -> str:
        """Convert expression to string with fresh depth counter."""
        formatter = ExpressionStringFormatter()
        return formatter.format_expression(expr, depth)


class ExpressionStringFormatter:
    """Helper class to format expression strings with reduced complexity."""

    ELLIPSIS_PARENTHESES = "(...)"

    def format_expression(self, expr, depth=0) -> str:
        """Format an expression to string representation."""
        if depth > 5:
            return "..."

        if not expr or not hasattr(expr, "__class__"):
            return "..."

        class_name = expr.__class__.__name__

        formatters = {
            "BinaryExpression": self._format_binary_expression,
            "ParenthesesExpression": self._format_parentheses_expression,
            "FunctionCall": self._format_function_call,
            "StringIdentifier": self._format_string_identifier,
            "Identifier": self._format_identifier,
            "IntegerLiteral": self._format_integer_literal,
            "StringLiteral": self._format_string_literal,
            "OfExpression": self._format_of_expression,
            "StringCount": self._format_string_count,
            "StringOffset": self._format_string_offset,
            "ForExpression": self._format_for_expression,
            "MemberAccess": self._format_member_access,
            "RangeExpression": self._format_range_expression,
        }

        formatter = formatters.get(class_name, lambda e, d: f"<{class_name[:10]}>")
        return formatter(expr, depth)

    def _format_binary_expression(self, expr, depth):
        op = getattr(expr, "operator", "?")
        left = self.format_expression(expr.left, depth + 1) if hasattr(expr, "left") else "?"
        right = self.format_expression(expr.right, depth + 1) if hasattr(expr, "right") else "?"
        return f"{left} {op} {right}"

    def _format_parentheses_expression(self, expr, depth):
        inner = (
            self.format_expression(expr.expression, depth + 1)
            if hasattr(expr, "expression")
            else "..."
        )
        return f"({inner})"

    def _format_function_call(self, expr, depth):
        func = getattr(expr, "function", "func")
        args = self._format_function_args(expr, depth)
        return f"{func}({args})"

    def _format_function_args(self, expr, depth):
        if not (hasattr(expr, "arguments") and expr.arguments):
            return ""

        args = ", ".join(self.format_expression(arg, depth + 1) for arg in expr.arguments[:2])
        if len(expr.arguments) > 2:
            args += ", ..."
        return args

    def _format_string_identifier(self, expr, _depth):
        return getattr(expr, "name", "$?")

    def _format_identifier(self, expr, _depth):
        return getattr(expr, "name", "?")

    def _format_integer_literal(self, expr, _depth):
        return format_int_literal(getattr(expr, "value", 0))

    def _format_string_literal(self, expr, _depth):
        val = truncate_string(getattr(expr, "value", ""), 30)
        return f'"{val}"'

    def _format_of_expression(self, expr, depth):
        quantifier = getattr(expr, "quantifier", "any")
        string_set = self._format_string_set(expr, depth)
        return f"{quantifier} of {string_set}"

    def _format_string_set(self, expr, depth):
        """Format the string set part of an of expression."""
        if not hasattr(expr, "string_set"):
            return "them"

        string_set = expr.string_set
        if hasattr(string_set, "name"):
            return string_set.name

        if not hasattr(string_set, "__class__"):
            return "them"

        s_class = string_set.__class__.__name__
        if s_class == "SetExpression":
            return self._format_set_expression(string_set, depth)
        if s_class == "StringWildcard":
            return self._format_string_wildcard(string_set)
        return "them"

    def _format_set_expression(self, string_set, depth):
        """Format a set expression like ($a, $b, $c)."""
        if not hasattr(string_set, "elements"):
            return self.ELLIPSIS_PARENTHESES

        elements = []
        for el in string_set.elements[:5]:
            if hasattr(el, "name"):
                elements.append(el.name)
            else:
                elements.append(self.format_expression(el, depth + 1))

        if len(string_set.elements) > 5:
            elements.append("...")

        return "(" + ", ".join(elements) + ")"

    def _format_string_wildcard(self, string_set):
        """Format a string wildcard like $a*."""
        if hasattr(string_set, "prefix"):
            return f"(${string_set.prefix}*)"
        return "($*)"

    def _format_string_count(self, expr, _depth):
        return f"#{getattr(expr, 'string_id', '?')}"

    def _format_string_offset(self, expr, depth):
        sid = getattr(expr, "string_id", "?")
        if hasattr(expr, "index") and expr.index is not None:
            idx = self.format_expression(expr.index, depth + 1)
            return f"@{sid}[{idx}]"
        return f"@{sid}"

    def _format_for_expression(self, expr, depth):
        quantifier = getattr(expr, "quantifier", "any")
        variable = getattr(expr, "variable", "i")
        iterable = (
            self.format_expression(expr.iterable, depth + 1) if hasattr(expr, "iterable") else "..."
        )
        body = self.format_expression(expr.body, depth + 1) if hasattr(expr, "body") else "..."
        return f"for {quantifier} {variable} in {iterable} : ({body})"

    def _format_member_access(self, expr, depth):
        obj = self.format_expression(expr.object, depth + 1) if hasattr(expr, "object") else "?"
        member = getattr(expr, "member", "?")
        return f"{obj}.{member}"

    def _format_range_expression(self, expr, depth):
        low = self.format_expression(expr.low, depth + 1) if hasattr(expr, "low") else "0"
        high = self.format_expression(expr.high, depth + 1) if hasattr(expr, "high") else "..."
        return f"({low}..{high})"


class DetailedNodeStringFormatter:
    """Helper class to format detailed node strings."""

    ELLIPSIS_PARENTHESES = "(...)"

    def format_node(self, node, depth=0) -> str:
        """Format a node to detailed string representation."""
        if not node or depth > 2:
            return "..."

        class_name = node.__class__.__name__

        formatters = {
            "StringIdentifier": self._format_string_identifier,
            "IntegerLiteral": self._format_integer_literal,
            "BooleanLiteral": self._format_boolean_literal,
            "StringLiteral": self._format_string_literal,
            "FunctionCall": lambda n, d: self._format_function_call(n, d),
            "BinaryExpression": lambda n, d: self._format_binary_expression(n, d),
            "ParenthesesExpression": lambda n, d: self._format_parentheses(n, d),
            "Identifier": self._format_identifier,
            "MemberAccess": lambda n, d: self._format_member_access(n, d),
        }

        formatter = formatters.get(class_name, lambda n, d: "...")
        return formatter(node, depth)

    def _format_string_identifier(self, node, _depth):
        return getattr(node, "name", "$...")

    def _format_integer_literal(self, node, _depth):
        return str(getattr(node, "value", 0))

    def _format_boolean_literal(self, node, _depth):
        value = getattr(node, "value", True)
        return str(value).lower()

    def _format_string_literal(self, node, _depth):
        val = truncate_string(getattr(node, "value", ""), 15)
        return f'"{val}"'

    def _format_function_call(self, node, depth):
        func = getattr(node, "function", "func")
        args = self._format_function_args(node, depth)
        return f"{func}({args})"

    def _format_function_args(self, node, depth):
        if not (hasattr(node, "arguments") and node.arguments):
            return ""
        return self.format_node(node.arguments[0], depth + 1)

    def _format_binary_expression(self, node, depth):
        if depth >= 2:
            return self.ELLIPSIS_PARENTHESES
        formatter = ConditionStringFormatter()
        return formatter.format_condition(node, depth)

    def _format_parentheses(self, node, depth):
        if hasattr(node, "expression"):
            inner = self.format_node(node.expression, depth + 1)
            return f"({inner})"
        return self.ELLIPSIS_PARENTHESES

    def _format_identifier(self, node, _depth):
        return getattr(node, "name", "id")

    def _format_member_access(self, node, depth):
        obj = self.format_node(node.object, depth + 1) if hasattr(node, "object") else "obj"
        member = getattr(node, "member", "member")
        return f"{obj}.{member}"
