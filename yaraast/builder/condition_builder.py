"""Fluent builder for conditions."""

from __future__ import annotations

from copy import deepcopy
import re

from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    Expression,
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
from yaraast.builder.file_builder_validation import validate_identifier, validate_identifier_path
from yaraast.errors import ValidationError

_STRING_REFERENCE_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")


def _identifier_path_expression(name: str) -> Expression:
    validate_identifier_path(name, "identifier")
    parts = name.split(".")
    expr: Expression = Identifier(name=parts[0])
    for member in parts[1:]:
        expr = MemberAccess(object=expr, member=member)
    return expr


class ConditionBuilder:
    """Fluent builder for constructing conditions."""

    def __init__(self, expr: Expression | None = None) -> None:
        self._expression = expr

    @staticmethod
    def _integer_literal(value: int) -> IntegerLiteral:
        if not isinstance(value, int) or isinstance(value, bool):
            msg = f"Invalid integer literal value: {value}"
            raise TypeError(msg)
        return IntegerLiteral(value=value)

    # String references
    def string(self, identifier: str) -> ConditionBuilder:
        """Reference a string identifier."""
        self._validate_string_reference(identifier)
        return ConditionBuilder(StringIdentifier(name=identifier))

    def string_count(self, identifier: str) -> ConditionBuilder:
        """Reference string count (#string)."""
        return ConditionBuilder(
            StringCount(string_id=self._normalize_string_reference(identifier, "#"))
        )

    def string_offset(self, identifier: str, index: int | None = None) -> ConditionBuilder:
        """Reference string offset (@string or @string[i])."""
        index_expr = self._integer_literal(index) if index is not None else None
        return ConditionBuilder(
            StringOffset(
                string_id=self._normalize_string_reference(identifier, "@"),
                index=index_expr,
            ),
        )

    def string_length(self, identifier: str, index: int | None = None) -> ConditionBuilder:
        """Reference string length (!string or !string[i])."""
        index_expr = self._integer_literal(index) if index is not None else None
        return ConditionBuilder(
            StringLength(
                string_id=self._normalize_string_reference(identifier, "!"),
                index=index_expr,
            ),
        )

    # Literals
    def true(self) -> ConditionBuilder:
        """Boolean true."""
        return ConditionBuilder(BooleanLiteral(value=True))

    def false(self) -> ConditionBuilder:
        """Boolean false."""
        return ConditionBuilder(BooleanLiteral(value=False))

    def integer(self, value: int) -> ConditionBuilder:
        """Integer literal."""
        return ConditionBuilder(self._integer_literal(value))

    def filesize(self) -> ConditionBuilder:
        """Filesize keyword."""
        return ConditionBuilder(Identifier(name="filesize"))

    def entrypoint(self) -> ConditionBuilder:
        """Entrypoint keyword."""
        return ConditionBuilder(Identifier(name="entrypoint"))

    def identifier(self, name: str) -> ConditionBuilder:
        """Generic identifier."""
        return ConditionBuilder(_identifier_path_expression(name))

    def range(self, start: int | ConditionBuilder, end: int | ConditionBuilder) -> ConditionBuilder:
        """Create a range expression."""
        start_expr = self._to_integer_expression(start)
        end_expr = self._to_integer_expression(end)
        return ConditionBuilder(RangeExpression(low=start_expr, high=end_expr))

    def member_access(self, obj: ConditionBuilder | Expression, member: str) -> ConditionBuilder:
        """Member access (obj.member)."""
        validate_identifier(member, "member")
        obj_expr = self._to_expression(obj)
        return ConditionBuilder(MemberAccess(object=obj_expr, member=member))

    def array_access(
        self,
        array: ConditionBuilder | Expression,
        index: int | ConditionBuilder | Expression,
    ) -> ConditionBuilder:
        """Array access (array[index])."""
        array_expr = self._to_expression(array)
        index_expr = self._to_integer_expression(index)
        return ConditionBuilder(ArrayAccess(array=array_expr, index=index_expr))

    # Logical operators
    def and_(self, other: ConditionBuilder | Expression) -> ConditionBuilder:
        """Logical AND."""
        if self._expression is None:
            msg = "Cannot apply AND to empty expression"
            raise ValidationError(msg)

        right = self._to_logical_operand(other)
        return ConditionBuilder(
            BinaryExpression(left=self._expression, operator="and", right=right),
        )

    def or_(self, other: ConditionBuilder | Expression) -> ConditionBuilder:
        """Logical OR."""
        if self._expression is None:
            msg = "Cannot apply OR to empty expression"
            raise ValidationError(msg)

        right = self._to_logical_operand(other)
        return ConditionBuilder(
            BinaryExpression(left=self._expression, operator="or", right=right),
        )

    def not_(self) -> ConditionBuilder:
        """Logical NOT."""
        if self._expression is None:
            msg = "Cannot apply NOT to empty expression"
            raise ValidationError(msg)

        return ConditionBuilder(
            UnaryExpression(operator="not", operand=self._expression),
        )

    # Comparison operators
    def eq(self, other: ConditionBuilder | Expression | int | str) -> ConditionBuilder:
        """Equal comparison."""
        return self._binary_op("==", other)

    def ne(self, other: ConditionBuilder | Expression | int | str) -> ConditionBuilder:
        """Not equal comparison."""
        return self._binary_op("!=", other)

    def lt(self, other: ConditionBuilder | Expression | int) -> ConditionBuilder:
        """Less than comparison."""
        return self._integer_binary_op("<", other)

    def le(self, other: ConditionBuilder | Expression | int) -> ConditionBuilder:
        """Less than or equal comparison."""
        return self._integer_binary_op("<=", other)

    def gt(self, other: ConditionBuilder | Expression | int) -> ConditionBuilder:
        """Greater than comparison."""
        return self._integer_binary_op(">", other)

    def ge(self, other: ConditionBuilder | Expression | int) -> ConditionBuilder:
        """Greater than or equal comparison."""
        return self._integer_binary_op(">=", other)

    # String operations
    def contains(self, pattern: str | ConditionBuilder | Expression) -> ConditionBuilder:
        """String contains."""
        return self._string_binary_op("contains", pattern)

    def matches(self, pattern: str | ConditionBuilder | Expression) -> ConditionBuilder:
        """String matches regex."""
        return self._string_binary_op("matches", pattern)

    def startswith(self, pattern: str | ConditionBuilder | Expression) -> ConditionBuilder:
        """String starts with."""
        return self._string_binary_op("startswith", pattern)

    def endswith(self, pattern: str | ConditionBuilder | Expression) -> ConditionBuilder:
        """String ends with."""
        return self._string_binary_op("endswith", pattern)

    def icontains(self, pattern: str | ConditionBuilder | Expression) -> ConditionBuilder:
        """Case-insensitive contains."""
        return self._string_binary_op("icontains", pattern)

    def iequals(self, pattern: str | ConditionBuilder | Expression) -> ConditionBuilder:
        """Case-insensitive equals."""
        return self._string_binary_op("iequals", pattern)

    # Special conditions
    def at(self, offset: int | ConditionBuilder) -> ConditionBuilder:
        """String at offset."""
        if self._expression is None or not isinstance(self._expression, StringIdentifier):
            msg = "'at' can only be used with string identifiers"
            raise ValidationError(msg)

        offset_expr = self._to_integer_expression(offset)
        return ConditionBuilder(
            AtExpression(string_id=self._expression.name, offset=offset_expr),
        )

    def in_range(
        self,
        start: int | ConditionBuilder,
        end: int | ConditionBuilder,
    ) -> ConditionBuilder:
        """String in range."""
        if self._expression is None or not isinstance(self._expression, StringIdentifier):
            msg = "'in' can only be used with string identifiers"
            raise ValidationError(msg)

        start_expr = self._to_integer_expression(start)
        end_expr = self._to_integer_expression(end)
        range_expr = RangeExpression(low=start_expr, high=end_expr)

        return ConditionBuilder(
            InExpression(subject=self._expression.name, range=range_expr),
        )

    # Quantifiers
    def any_of(self, *strings: str) -> ConditionBuilder:
        """Any of strings."""
        self._validate_string_set_args(strings)
        string_set: Expression
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements: list[Expression] = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(
            OfExpression(quantifier=StringLiteral(value="any"), string_set=string_set),
        )

    def all_of(self, *strings: str) -> ConditionBuilder:
        """All of strings."""
        self._validate_string_set_args(strings)
        string_set: Expression
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements: list[Expression] = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(
            OfExpression(quantifier=StringLiteral(value="all"), string_set=string_set),
        )

    def n_of(self, n: int, *strings: str) -> ConditionBuilder:
        """N of strings."""
        self._validate_string_set_args(strings)
        string_set: Expression
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements: list[Expression] = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(
            OfExpression(quantifier=self._integer_literal(n), string_set=string_set),
        )

    # For loops
    def for_any(
        self,
        var: str,
        iterable: ConditionBuilder | Expression,
        condition: ConditionBuilder | Expression,
    ) -> ConditionBuilder:
        """For any loop."""
        validate_identifier(var, "loop variable")
        iter_expr = self._to_expression(iterable)
        cond_expr = self._to_expression(condition)

        return ConditionBuilder(
            ForExpression(
                quantifier="any",
                variable=var,
                iterable=iter_expr,
                body=cond_expr,
            ),
        )

    def for_all(
        self,
        var: str,
        iterable: ConditionBuilder | Expression,
        condition: ConditionBuilder | Expression,
    ) -> ConditionBuilder:
        """For all loop."""
        validate_identifier(var, "loop variable")
        iter_expr = self._to_expression(iterable)
        cond_expr = self._to_expression(condition)

        return ConditionBuilder(
            ForExpression(
                quantifier="all",
                variable=var,
                iterable=iter_expr,
                body=cond_expr,
            ),
        )

    # Arithmetic operations
    def add(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Addition."""
        return self._integer_binary_op("+", other)

    def sub(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Subtraction."""
        return self._integer_binary_op("-", other)

    def mul(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Multiplication."""
        return self._integer_binary_op("*", other)

    def div(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Division."""
        return self._integer_binary_op("\\", other)

    def mod(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Modulo."""
        return self._integer_binary_op("%", other)

    # Bitwise operations
    def bitwise_and(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Bitwise AND."""
        return self._integer_binary_op("&", other)

    def bitwise_or(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Bitwise OR."""
        return self._integer_binary_op("|", other)

    def bitwise_xor(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Bitwise XOR."""
        return self._integer_binary_op("^", other)

    def bitwise_not(self) -> ConditionBuilder:
        """Bitwise NOT."""
        if self._expression is None:
            msg = "Cannot apply bitwise NOT to empty expression"
            raise ValidationError(msg)

        return ConditionBuilder(UnaryExpression(operator="~", operand=self._expression))

    def shift_left(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Shift left."""
        return self._integer_binary_op("<<", other)

    def shift_right(self, other: ConditionBuilder | int) -> ConditionBuilder:
        """Shift right."""
        return self._integer_binary_op(">>", other)

    # Grouping
    def group(self) -> ConditionBuilder:
        """Group expression in parentheses."""
        if self._expression is None:
            msg = "Cannot group empty expression"
            raise ValidationError(msg)

        return ConditionBuilder(ParenthesesExpression(expression=self._expression))

    # Helper methods
    def _binary_op(
        self,
        op: str,
        other: ConditionBuilder | Expression | int | str,
    ) -> ConditionBuilder:
        """Create binary expression."""
        if self._expression is None:
            msg = f"Cannot apply {op} to empty expression"
            raise ValidationError(msg)

        right = self._to_expression(other)
        return ConditionBuilder(
            BinaryExpression(left=self._expression, operator=op, right=right),
        )

    def _integer_binary_op(
        self,
        op: str,
        other: ConditionBuilder | Expression | int,
    ) -> ConditionBuilder:
        if self._expression is None:
            msg = f"Cannot apply {op} to empty expression"
            raise ValidationError(msg)

        right = self._to_integer_expression(other)
        return ConditionBuilder(
            BinaryExpression(left=self._expression, operator=op, right=right),
        )

    def _string_binary_op(
        self,
        op: str,
        pattern: ConditionBuilder | Expression | str,
    ) -> ConditionBuilder:
        if self._expression is None:
            msg = f"Cannot apply {op} to empty expression"
            raise ValidationError(msg)

        right = self._to_string_pattern(pattern)
        return ConditionBuilder(
            BinaryExpression(left=self._expression, operator=op, right=right),
        )

    def _to_logical_operand(self, value: ConditionBuilder | Expression) -> Expression:
        if isinstance(value, ConditionBuilder):
            if value._expression is None:
                msg = "Empty condition builder"
                raise ValidationError(msg)
            return value._expression
        if isinstance(value, Expression):
            return value
        msg = "Logical operand must be a ConditionBuilder or Expression"
        raise TypeError(msg)

    def _to_string_pattern(
        self,
        value: ConditionBuilder | Expression | str,
    ) -> Expression:
        if isinstance(value, ConditionBuilder):
            if value._expression is None:
                msg = "Empty condition builder"
                raise ValidationError(msg)
            return value._expression
        if isinstance(value, Expression):
            return value
        if isinstance(value, str):
            return StringLiteral(value=value)
        msg = "String pattern must be a string, ConditionBuilder, or Expression"
        raise TypeError(msg)

    def _to_expression(
        self,
        value: ConditionBuilder | Expression | int | str,
    ) -> Expression:
        """Convert value to expression."""
        if isinstance(value, ConditionBuilder):
            if value._expression is None:
                msg = "Empty condition builder"
                raise ValidationError(msg)
            return value._expression
        if isinstance(value, Expression):
            return value
        if isinstance(value, bool):
            return BooleanLiteral(value=value)
        if isinstance(value, int):
            return IntegerLiteral(value=value)
        if isinstance(value, str):
            if value.startswith("$"):
                self._validate_string_reference(value)
                return StringIdentifier(name=value)
            return StringLiteral(value=value)
        msg = f"Cannot convert {type(value)} to expression"
        raise TypeError(msg)

    def _to_integer_expression(
        self,
        value: ConditionBuilder | Expression | int,
    ) -> Expression:
        """Convert integer-position arguments without accepting booleans as 0/1."""
        if isinstance(value, ConditionBuilder):
            if value._expression is None:
                msg = "Empty condition builder"
                raise ValidationError(msg)
            return value._expression
        if isinstance(value, Expression):
            return value
        if isinstance(value, int):
            return self._integer_literal(value)
        msg = f"Cannot convert {type(value)} to integer expression"
        raise TypeError(msg)

    def _validate_string_set_args(self, strings: tuple[str, ...]) -> None:
        if not strings:
            msg = "At least one string identifier is required"
            raise ValidationError(msg)
        if "them" in strings and not all(string == "them" for string in strings):
            msg = "'them' cannot be mixed with explicit string identifiers"
            raise ValidationError(msg)
        for string in strings:
            if string != "them":
                self._validate_string_reference(string)

    def _validate_string_reference(self, identifier: str) -> None:
        self._normalize_string_reference(identifier, "$")

    def _normalize_string_reference(self, identifier: str, marker: str) -> str:
        if not isinstance(identifier, str):
            msg = f"Invalid string reference: {identifier}"
            raise TypeError(msg)
        normalized = identifier[1:] if identifier.startswith(marker) else identifier
        body = normalized[1:] if normalized.startswith("$") else normalized
        if not body or _STRING_REFERENCE_BODY_RE.fullmatch(body) is None:
            msg = f"Invalid string reference: {identifier}"
            raise ValidationError(msg)
        return normalized

    def build(self) -> Expression:
        """Build the final expression."""
        if self._expression is None:
            msg = "Cannot build empty expression"
            raise ValidationError(msg)
        return deepcopy(self._expression)

    # Static factory methods
    @staticmethod
    def match(string_id: str) -> ConditionBuilder:
        """Create condition that matches a string."""
        ConditionBuilder()._validate_string_reference(string_id)
        return ConditionBuilder(StringIdentifier(name=string_id))

    @staticmethod
    def them() -> ConditionBuilder:
        """Reference to 'them' keyword."""
        return ConditionBuilder(Identifier(name="them"))
