"""Fluent builder for conditions."""

from typing import Any, Dict, List, Optional, Self, Set, Tuple, Union

from yaraast.ast.base import ASTNode, Location, YaraFile
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
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
    StringModifier,
)


class ConditionBuilder:
    """Fluent builder for constructing conditions."""

    def __init__(self, expr: Optional[Expression] = None):
        self._expression = expr

    # String references
    def string(self, identifier: str) -> Self:
        """Reference a string identifier."""
        return ConditionBuilder(StringIdentifier(name=identifier))

    def string_count(self, identifier: str) -> Self:
        """Reference string count (#string)."""
        return ConditionBuilder(StringCount(string_id=identifier.lstrip('#')))

    def string_offset(self, identifier: str, index: Optional[int] = None) -> Self:
        """Reference string offset (@string or @string[i])."""
        index_expr = IntegerLiteral(value=index) if index is not None else None
        return ConditionBuilder(StringOffset(
            string_id=identifier.lstrip('@'),
            index=index_expr
        ))

    def string_length(self, identifier: str, index: Optional[int] = None) -> Self:
        """Reference string length (!string or !string[i])."""
        index_expr = IntegerLiteral(value=index) if index is not None else None
        return ConditionBuilder(StringLength(
            string_id=identifier.lstrip('!'),
            index=index_expr
        ))

    # Literals
    def true(self) -> Self:
        """Boolean true."""
        return ConditionBuilder(BooleanLiteral(value=True))

    def false(self) -> Self:
        """Boolean false."""
        return ConditionBuilder(BooleanLiteral(value=False))

    def integer(self, value: int) -> Self:
        """Integer literal."""
        return ConditionBuilder(IntegerLiteral(value=value))

    def filesize(self) -> Self:
        """Filesize keyword."""
        return ConditionBuilder(Identifier(name="filesize"))

    def entrypoint(self) -> Self:
        """Entrypoint keyword."""
        return ConditionBuilder(Identifier(name="entrypoint"))

    def identifier(self, name: str) -> Self:
        """Generic identifier."""
        return ConditionBuilder(Identifier(name=name))

    def range(self, start: Union[int, 'ConditionBuilder'],
             end: Union[int, 'ConditionBuilder']) -> Self:
        """Create a range expression."""
        start_expr = self._to_expression(start)
        end_expr = self._to_expression(end)
        return ConditionBuilder(RangeExpression(low=start_expr, high=end_expr))

    def member_access(self, obj: Union['ConditionBuilder', Expression], member: str) -> Self:
        """Member access (obj.member)."""
        obj_expr = self._to_expression(obj)
        return ConditionBuilder(MemberAccess(object=obj_expr, member=member))

    def array_access(self, array: Union['ConditionBuilder', Expression],
                    index: Union[int, 'ConditionBuilder', Expression]) -> Self:
        """Array access (array[index])."""
        array_expr = self._to_expression(array)
        index_expr = self._to_expression(index)
        return ConditionBuilder(ArrayAccess(array=array_expr, index=index_expr))

    # Logical operators
    def and_(self, other: Union['ConditionBuilder', Expression]) -> Self:
        """Logical AND."""
        if not self._expression:
            raise ValueError("Cannot apply AND to empty expression")

        right = other._expression if isinstance(other, ConditionBuilder) else other
        return ConditionBuilder(BinaryExpression(
            left=self._expression,
            operator="and",
            right=right
        ))

    def or_(self, other: Union['ConditionBuilder', Expression]) -> Self:
        """Logical OR."""
        if not self._expression:
            raise ValueError("Cannot apply OR to empty expression")

        right = other._expression if isinstance(other, ConditionBuilder) else other
        return ConditionBuilder(BinaryExpression(
            left=self._expression,
            operator="or",
            right=right
        ))

    def not_(self) -> Self:
        """Logical NOT."""
        if not self._expression:
            raise ValueError("Cannot apply NOT to empty expression")

        return ConditionBuilder(UnaryExpression(
            operator="not",
            operand=self._expression
        ))

    # Comparison operators
    def eq(self, other: Union['ConditionBuilder', Expression, int, str]) -> Self:
        """Equal comparison."""
        return self._binary_op("==", other)

    def ne(self, other: Union['ConditionBuilder', Expression, int, str]) -> Self:
        """Not equal comparison."""
        return self._binary_op("!=", other)

    def lt(self, other: Union['ConditionBuilder', Expression, int]) -> Self:
        """Less than comparison."""
        return self._binary_op("<", other)

    def le(self, other: Union['ConditionBuilder', Expression, int]) -> Self:
        """Less than or equal comparison."""
        return self._binary_op("<=", other)

    def gt(self, other: Union['ConditionBuilder', Expression, int]) -> Self:
        """Greater than comparison."""
        return self._binary_op(">", other)

    def ge(self, other: Union['ConditionBuilder', Expression, int]) -> Self:
        """Greater than or equal comparison."""
        return self._binary_op(">=", other)

    # String operations
    def contains(self, pattern: Union[str, 'ConditionBuilder']) -> Self:
        """String contains."""
        return self._binary_op("contains", pattern)

    def matches(self, pattern: Union[str, 'ConditionBuilder']) -> Self:
        """String matches regex."""
        return self._binary_op("matches", pattern)

    def startswith(self, pattern: Union[str, 'ConditionBuilder']) -> Self:
        """String starts with."""
        return self._binary_op("startswith", pattern)

    def endswith(self, pattern: Union[str, 'ConditionBuilder']) -> Self:
        """String ends with."""
        return self._binary_op("endswith", pattern)

    def icontains(self, pattern: Union[str, 'ConditionBuilder']) -> Self:
        """Case-insensitive contains."""
        return self._binary_op("icontains", pattern)

    def iequals(self, pattern: Union[str, 'ConditionBuilder']) -> Self:
        """Case-insensitive equals."""
        return self._binary_op("iequals", pattern)

    # Special conditions
    def at(self, offset: Union[int, 'ConditionBuilder']) -> Self:
        """String at offset."""
        if not self._expression or not isinstance(self._expression, StringIdentifier):
            raise ValueError("'at' can only be used with string identifiers")

        offset_expr = self._to_expression(offset)
        return ConditionBuilder(AtExpression(
            string_id=self._expression.name,
            offset=offset_expr
        ))

    def in_range(self, start: Union[int, 'ConditionBuilder'],
                 end: Union[int, 'ConditionBuilder']) -> Self:
        """String in range."""
        if not self._expression or not isinstance(self._expression, StringIdentifier):
            raise ValueError("'in' can only be used with string identifiers")

        start_expr = self._to_expression(start)
        end_expr = self._to_expression(end)
        range_expr = RangeExpression(low=start_expr, high=end_expr)

        return ConditionBuilder(InExpression(
            string_id=self._expression.name,
            range=range_expr
        ))

    # Quantifiers
    def any_of(self, *strings: str) -> Self:
        """Any of strings."""
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(OfExpression(
            quantifier=StringLiteral(value="any"),
            string_set=string_set
        ))

    def all_of(self, *strings: str) -> Self:
        """All of strings."""
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(OfExpression(
            quantifier=StringLiteral(value="all"),
            string_set=string_set
        ))

    def n_of(self, n: int, *strings: str) -> Self:
        """N of strings."""
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return ConditionBuilder(OfExpression(
            quantifier=IntegerLiteral(value=n),
            string_set=string_set
        ))

    # For loops
    def for_any(self, var: str, iterable: Union['ConditionBuilder', Expression],
                condition: Union['ConditionBuilder', Expression]) -> Self:
        """For any loop."""
        iter_expr = self._to_expression(iterable)
        cond_expr = self._to_expression(condition)

        return ConditionBuilder(ForExpression(
            quantifier="any",
            variable=var,
            iterable=iter_expr,
            body=cond_expr
        ))

    def for_all(self, var: str, iterable: Union['ConditionBuilder', Expression],
                condition: Union['ConditionBuilder', Expression]) -> Self:
        """For all loop."""
        iter_expr = self._to_expression(iterable)
        cond_expr = self._to_expression(condition)

        return ConditionBuilder(ForExpression(
            quantifier="all",
            variable=var,
            iterable=iter_expr,
            body=cond_expr
        ))

    # Arithmetic operations
    def add(self, other: Union['ConditionBuilder', int]) -> Self:
        """Addition."""
        return self._binary_op("+", other)

    def sub(self, other: Union['ConditionBuilder', int]) -> Self:
        """Subtraction."""
        return self._binary_op("-", other)

    def mul(self, other: Union['ConditionBuilder', int]) -> Self:
        """Multiplication."""
        return self._binary_op("*", other)

    def div(self, other: Union['ConditionBuilder', int]) -> Self:
        """Division."""
        return self._binary_op("/", other)

    def mod(self, other: Union['ConditionBuilder', int]) -> Self:
        """Modulo."""
        return self._binary_op("%", other)

    # Bitwise operations
    def bitwise_and(self, other: Union['ConditionBuilder', int]) -> Self:
        """Bitwise AND."""
        return self._binary_op("&", other)

    def bitwise_or(self, other: Union['ConditionBuilder', int]) -> Self:
        """Bitwise OR."""
        return self._binary_op("|", other)

    def bitwise_xor(self, other: Union['ConditionBuilder', int]) -> Self:
        """Bitwise XOR."""
        return self._binary_op("^", other)

    def bitwise_not(self) -> Self:
        """Bitwise NOT."""
        if not self._expression:
            raise ValueError("Cannot apply bitwise NOT to empty expression")

        return ConditionBuilder(UnaryExpression(
            operator="~",
            operand=self._expression
        ))

    def shift_left(self, other: Union['ConditionBuilder', int]) -> Self:
        """Shift left."""
        return self._binary_op("<<", other)

    def shift_right(self, other: Union['ConditionBuilder', int]) -> Self:
        """Shift right."""
        return self._binary_op(">>", other)

    # Grouping
    def group(self) -> Self:
        """Group expression in parentheses."""
        if not self._expression:
            raise ValueError("Cannot group empty expression")

        return ConditionBuilder(ParenthesesExpression(expression=self._expression))

    # Helper methods
    def _binary_op(self, op: str, other: Union['ConditionBuilder', Expression, int, str]) -> Self:
        """Create binary expression."""
        if not self._expression:
            raise ValueError(f"Cannot apply {op} to empty expression")

        right = self._to_expression(other)
        return ConditionBuilder(BinaryExpression(
            left=self._expression,
            operator=op,
            right=right
        ))

    def _to_expression(self, value: Union['ConditionBuilder', Expression, int, str]) -> Expression:
        """Convert value to expression."""
        if isinstance(value, ConditionBuilder):
            if not value._expression:
                raise ValueError("Empty condition builder")
            return value._expression
        elif isinstance(value, Expression):
            return value
        elif isinstance(value, int):
            return IntegerLiteral(value=value)
        elif isinstance(value, str):
            if value.startswith('$'):
                return StringIdentifier(name=value)
            else:
                return StringLiteral(value=value)
        else:
            raise TypeError(f"Cannot convert {type(value)} to expression")

    def build(self) -> Expression:
        """Build the final expression."""
        if not self._expression:
            raise ValueError("Cannot build empty expression")
        return self._expression

    # Static factory methods
    @staticmethod
    def match(string_id: str) -> 'ConditionBuilder':
        """Create condition that matches a string."""
        return ConditionBuilder(StringIdentifier(name=string_id))

    @staticmethod
    def them() -> 'ConditionBuilder':
        """Reference to 'them' keyword."""
        return ConditionBuilder(Identifier(name="them"))
