"""Expression AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any

from yaraast.ast.base import (
    ASTNode,
    _require_ast_node_sequence_type,
    _require_nonempty_string,
    _VisitorType,
)
from yaraast.lexer.lexer_tables import YARA_IDENTIFIER_MAX_LENGTH
from yaraast.regex_literals import validate_regex_modifiers, validate_regex_pattern
from yaraast.string_references import (
    normalize_string_reference_id,
)

_INT64_BITS = 64
_INT64_MAX = (1 << 63) - 1
_UINT64_MASK = (1 << _INT64_BITS) - 1
_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RANGE_INTEGER_BINARY_OPERATORS = frozenset({"+", "-", "*", "%", "&", "|", "^", "<<", ">>"})
_STRING_BINARY_OPERATORS = frozenset(
    {
        "contains",
        "matches",
        "startswith",
        "endswith",
        "icontains",
        "istartswith",
        "iendswith",
        "iequals",
    }
)
_RANGE_NON_INTEGER_BINARY_OPERATORS = frozenset(
    {"<", "<=", ">", ">=", "==", "!=", "and", "or"} | _STRING_BINARY_OPERATORS
)
_VALID_BINARY_OPERATORS = frozenset(
    {
        "or",
        "and",
        "==",
        "!=",
        "<",
        "<=",
        ">",
        ">=",
        "contains",
        "matches",
        "startswith",
        "endswith",
        "icontains",
        "istartswith",
        "iendswith",
        "iequals",
        "|",
        "^",
        "&",
        "<<",
        ">>",
        "+",
        "-",
        "*",
        "/",
        "\\",
        "%",
    }
)
_VALID_UNARY_OPERATORS = frozenset({"not", "-", "~", "%"})


def _validate_expression_identifier(name: object) -> str:
    if not isinstance(name, str):
        msg = "Identifier name must be a string"
        raise TypeError(msg)
    if len(name) <= YARA_IDENTIFIER_MAX_LENGTH and _YARA_IDENTIFIER_RE.fullmatch(name):
        return name
    if name.startswith("$"):
        normalize_string_reference_id(name, allow_wildcard=False)
        return name
    msg = f"Invalid identifier '{name}'"
    raise ValueError(msg)


def _validate_string_reference_suffix(identifier: object) -> None:
    text = _require_nonempty_string(identifier, "String identifier")
    if text.startswith(("#", "@", "!")):
        msg = f"Invalid string reference '{text}'"
        raise ValueError(msg)
    if text == "$":
        return
    normalize_string_reference_id(text, allow_wildcard=False)


def _validate_regex_text(pattern: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in pattern):
        msg = "Regex pattern must not contain Unicode surrogate code points"
        raise ValueError(msg)
    if "\n" in pattern:
        msg = "Regex pattern must not contain line breaks"
        raise ValueError(msg)
    if "\x00" in pattern:
        msg = "Regex pattern must not contain NUL bytes"
        raise ValueError(msg)
    validate_regex_pattern(pattern)


def _normalize_range_int64(value: int) -> int:
    unsigned = value & _UINT64_MASK
    if unsigned > _INT64_MAX:
        return unsigned - (1 << _INT64_BITS)
    return unsigned


def _range_integer_remainder(left: int, right: int) -> int:
    quotient = abs(left) // abs(right)
    if (left < 0) != (right < 0):
        quotient = -quotient
    return left - quotient * right


def _range_shift_left_int64(left: int, right: int) -> int:
    if right >= _INT64_BITS:
        return 0
    return _normalize_range_int64(left << right)


def _range_shift_right_int64(left: int, right: int) -> int:
    if right >= _INT64_BITS:
        return 0
    return _normalize_range_int64(left) >> right


def _is_definitely_non_integer_range_bound(value: Any) -> bool:
    from yaraast.ast.conditions import (
        AtExpression,
        ForExpression,
        ForOfExpression,
        InExpression,
        OfExpression,
    )

    if isinstance(value, ParenthesesExpression):
        return _is_definitely_non_integer_range_bound(value.expression)
    if isinstance(value, AtExpression | ForExpression | ForOfExpression | OfExpression):
        return True
    if isinstance(value, InExpression):
        return not isinstance(value.subject, StringCount)
    if isinstance(value, BinaryExpression):
        if value.operator in _RANGE_NON_INTEGER_BINARY_OPERATORS:
            return True
        if value.operator == "/":
            return True
        if value.operator in _RANGE_INTEGER_BINARY_OPERATORS | {"\\"}:
            return _is_definitely_non_integer_range_bound(
                value.left
            ) or _is_definitely_non_integer_range_bound(value.right)
        return False
    if isinstance(value, UnaryExpression):
        if value.operator in {"-", "~"}:
            return _is_definitely_non_integer_range_bound(value.operand)
        return True
    return isinstance(
        value, BooleanLiteral | DoubleLiteral | StringLiteral | RegexLiteral | StringIdentifier
    )


def _is_definitely_non_numeric_expression(value: Any) -> bool:
    from yaraast.ast.conditions import (
        AtExpression,
        ForExpression,
        ForOfExpression,
        InExpression,
        OfExpression,
    )

    if isinstance(value, ParenthesesExpression):
        return _is_definitely_non_numeric_expression(value.expression)
    if isinstance(value, AtExpression | ForExpression | ForOfExpression | OfExpression):
        return True
    if isinstance(value, InExpression):
        return not isinstance(value.subject, StringCount)
    if isinstance(value, UnaryExpression):
        if value.operator in {"not", "%"}:
            return True
        return _is_definitely_non_numeric_expression(value.operand)
    if isinstance(value, BinaryExpression):
        if value.operator in _RANGE_NON_INTEGER_BINARY_OPERATORS:
            return True
        if value.operator in _RANGE_INTEGER_BINARY_OPERATORS | {"/", "\\"}:
            return _is_definitely_non_numeric_expression(
                value.left
            ) or _is_definitely_non_numeric_expression(value.right)
        return True
    return isinstance(value, BooleanLiteral | StringLiteral | RegexLiteral | StringIdentifier)


def _constant_range_integer_value(value: Any) -> int | None:
    if (
        isinstance(value, IntegerLiteral)
        and isinstance(value.value, int)
        and not isinstance(value.value, bool)
    ):
        return value.value
    if isinstance(value, ParenthesesExpression):
        return _constant_range_integer_value(value.expression)
    if isinstance(value, UnaryExpression):
        operand = _constant_range_integer_value(value.operand)
        if operand is None:
            return None
        if value.operator == "-":
            return _normalize_range_int64(-operand)
        if value.operator == "~":
            return _normalize_range_int64(~operand)
        return None
    if (
        not isinstance(value, BinaryExpression)
        or value.operator not in _RANGE_INTEGER_BINARY_OPERATORS
    ):
        return None
    left = _constant_range_integer_value(value.left)
    right = _constant_range_integer_value(value.right)
    if left is None or right is None:
        return None
    if value.operator == "+":
        return _normalize_range_int64(left + right)
    if value.operator == "-":
        return _normalize_range_int64(left - right)
    if value.operator == "*":
        return _normalize_range_int64(left * right)
    if value.operator == "%":
        if right == 0:
            return None
        return _range_integer_remainder(left, right)
    if value.operator == "&":
        return _normalize_range_int64(left & right)
    if value.operator == "|":
        return _normalize_range_int64(left | right)
    if value.operator == "^":
        return _normalize_range_int64(left ^ right)
    if right < 0:
        return None
    if value.operator == "<<":
        return _range_shift_left_int64(left, right)
    if value.operator == ">>":
        return _range_shift_right_int64(left, right)
    return None


def _validate_integer_expression(value: Any, field_name: str) -> None:
    if _is_definitely_non_integer_range_bound(value):
        msg = f"{field_name} must be integer"
        raise ValueError(msg)


def _is_definitely_boolean_expression(value: Any) -> bool:
    if isinstance(value, ParenthesesExpression):
        return _is_definitely_boolean_expression(value.expression)
    if isinstance(value, BooleanLiteral):
        return True
    if isinstance(value, UnaryExpression):
        return value.operator == "not"
    if isinstance(value, BinaryExpression):
        return value.operator in _RANGE_NON_INTEGER_BINARY_OPERATORS
    return False


def _validate_non_boolean_expression(value: Any, field_name: str) -> None:
    if _is_definitely_boolean_expression(value):
        msg = f"{field_name} must not be boolean"
        raise ValueError(msg)


def _validate_constant_range_bounds(low: Any, high: Any) -> None:
    low_value = _constant_range_integer_value(low)
    high_value = _constant_range_integer_value(high)
    if low_value is None or high_value is None:
        return
    if low_value < 0:
        msg = "Range low bound cannot be negative"
        raise ValueError(msg)
    if low_value > high_value:
        msg = "Range low bound cannot exceed high bound"
        raise ValueError(msg)


@dataclass
class Expression(ASTNode):
    """Base class for all expressions."""

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_expression(self)


def _require_expression(value: Any, field_name: str) -> Expression:
    if not isinstance(value, Expression):
        msg = f"{field_name} must be an Expression"
        raise TypeError(msg)
    return value


def _validate_expression(value: Any, field_name: str) -> Expression:
    expression = _require_expression(value, field_name)
    validate_structure = getattr(expression, "validate_structure", None)
    if callable(validate_structure):
        validate_structure()
    return expression


def _unwrap_parentheses_expression(value: Any) -> Any:
    while isinstance(value, ParenthesesExpression):
        value = value.expression
    return value


@dataclass
class Identifier(Expression):
    """Identifier expression."""

    name: str

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        _require_nonempty_string(self.name, "Identifier name")
        _validate_expression_identifier(self.name)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_identifier(self)


@dataclass
class StringIdentifier(Expression):
    """String identifier (e.g., $str1)."""

    name: str

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        _require_nonempty_string(self.name, "String identifier")
        if self.name != "$":
            normalize_string_reference_id(self.name, allow_wildcard=False)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_identifier(self)


@dataclass
class StringWildcard(Expression):
    """String wildcard pattern (e.g., $a*, $prefix*)."""

    pattern: str

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        _require_nonempty_string(self.pattern, "String wildcard pattern")
        normalize_string_reference_id(self.pattern, allow_wildcard=True)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_wildcard(self)


@dataclass
class StringCount(Expression):
    """String count expression (#str)."""

    string_id: str

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        _require_nonempty_string(self.string_id, "String count identifier")
        _validate_string_reference_suffix(self.string_id)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_count(self)


@dataclass
class StringOffset(Expression):
    """String offset expression (@str or @str[i])."""

    string_id: str
    index: Expression | None = None

    def validate_structure(self) -> None:
        """Validate scalar fields and optional index before direct analysis."""
        _require_nonempty_string(self.string_id, "String offset identifier")
        _validate_string_reference_suffix(self.string_id)
        if self.index is not None:
            _validate_expression(self.index, "StringOffset.index")
            _validate_non_boolean_expression(self.index, "String offset index")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_offset(self)


@dataclass
class StringLength(Expression):
    """String length expression (!str or !str[i])."""

    string_id: str
    index: Expression | None = None

    def validate_structure(self) -> None:
        """Validate scalar fields and optional index before direct analysis."""
        _require_nonempty_string(self.string_id, "String length identifier")
        _validate_string_reference_suffix(self.string_id)
        if self.index is not None:
            _validate_expression(self.index, "StringLength.index")
            _validate_non_boolean_expression(self.index, "String length index")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_length(self)


@dataclass
class IntegerLiteral(Expression):
    """Integer literal."""

    value: int

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            msg = "Integer literal value must be an integer"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_integer_literal(self)


@dataclass
class DoubleLiteral(Expression):
    """Double/float literal."""

    value: float

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        if isinstance(self.value, bool) or not isinstance(self.value, int | float):
            msg = "Double literal value must be numeric"
            raise TypeError(msg)
        if not math.isfinite(self.value):
            msg = "Double literal value must be finite"
            raise ValueError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_double_literal(self)


@dataclass
class StringLiteral(Expression):
    """String literal."""

    value: str

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        if not isinstance(self.value, str):
            msg = "String literal value must be a string"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_literal(self)


@dataclass
class RegexLiteral(Expression):
    """Regex literal expression (e.g., /foo.*bar/i)."""

    pattern: str
    modifiers: str = ""  # i for case-insensitive, s for single-line, etc.

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        if not isinstance(self.pattern, str):
            msg = "Regex literal pattern must be a string"
            raise TypeError(msg)
        if not self.pattern:
            msg = "RegexLiteral pattern must not be empty"
            raise ValueError(msg)
        if not isinstance(self.modifiers, str):
            msg = "Regex literal modifiers must be a string"
            raise TypeError(msg)
        _validate_regex_text(self.pattern)
        validate_regex_modifiers(self.modifiers)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_regex_literal(self)


@dataclass
class BooleanLiteral(Expression):
    """Boolean literal."""

    value: bool

    def validate_structure(self) -> None:
        """Validate scalar fields before direct analysis."""
        if not isinstance(self.value, bool):
            msg = "Boolean literal value must be a boolean"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_boolean_literal(self)


@dataclass
class BinaryExpression(Expression):
    """Binary expression."""

    left: Expression
    operator: str
    right: Expression

    def validate_structure(self) -> None:
        """Validate child expressions and operator before direct analysis."""
        _validate_expression(self.left, "BinaryExpression.left")
        _require_nonempty_string(self.operator, "BinaryExpression operator")
        if self.operator not in _VALID_BINARY_OPERATORS:
            msg = f"Invalid binary operator '{self.operator}'"
            raise ValueError(msg)
        _validate_expression(self.right, "BinaryExpression.right")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_binary_expression(self)


@dataclass
class UnaryExpression(Expression):
    """Unary expression."""

    operator: str
    operand: Expression

    def validate_structure(self) -> None:
        """Validate child expression and operator before direct analysis."""
        _require_nonempty_string(self.operator, "UnaryExpression operator")
        if self.operator not in _VALID_UNARY_OPERATORS:
            msg = f"Invalid unary operator '{self.operator}'"
            raise ValueError(msg)
        _validate_expression(self.operand, "UnaryExpression.operand")
        if self.operator == "-" and _is_definitely_non_numeric_expression(self.operand):
            msg = "Operand of '-' must be numeric"
            raise ValueError(msg)
        if self.operator == "~" and _is_definitely_non_integer_range_bound(self.operand):
            msg = "Operand of '~' must be integer"
            raise ValueError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_unary_expression(self)


@dataclass
class ParenthesesExpression(Expression):
    """Parentheses expression."""

    expression: Expression

    def validate_structure(self) -> None:
        """Validate wrapped expression before direct analysis."""
        _validate_expression(self.expression, "ParenthesesExpression.expression")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_parentheses_expression(self)


@dataclass
class SetExpression(Expression):
    """Set expression (a, b, c)."""

    elements: list[Expression]

    def validate_structure(self) -> None:
        """Validate set elements before direct analysis."""
        _require_ast_node_sequence_type(
            self.elements,
            "SetExpression.elements",
            Expression,
            "Expression",
        )
        for element in self.elements:
            _validate_expression(element, "SetExpression.elements")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_set_expression(self)


@dataclass
class RangeExpression(Expression):
    """Range expression (a..b)."""

    low: Expression
    high: Expression

    def validate_structure(self) -> None:
        """Validate range bounds before direct analysis."""
        _validate_expression(self.low, "RangeExpression.low")
        _validate_expression(self.high, "RangeExpression.high")
        _validate_integer_expression(self.low, "Range low bound")
        _validate_integer_expression(self.high, "Range high bound")
        _validate_constant_range_bounds(self.low, self.high)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_range_expression(self)


@dataclass
class FunctionCall(Expression):
    """Function call expression.

    ``function`` carries the callee name. For an identifier-chain callee it is
    the full dotted path (``uint16``, ``pe.imphash``, ``pe.rich_signature.version``)
    and ``receiver`` is ``None``. When the callee's object cannot be a pure dotted
    path because it indexes into an array or dictionary (``pe.signatures[0].valid_on``),
    ``receiver`` holds that object expression and ``function`` is just the method
    name (``valid_on``).
    """

    function: str
    arguments: list[Expression]
    receiver: Expression | None = None

    def validate_structure(self) -> None:
        """Validate callee and argument expressions before direct analysis."""
        _require_nonempty_string(self.function, "Function name")
        _require_ast_node_sequence_type(
            self.arguments,
            "Function arguments",
            Expression,
            "AST",
        )
        for argument in self.arguments:
            _validate_expression(argument, "FunctionCall.arguments")
        if self.receiver is not None:
            _validate_expression(self.receiver, "FunctionCall.receiver")
            from yaraast.ast.conditions import AtExpression
            from yaraast.yarax.ast_nodes import WithStatement

            receiver = _unwrap_parentheses_expression(self.receiver)
            if isinstance(receiver, AtExpression | WithStatement):
                raise ValueError("FunctionCall.receiver must not be an 'at' or 'with' expression")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_function_call(self)

    def qualified_name(self) -> str:
        """Dotted display name, with indexed receivers flattened (no indices)."""
        if self.receiver is None:
            return self.function
        base = _receiver_identifier_path(self.receiver)
        return f"{base}.{self.function}" if base else self.function

    def module_and_function(self) -> tuple[str, str] | None:
        """Resolve to ``(module_alias, function_key)`` for a module call, else None.

        Builtins and unqualified calls return ``None``. The function key matches
        the dotted keys used in module definitions (e.g. ``signatures.valid_on``).
        """
        if self.receiver is None:
            if "." in self.function:
                module_name, func_name = self.function.split(".", 1)
                return module_name, func_name
            return None
        base, members = _receiver_base_and_members(self.receiver)
        if base is None:
            return None
        return base, ".".join([*members, self.function])


def _receiver_base_and_members(expr: Any) -> tuple[str | None, list[str]]:
    """Walk a callee object expression to ``(base_identifier, member_path)``.

    Array and dictionary indices are dropped so the member path matches the
    declared (index-free) module member keys.
    """
    from yaraast.ast.modules import DictionaryAccess, ModuleReference

    members: list[str] = []
    current = expr
    while True:
        if isinstance(current, MemberAccess):
            members.append(current.member)
            current = current.object
        elif isinstance(current, ArrayAccess):
            current = current.array
        elif isinstance(current, DictionaryAccess):
            current = current.object
        elif isinstance(current, Identifier):
            return current.name, list(reversed(members))
        elif isinstance(current, ModuleReference):
            return current.module, list(reversed(members))
        else:
            return None, []


def _receiver_identifier_path(expr: Any) -> str | None:
    base, members = _receiver_base_and_members(expr)
    if base is None:
        return None
    return ".".join([base, *members]) if members else base


@dataclass
class ArrayAccess(Expression):
    """Array access expression."""

    array: Expression
    index: Expression

    def validate_structure(self) -> None:
        """Validate array and index expressions before direct analysis."""
        _validate_expression(self.array, "ArrayAccess.array")
        _validate_expression(self.index, "ArrayAccess.index")
        _validate_integer_expression(self.index, "Array index")
        from yaraast.ast.conditions import AtExpression
        from yaraast.ast.modules import ModuleReference
        from yaraast.yarax.ast_nodes import TupleExpression, WithStatement

        array = _unwrap_parentheses_expression(self.array)
        if isinstance(array, ModuleReference):
            raise ValueError("ArrayAccess.array must not be a module reference")
        if isinstance(array, TupleExpression):
            raise ValueError("ArrayAccess.array must not be a tuple expression")
        if isinstance(array, AtExpression | WithStatement):
            raise ValueError("ArrayAccess.array must not be an 'at' or 'with' expression")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_array_access(self)


@dataclass
class MemberAccess(Expression):
    """Member access expression (a.b)."""

    object: Expression
    member: str

    def validate_structure(self) -> None:
        """Validate object expression and member name before direct analysis."""
        _validate_expression(self.object, "MemberAccess.object")
        _require_nonempty_string(self.member, "MemberAccess member")
        from yaraast.ast.conditions import AtExpression
        from yaraast.yarax.ast_nodes import WithStatement

        obj = _unwrap_parentheses_expression(self.object)
        if isinstance(obj, AtExpression | WithStatement):
            raise ValueError("MemberAccess.object must not be an 'at' or 'with' expression")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_member_access(self)
