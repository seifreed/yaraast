"""Enhanced fluent condition builder with comprehensive helpers."""

from __future__ import annotations

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLiteral,
    UnaryExpression,
)
from yaraast.builder.condition_builder import ConditionBuilder


class FluentConditionBuilder(ConditionBuilder):
    """Enhanced fluent condition builder with common pattern helpers."""

    def __init__(self, expr: Expression | None = None) -> None:
        super().__init__(expr)

    # Enhanced quantifier methods
    def any_of_them(self) -> FluentConditionBuilder:
        """Any of them - common pattern."""
        return FluentConditionBuilder(
            OfExpression(
                quantifier=StringLiteral(value="any"),
                string_set=Identifier(name="them"),
            ),
        )

    def all_of_them(self) -> FluentConditionBuilder:
        """All of them - common pattern."""
        return FluentConditionBuilder(
            OfExpression(
                quantifier=StringLiteral(value="all"),
                string_set=Identifier(name="them"),
            ),
        )

    def not_them(self) -> FluentConditionBuilder:
        """Not any of them - negated pattern."""
        return FluentConditionBuilder(
            UnaryExpression(
                operator="not",
                operand=OfExpression(
                    quantifier=StringLiteral(value="any"),
                    string_set=Identifier(name="them"),
                ),
            ),
        )

    def one_of(self, *strings: str) -> FluentConditionBuilder:
        """Exactly one of the specified strings."""
        return self.n_of(1, *strings)

    def two_of(self, *strings: str) -> FluentConditionBuilder:
        """Exactly two of the specified strings."""
        return self.n_of(2, *strings)

    def three_of(self, *strings: str) -> FluentConditionBuilder:
        """Exactly three of the specified strings."""
        return self.n_of(3, *strings)

    def most_of(self, *strings: str) -> FluentConditionBuilder:
        """Most of the strings (more than half)."""
        threshold = (len(strings) // 2) + 1
        return self.n_of(threshold, *strings)

    def few_of(self, *strings: str) -> FluentConditionBuilder:
        """Few of the strings (at least 2)."""
        return self.at_least_n_of(2, *strings)

    def many_of(self, *strings: str) -> FluentConditionBuilder:
        """Many of the strings (at least 3)."""
        return self.at_least_n_of(3, *strings)

    def at_least_n_of(self, n: int, *strings: str) -> FluentConditionBuilder:
        """At least N of the specified strings."""
        # Create condition: n_of OR (n+1)_of OR ... OR all_of
        conditions = []
        for i in range(n, len(strings) + 1):
            conditions.append(self._create_n_of(i, *strings))

        # Chain with OR
        result = conditions[0]
        for cond in conditions[1:]:
            result = BinaryExpression(left=result, operator="or", right=cond)

        return FluentConditionBuilder(result)

    def at_most_n_of(self, n: int, *strings: str) -> FluentConditionBuilder:
        """At most N of the specified strings."""
        # Create condition: 0_of OR 1_of OR ... OR n_of
        conditions = []
        for i in range(n + 1):
            conditions.append(self._create_n_of(i, *strings))

        # Chain with OR
        result = conditions[0]
        for cond in conditions[1:]:
            result = BinaryExpression(left=result, operator="or", right=cond)

        return FluentConditionBuilder(result)

    def between_n_and_m_of(
        self,
        min_n: int,
        max_m: int,
        *strings: str,
    ) -> FluentConditionBuilder:
        """Between N and M of the specified strings."""
        conditions = []
        for i in range(min_n, max_m + 1):
            conditions.append(self._create_n_of(i, *strings))

        # Chain with OR
        result = conditions[0]
        for cond in conditions[1:]:
            result = BinaryExpression(left=result, operator="or", right=cond)

        return FluentConditionBuilder(result)

    # String-specific helpers
    def string_matches(self, string_id: str) -> FluentConditionBuilder:
        """String matches (shorthand for string identifier)."""
        return FluentConditionBuilder(StringIdentifier(name=string_id))

    def string_count_eq(self, string_id: str, count: int) -> FluentConditionBuilder:
        """String count equals N."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=StringCount(string_id=string_id.lstrip("#")),
                operator="==",
                right=IntegerLiteral(value=count),
            ),
        )

    def string_count_gt(self, string_id: str, count: int) -> FluentConditionBuilder:
        """String count greater than N."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=StringCount(string_id=string_id.lstrip("#")),
                operator=">",
                right=IntegerLiteral(value=count),
            ),
        )

    def string_count_ge(self, string_id: str, count: int) -> FluentConditionBuilder:
        """String count greater than or equal to N."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=StringCount(string_id=string_id.lstrip("#")),
                operator=">=",
                right=IntegerLiteral(value=count),
            ),
        )

    def string_at_entrypoint(self, string_id: str) -> FluentConditionBuilder:
        """String at entrypoint."""
        return FluentConditionBuilder(
            AtExpression(string_id=string_id, offset=Identifier(name="entrypoint")),
        )

    def string_at_offset(self, string_id: str, offset: int) -> FluentConditionBuilder:
        """String at specific offset."""
        return FluentConditionBuilder(
            AtExpression(string_id=string_id, offset=IntegerLiteral(value=offset)),
        )

    def string_in_first_kb(self, string_id: str) -> FluentConditionBuilder:
        """String in first 1KB of file."""
        return FluentConditionBuilder(
            InExpression(
                string_id=string_id,
                range=RangeExpression(
                    low=IntegerLiteral(value=0),
                    high=IntegerLiteral(value=1024),
                ),
            ),
        )

    def string_in_last_kb(self, string_id: str) -> FluentConditionBuilder:
        """String in last 1KB of file."""
        return FluentConditionBuilder(
            InExpression(
                string_id=string_id,
                range=RangeExpression(
                    low=BinaryExpression(
                        left=Identifier(name="filesize"),
                        operator="-",
                        right=IntegerLiteral(value=1024),
                    ),
                    high=Identifier(name="filesize"),
                ),
            ),
        )

    # File property helpers
    def filesize_eq(self, size: int) -> FluentConditionBuilder:
        """File size equals specific value."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=Identifier(name="filesize"),
                operator="==",
                right=IntegerLiteral(value=size),
            ),
        )

    def filesize_gt(self, size: int) -> FluentConditionBuilder:
        """File size greater than."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=Identifier(name="filesize"),
                operator=">",
                right=IntegerLiteral(value=size),
            ),
        )

    def filesize_lt(self, size: int) -> FluentConditionBuilder:
        """File size less than."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=Identifier(name="filesize"),
                operator="<",
                right=IntegerLiteral(value=size),
            ),
        )

    def filesize_between(self, min_size: int, max_size: int) -> FluentConditionBuilder:
        """File size between min and max."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=BinaryExpression(
                    left=Identifier(name="filesize"),
                    operator=">=",
                    right=IntegerLiteral(value=min_size),
                ),
                operator="and",
                right=BinaryExpression(
                    left=Identifier(name="filesize"),
                    operator="<=",
                    right=IntegerLiteral(value=max_size),
                ),
            ),
        )

    def small_file(self) -> FluentConditionBuilder:
        """Small file (< 1MB)."""
        return self.filesize_lt(1024 * 1024)

    def large_file(self) -> FluentConditionBuilder:
        """Large file (> 10MB)."""
        return self.filesize_gt(10 * 1024 * 1024)

    def tiny_file(self) -> FluentConditionBuilder:
        """Tiny file (< 1KB)."""
        return self.filesize_lt(1024)

    def huge_file(self) -> FluentConditionBuilder:
        """Huge file (> 100MB)."""
        return self.filesize_gt(100 * 1024 * 1024)

    # Module helpers
    def pe_module(self) -> FluentConditionBuilder:
        """PE module reference."""
        return FluentConditionBuilder(Identifier(name="pe"))

    def pe_is_dll(self) -> FluentConditionBuilder:
        """PE is DLL."""
        return FluentConditionBuilder(
            MemberAccess(object=Identifier(name="pe"), member="is_dll"),
        )

    def pe_is_exe(self) -> FluentConditionBuilder:
        """PE is executable (not DLL)."""
        return FluentConditionBuilder(
            UnaryExpression(
                operator="not",
                operand=MemberAccess(object=Identifier(name="pe"), member="is_dll"),
            ),
        )

    def pe_is_32bit(self) -> FluentConditionBuilder:
        """PE is 32-bit."""
        return FluentConditionBuilder(
            MemberAccess(object=Identifier(name="pe"), member="is_32bit"),
        )

    def pe_is_64bit(self) -> FluentConditionBuilder:
        """PE is 64-bit."""
        return FluentConditionBuilder(
            MemberAccess(object=Identifier(name="pe"), member="is_64bit"),
        )

    def pe_section_count_eq(self, count: int) -> FluentConditionBuilder:
        """PE section count equals."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=MemberAccess(
                    object=Identifier(name="pe"),
                    member="number_of_sections",
                ),
                operator="==",
                right=IntegerLiteral(value=count),
            ),
        )

    def pe_imphash_eq(self, hash_value: str) -> FluentConditionBuilder:
        """PE import hash equals."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=FunctionCall(function="pe.imphash", arguments=[]),
                operator="==",
                right=StringLiteral(value=hash_value),
            ),
        )

    def pe_exports(self, function_name: str) -> FluentConditionBuilder:
        """PE exports function."""
        return FluentConditionBuilder(
            FunctionCall(
                function="pe.exports",
                arguments=[StringLiteral(value=function_name)],
            ),
        )

    def pe_imports(self, dll_name: str, function_name: str) -> FluentConditionBuilder:
        """PE imports function from DLL."""
        return FluentConditionBuilder(
            FunctionCall(
                function="pe.imports",
                arguments=[
                    StringLiteral(value=dll_name),
                    StringLiteral(value=function_name),
                ],
            ),
        )

    # Math module helpers
    MATH_ENTROPY = "math.entropy"

    def entropy_gt(
        self,
        offset: int,
        size: int,
        threshold: float,
    ) -> FluentConditionBuilder:
        """Entropy greater than threshold."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=FunctionCall(
                    function=self.MATH_ENTROPY,
                    arguments=[
                        IntegerLiteral(value=offset),
                        IntegerLiteral(value=size),
                    ],
                ),
                operator=">",
                right=DoubleLiteral(value=threshold),
            ),
        )

    def high_entropy(self, offset: int = 0, size: int = 1024) -> FluentConditionBuilder:
        """High entropy section (> 7.0)."""
        return self.entropy_gt(offset, size, 7.0)

    def low_entropy(self, offset: int = 0, size: int = 1024) -> FluentConditionBuilder:
        """Low entropy section (< 3.0)."""
        return FluentConditionBuilder(
            BinaryExpression(
                left=FunctionCall(
                    function=self.MATH_ENTROPY,
                    arguments=[
                        IntegerLiteral(value=offset),
                        IntegerLiteral(value=size),
                    ],
                ),
                operator="<",
                right=DoubleLiteral(value=3.0),
            ),
        )

    # Composite helpers
    def executable_file(self) -> FluentConditionBuilder:
        """Common executable file patterns."""
        mz_at_0 = FluentConditionBuilder(
            AtExpression(string_id="mz_header", offset=IntegerLiteral(value=0)),
        )

        return mz_at_0.and_(
            FluentConditionBuilder(
                BinaryExpression(
                    left=Identifier(name="filesize"),
                    operator=">",
                    right=IntegerLiteral(value=1024),
                ),
            ),
        )

    def suspicious_entropy(self) -> FluentConditionBuilder:
        """Suspicious entropy patterns."""
        return self.high_entropy().or_(
            FluentConditionBuilder(
                BinaryExpression(
                    left=FunctionCall(
                        function=self.MATH_ENTROPY,
                        arguments=[IntegerLiteral(value=0), IntegerLiteral(value=512)],
                    ),
                    operator=">",
                    right=DoubleLiteral(value=7.5),
                ),
            ),
        )

    def packed_executable(self) -> FluentConditionBuilder:
        """Common packed executable indicators."""
        return self.suspicious_entropy().and_(
            FluentConditionBuilder(
                BinaryExpression(
                    left=MemberAccess(
                        object=Identifier(name="pe"),
                        member="number_of_sections",
                    ),
                    operator="<",
                    right=IntegerLiteral(value=5),
                ),
            ),
        )

    # Helper methods
    def _create_n_of(self, n: int, *strings: str) -> Expression:
        """Create N of strings expression."""
        if all(s == "them" for s in strings):
            string_set = Identifier(name="them")
        else:
            elements = [StringIdentifier(name=s) for s in strings]
            string_set = SetExpression(elements=elements)

        return OfExpression(quantifier=IntegerLiteral(value=n), string_set=string_set)

    # Factory methods
    @staticmethod
    def create() -> FluentConditionBuilder:
        """Create empty fluent condition builder."""
        return FluentConditionBuilder()

    @staticmethod
    def match_string(string_id: str) -> FluentConditionBuilder:
        """Create condition matching a string."""
        return FluentConditionBuilder(StringIdentifier(name=string_id))

    @staticmethod
    def always_true() -> FluentConditionBuilder:
        """Always true condition."""
        return FluentConditionBuilder(BooleanLiteral(value=True))

    @staticmethod
    def always_false() -> FluentConditionBuilder:
        """Always false condition."""
        return FluentConditionBuilder(BooleanLiteral(value=False))


# Convenience functions
def condition() -> FluentConditionBuilder:
    """Create a new fluent condition builder."""
    return FluentConditionBuilder.create()


def match(string_id: str) -> FluentConditionBuilder:
    """Match a string identifier."""
    return FluentConditionBuilder.match_string(string_id)


def any_of_them() -> FluentConditionBuilder:
    """Any of them condition."""
    return FluentConditionBuilder().any_of_them()


def all_of_them() -> FluentConditionBuilder:
    """All of them condition."""
    return FluentConditionBuilder().all_of_them()


def not_them() -> FluentConditionBuilder:
    """Not any of them condition."""
    return FluentConditionBuilder().not_them()


def one_of(*strings: str) -> FluentConditionBuilder:
    """One of specified strings."""
    return FluentConditionBuilder().one_of(*strings)


def any_of(*strings: str) -> FluentConditionBuilder:
    """Any of specified strings."""
    return FluentConditionBuilder().any_of(*strings)


def all_of(*strings: str) -> FluentConditionBuilder:
    """All of specified strings."""
    return FluentConditionBuilder().all_of(*strings)


def filesize_gt(size: int) -> FluentConditionBuilder:
    """File size greater than."""
    return FluentConditionBuilder().filesize_gt(size)


def small_file() -> FluentConditionBuilder:
    """Small file condition."""
    return FluentConditionBuilder().small_file()


def large_file() -> FluentConditionBuilder:
    """Large file condition."""
    return FluentConditionBuilder().large_file()


def pe_is_dll() -> FluentConditionBuilder:
    """PE is DLL condition."""
    return FluentConditionBuilder().pe_is_dll()


def high_entropy(offset: int = 0, size: int = 1024) -> FluentConditionBuilder:
    """High entropy condition."""
    return FluentConditionBuilder().high_entropy(offset, size)
