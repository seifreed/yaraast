from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar

from google.protobuf import descriptor as _descriptor, message as _message
from google.protobuf.internal import containers as _containers

DESCRIPTOR: _descriptor.FileDescriptor

class YaraFile(_message.Message):
    __slots__ = (
        "extern_imports",
        "extern_rules",
        "imports",
        "includes",
        "metadata",
        "namespaces",
        "pragmas",
        "rules",
    )
    IMPORTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDES_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    EXTERN_RULES_FIELD_NUMBER: _ClassVar[int]
    EXTERN_IMPORTS_FIELD_NUMBER: _ClassVar[int]
    PRAGMAS_FIELD_NUMBER: _ClassVar[int]
    NAMESPACES_FIELD_NUMBER: _ClassVar[int]
    imports: _containers.RepeatedCompositeFieldContainer[Import]
    includes: _containers.RepeatedCompositeFieldContainer[Include]
    rules: _containers.RepeatedCompositeFieldContainer[Rule]
    metadata: Metadata
    extern_rules: _containers.RepeatedCompositeFieldContainer[ExternRule]
    extern_imports: _containers.RepeatedCompositeFieldContainer[ExternImport]
    pragmas: _containers.RepeatedCompositeFieldContainer[Pragma]
    namespaces: _containers.RepeatedCompositeFieldContainer[ExternNamespace]
    def __init__(
        self,
        imports: _Iterable[Import | _Mapping] | None = ...,
        includes: _Iterable[Include | _Mapping] | None = ...,
        rules: _Iterable[Rule | _Mapping] | None = ...,
        metadata: Metadata | _Mapping | None = ...,
        extern_rules: _Iterable[ExternRule | _Mapping] | None = ...,
        extern_imports: _Iterable[ExternImport | _Mapping] | None = ...,
        pragmas: _Iterable[Pragma | _Mapping] | None = ...,
        namespaces: _Iterable[ExternNamespace | _Mapping] | None = ...,
    ) -> None: ...

class Metadata(_message.Message):
    __slots__ = (
        "ast_type",
        "format",
        "imports_count",
        "includes_count",
        "rules_count",
        "source_file",
        "timestamp",
        "version",
    )
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    AST_TYPE_FIELD_NUMBER: _ClassVar[int]
    RULES_COUNT_FIELD_NUMBER: _ClassVar[int]
    IMPORTS_COUNT_FIELD_NUMBER: _ClassVar[int]
    INCLUDES_COUNT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FILE_FIELD_NUMBER: _ClassVar[int]
    format: str
    version: str
    ast_type: str
    rules_count: int
    imports_count: int
    includes_count: int
    timestamp: int
    source_file: str
    def __init__(
        self,
        format: str | None = ...,
        version: str | None = ...,
        ast_type: str | None = ...,
        rules_count: int | None = ...,
        imports_count: int | None = ...,
        includes_count: int | None = ...,
        timestamp: int | None = ...,
        source_file: str | None = ...,
    ) -> None: ...

class Import(_message.Message):
    __slots__ = ("alias", "module")
    MODULE_FIELD_NUMBER: _ClassVar[int]
    ALIAS_FIELD_NUMBER: _ClassVar[int]
    module: str
    alias: str
    def __init__(self, module: str | None = ..., alias: str | None = ...) -> None: ...

class Include(_message.Message):
    __slots__ = ("path",)
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: str
    def __init__(self, path: str | None = ...) -> None: ...

class Rule(_message.Message):
    __slots__ = (
        "condition",
        "meta",
        "meta_scopes",
        "modifiers",
        "name",
        "pragmas",
        "strings",
        "tags",
    )

    class MetaEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: MetaValue
        def __init__(
            self, key: str | None = ..., value: MetaValue | _Mapping | None = ...
        ) -> None: ...

    class MetaScopesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: str | None = ..., value: str | None = ...) -> None: ...

    NAME_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    TAGS_FIELD_NUMBER: _ClassVar[int]
    META_FIELD_NUMBER: _ClassVar[int]
    STRINGS_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    META_SCOPES_FIELD_NUMBER: _ClassVar[int]
    PRAGMAS_FIELD_NUMBER: _ClassVar[int]
    name: str
    modifiers: _containers.RepeatedScalarFieldContainer[str]
    tags: _containers.RepeatedCompositeFieldContainer[Tag]
    meta: _containers.MessageMap[str, MetaValue]
    strings: _containers.RepeatedCompositeFieldContainer[StringDefinition]
    condition: Expression
    meta_scopes: _containers.ScalarMap[str, str]
    pragmas: _containers.RepeatedCompositeFieldContainer[InRulePragma]
    def __init__(
        self,
        name: str | None = ...,
        modifiers: _Iterable[str] | None = ...,
        tags: _Iterable[Tag | _Mapping] | None = ...,
        meta: _Mapping[str, MetaValue] | None = ...,
        strings: _Iterable[StringDefinition | _Mapping] | None = ...,
        condition: Expression | _Mapping | None = ...,
        meta_scopes: _Mapping[str, str] | None = ...,
        pragmas: _Iterable[InRulePragma | _Mapping] | None = ...,
    ) -> None: ...

class Tag(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: str | None = ...) -> None: ...

class MetaValue(_message.Message):
    __slots__ = ("bool_value", "double_value", "int_value", "string_value")
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOL_VALUE_FIELD_NUMBER: _ClassVar[int]
    DOUBLE_VALUE_FIELD_NUMBER: _ClassVar[int]
    string_value: str
    int_value: int
    bool_value: bool
    double_value: float
    def __init__(
        self,
        string_value: str | None = ...,
        int_value: int | None = ...,
        bool_value: bool | None = ...,
        double_value: float | None = ...,
    ) -> None: ...

class ExternRule(_message.Message):
    __slots__ = ("modifiers", "name", "namespace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    modifiers: _containers.RepeatedScalarFieldContainer[str]
    namespace: str
    def __init__(
        self,
        name: str | None = ...,
        modifiers: _Iterable[str] | None = ...,
        namespace: str | None = ...,
    ) -> None: ...

class ExternImport(_message.Message):
    __slots__ = ("alias", "module_path", "rules")
    MODULE_PATH_FIELD_NUMBER: _ClassVar[int]
    ALIAS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    module_path: str
    alias: str
    rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(
        self,
        module_path: str | None = ...,
        alias: str | None = ...,
        rules: _Iterable[str] | None = ...,
    ) -> None: ...

class ExternNamespace(_message.Message):
    __slots__ = ("extern_rules", "name")
    NAME_FIELD_NUMBER: _ClassVar[int]
    EXTERN_RULES_FIELD_NUMBER: _ClassVar[int]
    name: str
    extern_rules: _containers.RepeatedCompositeFieldContainer[ExternRule]
    def __init__(
        self, name: str | None = ..., extern_rules: _Iterable[ExternRule | _Mapping] | None = ...
    ) -> None: ...

class Pragma(_message.Message):
    __slots__ = (
        "arguments",
        "condition",
        "macro_name",
        "macro_value",
        "name",
        "parameters",
        "pragma_type",
        "scope",
    )

    class ParametersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: MetaValue
        def __init__(
            self, key: str | None = ..., value: MetaValue | _Mapping | None = ...
        ) -> None: ...

    PRAGMA_TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    MACRO_NAME_FIELD_NUMBER: _ClassVar[int]
    MACRO_VALUE_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    pragma_type: str
    name: str
    arguments: _containers.RepeatedScalarFieldContainer[str]
    scope: str
    macro_name: str
    macro_value: str
    condition: str
    parameters: _containers.MessageMap[str, MetaValue]
    def __init__(
        self,
        pragma_type: str | None = ...,
        name: str | None = ...,
        arguments: _Iterable[str] | None = ...,
        scope: str | None = ...,
        macro_name: str | None = ...,
        macro_value: str | None = ...,
        condition: str | None = ...,
        parameters: _Mapping[str, MetaValue] | None = ...,
    ) -> None: ...

class InRulePragma(_message.Message):
    __slots__ = ("position", "pragma")
    PRAGMA_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    pragma: Pragma
    position: str
    def __init__(
        self, pragma: Pragma | _Mapping | None = ..., position: str | None = ...
    ) -> None: ...

class StringDefinition(_message.Message):
    __slots__ = ("hex", "identifier", "plain", "regex")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    PLAIN_FIELD_NUMBER: _ClassVar[int]
    HEX_FIELD_NUMBER: _ClassVar[int]
    REGEX_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    plain: PlainString
    hex: HexString
    regex: RegexString
    def __init__(
        self,
        identifier: str | None = ...,
        plain: PlainString | _Mapping | None = ...,
        hex: HexString | _Mapping | None = ...,
        regex: RegexString | _Mapping | None = ...,
    ) -> None: ...

class PlainString(_message.Message):
    __slots__ = ("modifiers", "value")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    value: str
    modifiers: _containers.RepeatedCompositeFieldContainer[StringModifier]
    def __init__(
        self, value: str | None = ..., modifiers: _Iterable[StringModifier | _Mapping] | None = ...
    ) -> None: ...

class HexString(_message.Message):
    __slots__ = ("modifiers", "tokens")
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    tokens: _containers.RepeatedCompositeFieldContainer[HexToken]
    modifiers: _containers.RepeatedCompositeFieldContainer[StringModifier]
    def __init__(
        self,
        tokens: _Iterable[HexToken | _Mapping] | None = ...,
        modifiers: _Iterable[StringModifier | _Mapping] | None = ...,
    ) -> None: ...

class RegexString(_message.Message):
    __slots__ = ("modifiers", "regex")
    REGEX_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    regex: str
    modifiers: _containers.RepeatedCompositeFieldContainer[StringModifier]
    def __init__(
        self, regex: str | None = ..., modifiers: _Iterable[StringModifier | _Mapping] | None = ...
    ) -> None: ...

class StringModifier(_message.Message):
    __slots__ = ("name", "tuple_value", "typed_value", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    TYPED_VALUE_FIELD_NUMBER: _ClassVar[int]
    TUPLE_VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: str
    typed_value: MetaValue
    tuple_value: _containers.RepeatedScalarFieldContainer[int]
    def __init__(
        self,
        name: str | None = ...,
        value: str | None = ...,
        typed_value: MetaValue | _Mapping | None = ...,
        tuple_value: _Iterable[int] | None = ...,
    ) -> None: ...

class HexToken(_message.Message):
    __slots__ = ("alternative", "byte", "jump", "negated_byte", "nibble", "wildcard")
    BYTE_FIELD_NUMBER: _ClassVar[int]
    WILDCARD_FIELD_NUMBER: _ClassVar[int]
    JUMP_FIELD_NUMBER: _ClassVar[int]
    ALTERNATIVE_FIELD_NUMBER: _ClassVar[int]
    NIBBLE_FIELD_NUMBER: _ClassVar[int]
    NEGATED_BYTE_FIELD_NUMBER: _ClassVar[int]
    byte: HexByte
    wildcard: HexWildcard
    jump: HexJump
    alternative: HexAlternative
    nibble: HexNibble
    negated_byte: HexNegatedByte
    def __init__(
        self,
        byte: HexByte | _Mapping | None = ...,
        wildcard: HexWildcard | _Mapping | None = ...,
        jump: HexJump | _Mapping | None = ...,
        alternative: HexAlternative | _Mapping | None = ...,
        nibble: HexNibble | _Mapping | None = ...,
        negated_byte: HexNegatedByte | _Mapping | None = ...,
    ) -> None: ...

class HexByte(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: str | None = ...) -> None: ...

class HexNegatedByte(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: str | None = ...) -> None: ...

class HexWildcard(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HexJump(_message.Message):
    __slots__ = ("max_jump", "min_jump")
    MIN_JUMP_FIELD_NUMBER: _ClassVar[int]
    MAX_JUMP_FIELD_NUMBER: _ClassVar[int]
    min_jump: int
    max_jump: int
    def __init__(self, min_jump: int | None = ..., max_jump: int | None = ...) -> None: ...

class HexAlternative(_message.Message):
    __slots__ = ("alternatives",)
    ALTERNATIVES_FIELD_NUMBER: _ClassVar[int]
    alternatives: _containers.RepeatedCompositeFieldContainer[HexTokenList]
    def __init__(self, alternatives: _Iterable[HexTokenList | _Mapping] | None = ...) -> None: ...

class HexTokenList(_message.Message):
    __slots__ = ("tokens",)
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    tokens: _containers.RepeatedCompositeFieldContainer[HexToken]
    def __init__(self, tokens: _Iterable[HexToken | _Mapping] | None = ...) -> None: ...

class HexNibble(_message.Message):
    __slots__ = ("high", "value")
    HIGH_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    high: bool
    value: int
    def __init__(self, high: bool | None = ..., value: int | None = ...) -> None: ...

class Expression(_message.Message):
    __slots__ = (
        "array_access",
        "at_expression",
        "binary_expression",
        "boolean_literal",
        "defined_expression",
        "dictionary_access",
        "double_literal",
        "extern_rule_reference",
        "for_expression",
        "for_of_expression",
        "function_call",
        "identifier",
        "in_expression",
        "integer_literal",
        "member_access",
        "module_reference",
        "of_expression",
        "parentheses_expression",
        "range_expression",
        "regex_literal",
        "set_expression",
        "string_count",
        "string_identifier",
        "string_length",
        "string_literal",
        "string_offset",
        "string_operator_expression",
        "string_wildcard",
        "unary_expression",
    )
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    STRING_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    STRING_COUNT_FIELD_NUMBER: _ClassVar[int]
    STRING_OFFSET_FIELD_NUMBER: _ClassVar[int]
    STRING_LENGTH_FIELD_NUMBER: _ClassVar[int]
    INTEGER_LITERAL_FIELD_NUMBER: _ClassVar[int]
    DOUBLE_LITERAL_FIELD_NUMBER: _ClassVar[int]
    STRING_LITERAL_FIELD_NUMBER: _ClassVar[int]
    REGEX_LITERAL_FIELD_NUMBER: _ClassVar[int]
    BOOLEAN_LITERAL_FIELD_NUMBER: _ClassVar[int]
    BINARY_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    UNARY_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    PARENTHESES_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    SET_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    RANGE_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_CALL_FIELD_NUMBER: _ClassVar[int]
    ARRAY_ACCESS_FIELD_NUMBER: _ClassVar[int]
    MEMBER_ACCESS_FIELD_NUMBER: _ClassVar[int]
    FOR_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    FOR_OF_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    AT_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    IN_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    OF_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    DEFINED_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    STRING_OPERATOR_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    STRING_WILDCARD_FIELD_NUMBER: _ClassVar[int]
    MODULE_REFERENCE_FIELD_NUMBER: _ClassVar[int]
    DICTIONARY_ACCESS_FIELD_NUMBER: _ClassVar[int]
    EXTERN_RULE_REFERENCE_FIELD_NUMBER: _ClassVar[int]
    identifier: Identifier
    string_identifier: StringIdentifier
    string_count: StringCount
    string_offset: StringOffset
    string_length: StringLength
    integer_literal: IntegerLiteral
    double_literal: DoubleLiteral
    string_literal: StringLiteral
    regex_literal: RegexLiteral
    boolean_literal: BooleanLiteral
    binary_expression: BinaryExpression
    unary_expression: UnaryExpression
    parentheses_expression: ParenthesesExpression
    set_expression: SetExpression
    range_expression: RangeExpression
    function_call: FunctionCall
    array_access: ArrayAccess
    member_access: MemberAccess
    for_expression: ForExpression
    for_of_expression: ForOfExpression
    at_expression: AtExpression
    in_expression: InExpression
    of_expression: OfExpression
    defined_expression: DefinedExpression
    string_operator_expression: StringOperatorExpression
    string_wildcard: StringWildcard
    module_reference: ModuleReference
    dictionary_access: DictionaryAccess
    extern_rule_reference: ExternRuleReference
    def __init__(
        self,
        identifier: Identifier | _Mapping | None = ...,
        string_identifier: StringIdentifier | _Mapping | None = ...,
        string_count: StringCount | _Mapping | None = ...,
        string_offset: StringOffset | _Mapping | None = ...,
        string_length: StringLength | _Mapping | None = ...,
        integer_literal: IntegerLiteral | _Mapping | None = ...,
        double_literal: DoubleLiteral | _Mapping | None = ...,
        string_literal: StringLiteral | _Mapping | None = ...,
        regex_literal: RegexLiteral | _Mapping | None = ...,
        boolean_literal: BooleanLiteral | _Mapping | None = ...,
        binary_expression: BinaryExpression | _Mapping | None = ...,
        unary_expression: UnaryExpression | _Mapping | None = ...,
        parentheses_expression: ParenthesesExpression | _Mapping | None = ...,
        set_expression: SetExpression | _Mapping | None = ...,
        range_expression: RangeExpression | _Mapping | None = ...,
        function_call: FunctionCall | _Mapping | None = ...,
        array_access: ArrayAccess | _Mapping | None = ...,
        member_access: MemberAccess | _Mapping | None = ...,
        for_expression: ForExpression | _Mapping | None = ...,
        for_of_expression: ForOfExpression | _Mapping | None = ...,
        at_expression: AtExpression | _Mapping | None = ...,
        in_expression: InExpression | _Mapping | None = ...,
        of_expression: OfExpression | _Mapping | None = ...,
        defined_expression: DefinedExpression | _Mapping | None = ...,
        string_operator_expression: StringOperatorExpression | _Mapping | None = ...,
        string_wildcard: StringWildcard | _Mapping | None = ...,
        module_reference: ModuleReference | _Mapping | None = ...,
        dictionary_access: DictionaryAccess | _Mapping | None = ...,
        extern_rule_reference: ExternRuleReference | _Mapping | None = ...,
    ) -> None: ...

class Identifier(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: str | None = ...) -> None: ...

class StringIdentifier(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: str | None = ...) -> None: ...

class StringWildcard(_message.Message):
    __slots__ = ("pattern",)
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    pattern: str
    def __init__(self, pattern: str | None = ...) -> None: ...

class StringCount(_message.Message):
    __slots__ = ("string_id",)
    STRING_ID_FIELD_NUMBER: _ClassVar[int]
    string_id: str
    def __init__(self, string_id: str | None = ...) -> None: ...

class StringOffset(_message.Message):
    __slots__ = ("index", "string_id")
    STRING_ID_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    string_id: str
    index: Expression
    def __init__(
        self, string_id: str | None = ..., index: Expression | _Mapping | None = ...
    ) -> None: ...

class StringLength(_message.Message):
    __slots__ = ("index", "string_id")
    STRING_ID_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    string_id: str
    index: Expression
    def __init__(
        self, string_id: str | None = ..., index: Expression | _Mapping | None = ...
    ) -> None: ...

class IntegerLiteral(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: int
    def __init__(self, value: int | None = ...) -> None: ...

class DoubleLiteral(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: float
    def __init__(self, value: float | None = ...) -> None: ...

class StringLiteral(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: str | None = ...) -> None: ...

class RegexLiteral(_message.Message):
    __slots__ = ("modifiers", "pattern")
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    pattern: str
    modifiers: str
    def __init__(self, pattern: str | None = ..., modifiers: str | None = ...) -> None: ...

class BooleanLiteral(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: bool
    def __init__(self, value: bool | None = ...) -> None: ...

class BinaryExpression(_message.Message):
    __slots__ = ("left", "operator", "right")
    LEFT_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_FIELD_NUMBER: _ClassVar[int]
    RIGHT_FIELD_NUMBER: _ClassVar[int]
    left: Expression
    operator: str
    right: Expression
    def __init__(
        self,
        left: Expression | _Mapping | None = ...,
        operator: str | None = ...,
        right: Expression | _Mapping | None = ...,
    ) -> None: ...

class UnaryExpression(_message.Message):
    __slots__ = ("operand", "operator")
    OPERATOR_FIELD_NUMBER: _ClassVar[int]
    OPERAND_FIELD_NUMBER: _ClassVar[int]
    operator: str
    operand: Expression
    def __init__(
        self, operator: str | None = ..., operand: Expression | _Mapping | None = ...
    ) -> None: ...

class ParenthesesExpression(_message.Message):
    __slots__ = ("expression",)
    EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    expression: Expression
    def __init__(self, expression: Expression | _Mapping | None = ...) -> None: ...

class SetExpression(_message.Message):
    __slots__ = ("elements",)
    ELEMENTS_FIELD_NUMBER: _ClassVar[int]
    elements: _containers.RepeatedCompositeFieldContainer[Expression]
    def __init__(self, elements: _Iterable[Expression | _Mapping] | None = ...) -> None: ...

class RangeExpression(_message.Message):
    __slots__ = ("high", "low")
    LOW_FIELD_NUMBER: _ClassVar[int]
    HIGH_FIELD_NUMBER: _ClassVar[int]
    low: Expression
    high: Expression
    def __init__(
        self, low: Expression | _Mapping | None = ..., high: Expression | _Mapping | None = ...
    ) -> None: ...

class FunctionCall(_message.Message):
    __slots__ = ("arguments", "function")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    function: str
    arguments: _containers.RepeatedCompositeFieldContainer[Expression]
    def __init__(
        self, function: str | None = ..., arguments: _Iterable[Expression | _Mapping] | None = ...
    ) -> None: ...

class ArrayAccess(_message.Message):
    __slots__ = ("array", "index")
    ARRAY_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    array: Expression
    index: Expression
    def __init__(
        self, array: Expression | _Mapping | None = ..., index: Expression | _Mapping | None = ...
    ) -> None: ...

class MemberAccess(_message.Message):
    __slots__ = ("member", "object")
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    MEMBER_FIELD_NUMBER: _ClassVar[int]
    object: Expression
    member: str
    def __init__(
        self, object: Expression | _Mapping | None = ..., member: str | None = ...
    ) -> None: ...

class ModuleReference(_message.Message):
    __slots__ = ("module",)
    MODULE_FIELD_NUMBER: _ClassVar[int]
    module: str
    def __init__(self, module: str | None = ...) -> None: ...

class DictionaryAccess(_message.Message):
    __slots__ = ("key", "key_expr", "object")
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    KEY_EXPR_FIELD_NUMBER: _ClassVar[int]
    object: Expression
    key: str
    key_expr: Expression
    def __init__(
        self,
        object: Expression | _Mapping | None = ...,
        key: str | None = ...,
        key_expr: Expression | _Mapping | None = ...,
    ) -> None: ...

class ExternRuleReference(_message.Message):
    __slots__ = ("namespace", "rule_name")
    RULE_NAME_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    rule_name: str
    namespace: str
    def __init__(self, rule_name: str | None = ..., namespace: str | None = ...) -> None: ...

class ForExpression(_message.Message):
    __slots__ = ("body", "iterable", "quantifier", "quantifier_expr", "variable")
    QUANTIFIER_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_FIELD_NUMBER: _ClassVar[int]
    ITERABLE_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    QUANTIFIER_EXPR_FIELD_NUMBER: _ClassVar[int]
    quantifier: str
    variable: str
    iterable: Expression
    body: Expression
    quantifier_expr: Expression
    def __init__(
        self,
        quantifier: str | None = ...,
        variable: str | None = ...,
        iterable: Expression | _Mapping | None = ...,
        body: Expression | _Mapping | None = ...,
        quantifier_expr: Expression | _Mapping | None = ...,
    ) -> None: ...

class ForOfExpression(_message.Message):
    __slots__ = (
        "condition",
        "quantifier",
        "quantifier_expr",
        "string_set",
        "string_set_items",
        "string_set_text",
    )
    QUANTIFIER_FIELD_NUMBER: _ClassVar[int]
    STRING_SET_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    QUANTIFIER_EXPR_FIELD_NUMBER: _ClassVar[int]
    STRING_SET_TEXT_FIELD_NUMBER: _ClassVar[int]
    STRING_SET_ITEMS_FIELD_NUMBER: _ClassVar[int]
    quantifier: str
    string_set: Expression
    condition: Expression
    quantifier_expr: Expression
    string_set_text: str
    string_set_items: _containers.RepeatedScalarFieldContainer[str]
    def __init__(
        self,
        quantifier: str | None = ...,
        string_set: Expression | _Mapping | None = ...,
        condition: Expression | _Mapping | None = ...,
        quantifier_expr: Expression | _Mapping | None = ...,
        string_set_text: str | None = ...,
        string_set_items: _Iterable[str] | None = ...,
    ) -> None: ...

class AtExpression(_message.Message):
    __slots__ = ("offset", "string_id")
    STRING_ID_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    string_id: str
    offset: Expression
    def __init__(
        self, string_id: str | None = ..., offset: Expression | _Mapping | None = ...
    ) -> None: ...

class InExpression(_message.Message):
    __slots__ = ("range", "string_id", "subject")
    STRING_ID_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    string_id: str
    range: Expression
    subject: Expression
    def __init__(
        self,
        string_id: str | None = ...,
        range: Expression | _Mapping | None = ...,
        subject: Expression | _Mapping | None = ...,
    ) -> None: ...

class OfExpression(_message.Message):
    __slots__ = (
        "quantifier",
        "quantifier_text",
        "string_set",
        "string_set_items",
        "string_set_text",
    )
    QUANTIFIER_FIELD_NUMBER: _ClassVar[int]
    STRING_SET_FIELD_NUMBER: _ClassVar[int]
    QUANTIFIER_TEXT_FIELD_NUMBER: _ClassVar[int]
    STRING_SET_TEXT_FIELD_NUMBER: _ClassVar[int]
    STRING_SET_ITEMS_FIELD_NUMBER: _ClassVar[int]
    quantifier: Expression
    string_set: Expression
    quantifier_text: str
    string_set_text: str
    string_set_items: _containers.RepeatedScalarFieldContainer[str]
    def __init__(
        self,
        quantifier: Expression | _Mapping | None = ...,
        string_set: Expression | _Mapping | None = ...,
        quantifier_text: str | None = ...,
        string_set_text: str | None = ...,
        string_set_items: _Iterable[str] | None = ...,
    ) -> None: ...

class DefinedExpression(_message.Message):
    __slots__ = ("expression",)
    EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    expression: Expression
    def __init__(self, expression: Expression | _Mapping | None = ...) -> None: ...

class StringOperatorExpression(_message.Message):
    __slots__ = ("left", "operator", "right")
    LEFT_FIELD_NUMBER: _ClassVar[int]
    OPERATOR_FIELD_NUMBER: _ClassVar[int]
    RIGHT_FIELD_NUMBER: _ClassVar[int]
    left: Expression
    operator: str
    right: Expression
    def __init__(
        self,
        left: Expression | _Mapping | None = ...,
        operator: str | None = ...,
        right: Expression | _Mapping | None = ...,
    ) -> None: ...
