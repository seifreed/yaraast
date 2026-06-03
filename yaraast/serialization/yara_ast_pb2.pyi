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
        "node_metadata",
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
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    imports: _containers.RepeatedCompositeFieldContainer[Import]
    includes: _containers.RepeatedCompositeFieldContainer[Include]
    rules: _containers.RepeatedCompositeFieldContainer[Rule]
    metadata: Metadata
    extern_rules: _containers.RepeatedCompositeFieldContainer[ExternRule]
    extern_imports: _containers.RepeatedCompositeFieldContainer[ExternImport]
    pragmas: _containers.RepeatedCompositeFieldContainer[Pragma]
    namespaces: _containers.RepeatedCompositeFieldContainer[ExternNamespace]
    node_metadata: NodeMetadata
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
        node_metadata: NodeMetadata | _Mapping | None = ...,
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

class SourceLocation(_message.Message):
    __slots__ = ("column", "end_column", "end_line", "file", "line")
    LINE_FIELD_NUMBER: _ClassVar[int]
    COLUMN_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    END_LINE_FIELD_NUMBER: _ClassVar[int]
    END_COLUMN_FIELD_NUMBER: _ClassVar[int]
    line: int
    column: int
    file: str
    end_line: int
    end_column: int
    def __init__(
        self,
        line: int | None = ...,
        column: int | None = ...,
        file: str | None = ...,
        end_line: int | None = ...,
        end_column: int | None = ...,
    ) -> None: ...

class AstComment(_message.Message):
    __slots__ = ("is_multiline", "node_metadata", "text")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    IS_MULTILINE_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    text: str
    is_multiline: bool
    node_metadata: NodeMetadata
    def __init__(
        self,
        text: str | None = ...,
        is_multiline: bool | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class AstCommentGroup(_message.Message):
    __slots__ = ("comments", "node_metadata")
    COMMENTS_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    comments: _containers.RepeatedCompositeFieldContainer[AstComment]
    node_metadata: NodeMetadata
    def __init__(
        self,
        comments: _Iterable[AstComment | _Mapping] | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class CommentMetadata(_message.Message):
    __slots__ = ("comment", "group")
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    comment: AstComment
    group: AstCommentGroup
    def __init__(
        self,
        comment: AstComment | _Mapping | None = ...,
        group: AstCommentGroup | _Mapping | None = ...,
    ) -> None: ...

class NodeMetadata(_message.Message):
    __slots__ = ("leading_comments", "location", "trailing_comment")
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    LEADING_COMMENTS_FIELD_NUMBER: _ClassVar[int]
    TRAILING_COMMENT_FIELD_NUMBER: _ClassVar[int]
    location: SourceLocation
    leading_comments: _containers.RepeatedCompositeFieldContainer[CommentMetadata]
    trailing_comment: CommentMetadata
    def __init__(
        self,
        location: SourceLocation | _Mapping | None = ...,
        leading_comments: _Iterable[CommentMetadata | _Mapping] | None = ...,
        trailing_comment: CommentMetadata | _Mapping | None = ...,
    ) -> None: ...

class Import(_message.Message):
    __slots__ = ("alias", "module", "node_metadata")
    MODULE_FIELD_NUMBER: _ClassVar[int]
    ALIAS_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    module: str
    alias: str
    node_metadata: NodeMetadata
    def __init__(
        self,
        module: str | None = ...,
        alias: str | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class Include(_message.Message):
    __slots__ = ("node_metadata", "path")
    PATH_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    path: str
    node_metadata: NodeMetadata
    def __init__(
        self,
        path: str | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class Rule(_message.Message):
    __slots__ = (
        "condition",
        "meta",
        "meta_entries",
        "meta_scopes",
        "modifiers",
        "name",
        "node_metadata",
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
    META_ENTRIES_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    name: str
    modifiers: _containers.RepeatedScalarFieldContainer[str]
    tags: _containers.RepeatedCompositeFieldContainer[Tag]
    meta: _containers.MessageMap[str, MetaValue]
    strings: _containers.RepeatedCompositeFieldContainer[StringDefinition]
    condition: Expression
    meta_scopes: _containers.ScalarMap[str, str]
    pragmas: _containers.RepeatedCompositeFieldContainer[InRulePragma]
    meta_entries: _containers.RepeatedCompositeFieldContainer[RuleMetaEntry]
    node_metadata: NodeMetadata
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
        meta_entries: _Iterable[RuleMetaEntry | _Mapping] | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class Tag(_message.Message):
    __slots__ = ("name", "node_metadata")
    NAME_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    name: str
    node_metadata: NodeMetadata
    def __init__(
        self,
        name: str | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

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

class RuleMetaEntry(_message.Message):
    __slots__ = ("ast_node", "key", "node_metadata", "scope", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    AST_NODE_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: MetaValue
    scope: str
    ast_node: bool
    node_metadata: NodeMetadata
    def __init__(
        self,
        key: str | None = ...,
        value: MetaValue | _Mapping | None = ...,
        scope: str | None = ...,
        ast_node: bool | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class ExternRule(_message.Message):
    __slots__ = ("modifiers", "name", "namespace", "node_metadata")
    NAME_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    name: str
    modifiers: _containers.RepeatedScalarFieldContainer[str]
    namespace: str
    node_metadata: NodeMetadata
    def __init__(
        self,
        name: str | None = ...,
        modifiers: _Iterable[str] | None = ...,
        namespace: str | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class ExternImport(_message.Message):
    __slots__ = ("alias", "module_path", "node_metadata", "rules")
    MODULE_PATH_FIELD_NUMBER: _ClassVar[int]
    ALIAS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    module_path: str
    alias: str
    rules: _containers.RepeatedScalarFieldContainer[str]
    node_metadata: NodeMetadata
    def __init__(
        self,
        module_path: str | None = ...,
        alias: str | None = ...,
        rules: _Iterable[str] | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class ExternNamespace(_message.Message):
    __slots__ = ("extern_rules", "name", "node_metadata")
    NAME_FIELD_NUMBER: _ClassVar[int]
    EXTERN_RULES_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    name: str
    extern_rules: _containers.RepeatedCompositeFieldContainer[ExternRule]
    node_metadata: NodeMetadata
    def __init__(
        self,
        name: str | None = ...,
        extern_rules: _Iterable[ExternRule | _Mapping] | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class Pragma(_message.Message):
    __slots__ = (
        "arguments",
        "condition",
        "macro_name",
        "macro_value",
        "name",
        "node_metadata",
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
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    pragma_type: str
    name: str
    arguments: _containers.RepeatedScalarFieldContainer[str]
    scope: str
    macro_name: str
    macro_value: str
    condition: str
    parameters: _containers.MessageMap[str, MetaValue]
    node_metadata: NodeMetadata
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
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class InRulePragma(_message.Message):
    __slots__ = ("node_metadata", "position", "pragma")
    PRAGMA_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    pragma: Pragma
    position: str
    node_metadata: NodeMetadata
    def __init__(
        self,
        pragma: Pragma | _Mapping | None = ...,
        position: str | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class StringDefinition(_message.Message):
    __slots__ = ("hex", "identifier", "is_anonymous", "node_metadata", "plain", "regex")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    IS_ANONYMOUS_FIELD_NUMBER: _ClassVar[int]
    PLAIN_FIELD_NUMBER: _ClassVar[int]
    HEX_FIELD_NUMBER: _ClassVar[int]
    REGEX_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    is_anonymous: bool
    plain: PlainString
    hex: HexString
    regex: RegexString
    node_metadata: NodeMetadata
    def __init__(
        self,
        identifier: str | None = ...,
        is_anonymous: bool | None = ...,
        plain: PlainString | _Mapping | None = ...,
        hex: HexString | _Mapping | None = ...,
        regex: RegexString | _Mapping | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class PlainString(_message.Message):
    __slots__ = ("modifiers", "raw_value", "value")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    RAW_VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    modifiers: _containers.RepeatedCompositeFieldContainer[StringModifier]
    raw_value: bytes
    def __init__(
        self,
        value: str | None = ...,
        modifiers: _Iterable[StringModifier | _Mapping] | None = ...,
        raw_value: bytes | None = ...,
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
        self,
        regex: str | None = ...,
        modifiers: _Iterable[StringModifier | _Mapping] | None = ...,
    ) -> None: ...

class StringModifier(_message.Message):
    __slots__ = ("name", "node_metadata", "tuple_value", "typed_value", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    TYPED_VALUE_FIELD_NUMBER: _ClassVar[int]
    TUPLE_VALUE_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: str
    typed_value: MetaValue
    tuple_value: _containers.RepeatedScalarFieldContainer[int]
    node_metadata: NodeMetadata
    def __init__(
        self,
        name: str | None = ...,
        value: str | None = ...,
        typed_value: MetaValue | _Mapping | None = ...,
        tuple_value: _Iterable[int] | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class HexToken(_message.Message):
    __slots__ = (
        "alternative",
        "byte",
        "jump",
        "negated_byte",
        "nibble",
        "node_metadata",
        "wildcard",
    )
    BYTE_FIELD_NUMBER: _ClassVar[int]
    WILDCARD_FIELD_NUMBER: _ClassVar[int]
    JUMP_FIELD_NUMBER: _ClassVar[int]
    ALTERNATIVE_FIELD_NUMBER: _ClassVar[int]
    NIBBLE_FIELD_NUMBER: _ClassVar[int]
    NEGATED_BYTE_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    byte: HexByte
    wildcard: HexWildcard
    jump: HexJump
    alternative: HexAlternative
    nibble: HexNibble
    negated_byte: HexNegatedByte
    node_metadata: NodeMetadata
    def __init__(
        self,
        byte: HexByte | _Mapping | None = ...,
        wildcard: HexWildcard | _Mapping | None = ...,
        jump: HexJump | _Mapping | None = ...,
        alternative: HexAlternative | _Mapping | None = ...,
        nibble: HexNibble | _Mapping | None = ...,
        negated_byte: HexNegatedByte | _Mapping | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
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
        "array_comprehension",
        "at_expression",
        "binary_expression",
        "boolean_literal",
        "defined_expression",
        "dict_comprehension",
        "dict_expression",
        "dictionary_access",
        "double_literal",
        "extern_rule_reference",
        "for_expression",
        "for_of_expression",
        "function_call",
        "identifier",
        "in_expression",
        "integer_literal",
        "lambda_expression",
        "list_expression",
        "member_access",
        "module_reference",
        "node_metadata",
        "of_expression",
        "parentheses_expression",
        "pattern_match",
        "range_expression",
        "regex_literal",
        "set_expression",
        "slice_expression",
        "spread_operator",
        "string_count",
        "string_identifier",
        "string_length",
        "string_literal",
        "string_offset",
        "string_operator_expression",
        "string_wildcard",
        "tuple_expression",
        "tuple_indexing",
        "unary_expression",
        "with_statement",
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
    WITH_STATEMENT_FIELD_NUMBER: _ClassVar[int]
    ARRAY_COMPREHENSION_FIELD_NUMBER: _ClassVar[int]
    DICT_COMPREHENSION_FIELD_NUMBER: _ClassVar[int]
    TUPLE_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    TUPLE_INDEXING_FIELD_NUMBER: _ClassVar[int]
    LIST_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    DICT_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    SLICE_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    LAMBDA_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    PATTERN_MATCH_FIELD_NUMBER: _ClassVar[int]
    SPREAD_OPERATOR_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
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
    with_statement: WithStatement
    array_comprehension: ArrayComprehension
    dict_comprehension: DictComprehension
    tuple_expression: TupleExpression
    tuple_indexing: TupleIndexing
    list_expression: ListExpression
    dict_expression: DictExpression
    slice_expression: SliceExpression
    lambda_expression: LambdaExpression
    pattern_match: PatternMatch
    spread_operator: SpreadOperator
    node_metadata: NodeMetadata
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
        with_statement: WithStatement | _Mapping | None = ...,
        array_comprehension: ArrayComprehension | _Mapping | None = ...,
        dict_comprehension: DictComprehension | _Mapping | None = ...,
        tuple_expression: TupleExpression | _Mapping | None = ...,
        tuple_indexing: TupleIndexing | _Mapping | None = ...,
        list_expression: ListExpression | _Mapping | None = ...,
        dict_expression: DictExpression | _Mapping | None = ...,
        slice_expression: SliceExpression | _Mapping | None = ...,
        lambda_expression: LambdaExpression | _Mapping | None = ...,
        pattern_match: PatternMatch | _Mapping | None = ...,
        spread_operator: SpreadOperator | _Mapping | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
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
        self,
        low: Expression | _Mapping | None = ...,
        high: Expression | _Mapping | None = ...,
    ) -> None: ...

class FunctionCall(_message.Message):
    __slots__ = ("arguments", "function", "receiver")
    FUNCTION_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    RECEIVER_FIELD_NUMBER: _ClassVar[int]
    function: str
    arguments: _containers.RepeatedCompositeFieldContainer[Expression]
    receiver: Expression
    def __init__(
        self,
        function: str | None = ...,
        arguments: _Iterable[Expression | _Mapping] | None = ...,
        receiver: Expression | _Mapping | None = ...,
    ) -> None: ...

class ArrayAccess(_message.Message):
    __slots__ = ("array", "index")
    ARRAY_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    array: Expression
    index: Expression
    def __init__(
        self,
        array: Expression | _Mapping | None = ...,
        index: Expression | _Mapping | None = ...,
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

class WithStatement(_message.Message):
    __slots__ = ("body", "declarations")
    DECLARATIONS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    declarations: _containers.RepeatedCompositeFieldContainer[WithDeclaration]
    body: Expression
    def __init__(
        self,
        declarations: _Iterable[WithDeclaration | _Mapping] | None = ...,
        body: Expression | _Mapping | None = ...,
    ) -> None: ...

class WithDeclaration(_message.Message):
    __slots__ = ("identifier", "node_metadata", "value")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    value: Expression
    node_metadata: NodeMetadata
    def __init__(
        self,
        identifier: str | None = ...,
        value: Expression | _Mapping | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class ArrayComprehension(_message.Message):
    __slots__ = ("condition", "expression", "iterable", "variable")
    EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    VARIABLE_FIELD_NUMBER: _ClassVar[int]
    ITERABLE_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    expression: Expression
    variable: str
    iterable: Expression
    condition: Expression
    def __init__(
        self,
        expression: Expression | _Mapping | None = ...,
        variable: str | None = ...,
        iterable: Expression | _Mapping | None = ...,
        condition: Expression | _Mapping | None = ...,
    ) -> None: ...

class DictComprehension(_message.Message):
    __slots__ = (
        "condition",
        "iterable",
        "key_expression",
        "key_variable",
        "value_expression",
        "value_variable",
    )
    KEY_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    VALUE_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    KEY_VARIABLE_FIELD_NUMBER: _ClassVar[int]
    VALUE_VARIABLE_FIELD_NUMBER: _ClassVar[int]
    ITERABLE_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    key_expression: Expression
    value_expression: Expression
    key_variable: str
    value_variable: str
    iterable: Expression
    condition: Expression
    def __init__(
        self,
        key_expression: Expression | _Mapping | None = ...,
        value_expression: Expression | _Mapping | None = ...,
        key_variable: str | None = ...,
        value_variable: str | None = ...,
        iterable: Expression | _Mapping | None = ...,
        condition: Expression | _Mapping | None = ...,
    ) -> None: ...

class TupleExpression(_message.Message):
    __slots__ = ("elements",)
    ELEMENTS_FIELD_NUMBER: _ClassVar[int]
    elements: _containers.RepeatedCompositeFieldContainer[Expression]
    def __init__(self, elements: _Iterable[Expression | _Mapping] | None = ...) -> None: ...

class TupleIndexing(_message.Message):
    __slots__ = ("index", "tuple_expr")
    TUPLE_EXPR_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    tuple_expr: Expression
    index: Expression
    def __init__(
        self,
        tuple_expr: Expression | _Mapping | None = ...,
        index: Expression | _Mapping | None = ...,
    ) -> None: ...

class ListExpression(_message.Message):
    __slots__ = ("elements",)
    ELEMENTS_FIELD_NUMBER: _ClassVar[int]
    elements: _containers.RepeatedCompositeFieldContainer[Expression]
    def __init__(self, elements: _Iterable[Expression | _Mapping] | None = ...) -> None: ...

class DictExpression(_message.Message):
    __slots__ = ("items",)
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    items: _containers.RepeatedCompositeFieldContainer[DictItem]
    def __init__(self, items: _Iterable[DictItem | _Mapping] | None = ...) -> None: ...

class DictItem(_message.Message):
    __slots__ = ("key", "node_metadata", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    key: Expression
    value: Expression
    node_metadata: NodeMetadata
    def __init__(
        self,
        key: Expression | _Mapping | None = ...,
        value: Expression | _Mapping | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class SliceExpression(_message.Message):
    __slots__ = ("start", "step", "stop", "target")
    TARGET_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    STOP_FIELD_NUMBER: _ClassVar[int]
    STEP_FIELD_NUMBER: _ClassVar[int]
    target: Expression
    start: Expression
    stop: Expression
    step: Expression
    def __init__(
        self,
        target: Expression | _Mapping | None = ...,
        start: Expression | _Mapping | None = ...,
        stop: Expression | _Mapping | None = ...,
        step: Expression | _Mapping | None = ...,
    ) -> None: ...

class LambdaExpression(_message.Message):
    __slots__ = ("body", "parameters")
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    parameters: _containers.RepeatedScalarFieldContainer[str]
    body: Expression
    def __init__(
        self,
        parameters: _Iterable[str] | None = ...,
        body: Expression | _Mapping | None = ...,
    ) -> None: ...

class PatternMatch(_message.Message):
    __slots__ = ("cases", "default", "value")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    CASES_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_FIELD_NUMBER: _ClassVar[int]
    value: Expression
    cases: _containers.RepeatedCompositeFieldContainer[MatchCase]
    default: Expression
    def __init__(
        self,
        value: Expression | _Mapping | None = ...,
        cases: _Iterable[MatchCase | _Mapping] | None = ...,
        default: Expression | _Mapping | None = ...,
    ) -> None: ...

class MatchCase(_message.Message):
    __slots__ = ("node_metadata", "pattern", "result")
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    NODE_METADATA_FIELD_NUMBER: _ClassVar[int]
    pattern: Expression
    result: Expression
    node_metadata: NodeMetadata
    def __init__(
        self,
        pattern: Expression | _Mapping | None = ...,
        result: Expression | _Mapping | None = ...,
        node_metadata: NodeMetadata | _Mapping | None = ...,
    ) -> None: ...

class SpreadOperator(_message.Message):
    __slots__ = ("expression", "is_dict")
    EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    IS_DICT_FIELD_NUMBER: _ClassVar[int]
    expression: Expression
    is_dict: bool
    def __init__(
        self,
        expression: Expression | _Mapping | None = ...,
        is_dict: bool | None = ...,
    ) -> None: ...
