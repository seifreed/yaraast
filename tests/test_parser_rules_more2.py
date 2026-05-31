from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modifiers import RuleModifier
from yaraast.ast.pragmas import (
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    IncludeOncePragma,
    InRulePragma,
    UndefDirective,
)
from yaraast.ast.rules import Import, Rule
from yaraast.codegen.generator import CodeGenerator
from yaraast.lexer import Lexer
from yaraast.lexer.lexer_errors import LexerError
from yaraast.lexer.lexer_tables import YARA_IDENTIFIER_MAX_LENGTH
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.comment_aware_parser import CommentAwareParser
from yaraast.parser.parser import Parser
from yaraast.types.semantic_validator import SemanticValidator


def _t(tt: TokenType, value: str | int | float | None) -> Token:
    return Token(type=tt, value=value, line=1, column=1)


def _parser_with_tokens(tokens: list[Token]) -> Parser:
    parser = Parser("rule seed { condition: true }")
    parser.tokens = [*tokens, _t(TokenType.EOF, None)]
    parser.current = 0
    return parser


def test_parse_import_and_include_success_and_errors() -> None:
    parser = _parser_with_tokens([_t(TokenType.STRING, "pe")])
    imp = parser._parse_import()
    assert isinstance(imp, Import)
    assert imp.module == "pe"
    assert imp.alias is None

    parser2 = _parser_with_tokens(
        [_t(TokenType.STRING, "pe"), _t(TokenType.AS, "as"), _t(TokenType.IDENTIFIER, "pe_mod")]
    )
    with pytest.raises(ParserError, match="Import aliases are not supported"):
        parser2._parse_import()

    parser3 = _parser_with_tokens([_t(TokenType.IDENTIFIER, "pe")])
    with pytest.raises(ParserError, match="Expected module name after 'import'"):
        parser3._parse_import()

    parser4 = _parser_with_tokens([_t(TokenType.STRING, "common.yar")])
    inc = parser4._parse_include()
    assert inc.path == "common.yar"

    parser5 = _parser_with_tokens([_t(TokenType.IDENTIFIER, "common.yar")])
    with pytest.raises(ParserError, match="Expected file path after 'include'"):
        parser5._parse_include()


def test_parse_rule_helpers_and_meta_section_variants() -> None:
    parser = Parser(
        'private global rule demo : tag1 tag2 { meta: a = -1 b = "x" c = true d = false strings: $a = "x" condition: true }'
    )
    rule = parser._parse_rule()
    assert rule.name == "demo"
    assert [str(m) for m in rule.modifiers] == ["private", "global"]
    assert [tag.name for tag in rule.tags] == ["tag1", "tag2"]
    assert {m.key: m.value for m in rule.meta} == {"a": -1, "b": "x", "c": True, "d": False}
    assert len(rule.strings) == 1
    assert rule.condition is not None

    for parser in (Parser(), CommentAwareParser()):
        with pytest.raises(Exception, match="Expected integer after '-' in meta value"):
            parser.parse("rule invalid_meta { meta: score = -1.5 condition: true }")

    parser2 = _parser_with_tokens(
        [_t(TokenType.PRIVATE, "PRIVATE"), _t(TokenType.GLOBAL, "GLOBAL")]
    )
    assert parser2._parse_rule_modifiers() == ["private", "global"]

    parser3 = _parser_with_tokens([_t(TokenType.RULE, "rule"), _t(TokenType.IDENTIFIER, "named")])
    assert parser3._parse_rule_name() == "named"

    parser4 = _parser_with_tokens(
        [
            _t(TokenType.COLON, ":"),
            _t(TokenType.IDENTIFIER, "tag1"),
            _t(TokenType.IDENTIFIER, "tag2"),
        ]
    )
    assert [t.name for t in parser4._parse_rule_tags()] == ["tag1", "tag2"]

    parser5 = _parser_with_tokens([_t(TokenType.STRINGS, "strings")])
    with pytest.raises(ParserError, match="Expected ':' after 'meta'"):
        parser5._expect_colon("meta")

    parser6 = _parser_with_tokens(
        [
            _t(TokenType.IDENTIFIER, "neg"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.MINUS, "-"),
            _t(TokenType.INTEGER, 7),
            _t(TokenType.IDENTIFIER, "txt"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.STRING, "v"),
            _t(TokenType.IDENTIFIER, "yes"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.BOOLEAN_TRUE, "true"),
            _t(TokenType.IDENTIFIER, "no"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.BOOLEAN_FALSE, "false"),
            _t(TokenType.RBRACE, "}"),
        ]
    )
    assert [(entry.key, entry.value) for entry in parser6._parse_meta_section()] == [
        ("neg", -7),
        ("txt", "v"),
        ("yes", True),
        ("no", False),
    ]

    parser7 = _parser_with_tokens(
        [
            _t(TokenType.IDENTIFIER, "bad"),
            _t(TokenType.ASSIGN, "="),
            _t(TokenType.MINUS, "-"),
            _t(TokenType.STRING, "x"),
        ]
    )
    with pytest.raises(ParserError, match="Expected integer after '-' in meta value"):
        parser7._parse_meta_section()

    parser8 = _parser_with_tokens(
        [_t(TokenType.IDENTIFIER, "bad"), _t(TokenType.ASSIGN, "="), _t(TokenType.LBRACE, "{")]
    )
    with pytest.raises(ParserError, match="Invalid meta value"):
        parser8._parse_meta_section()

    parser9 = _parser_with_tokens([_t(TokenType.IDENTIFIER, "bad")])
    with pytest.raises(ParserError, match="Expected '=' after meta key"):
        parser9._parse_meta_section()

    parser10 = _parser_with_tokens([_t(TokenType.STRING, "not-a-key")])
    assert parser10._parse_meta_section() == []


def test_parse_rule_preserves_duplicate_meta_entries() -> None:
    ast = Parser().parse("rule duplicated_meta { meta: a = 1 a = 2 condition: true }")
    generated = CodeGenerator().generate(ast)

    assert [(entry.key, entry.value) for entry in ast.rules[0].meta] == [("a", 1), ("a", 2)]
    assert "a = 1" in generated
    assert "a = 2" in generated


def test_parse_rule_and_sections_error_paths() -> None:
    with pytest.raises(ParserError, match="Expected 'rule' keyword"):
        _parser_with_tokens([_t(TokenType.IDENTIFIER, "x")])._parse_rule_name()

    with pytest.raises(ParserError, match="Expected rule name"):
        _parser_with_tokens([_t(TokenType.RULE, "rule")])._parse_rule_name()

    with pytest.raises(ParserError, match="Expected '\\{' after rule name"):
        Parser("rule r")._parse_rule()

    with pytest.raises(ParserError, match="Expected '\\}' at end of rule"):
        Parser("rule r { condition: true ")._parse_rule()

    for parser in (Parser(), CommentAwareParser()):
        with pytest.raises(ParserError, match="Expected tag name after ':'"):
            parser.parse("rule empty_tags : { condition: true }")
        with pytest.raises(ParserError, match="duplicated tag identifier"):
            parser.parse("rule duplicated_tags : tag tag { condition: true }")

    parser = Parser("rule r { junk: true }")
    parser.current = 3  # position on junk
    with pytest.raises(ParserError, match="Unexpected section: junk"):
        parser._parse_rule_sections()

    parser2 = _parser_with_tokens([_t(TokenType.IDENTIFIER, "x")])
    assert parser2._parse_rule_tags() == []

    parser3 = _parser_with_tokens([_t(TokenType.RBRACE, "}")])
    meta, strings, condition = parser3._parse_rule_sections()
    assert meta == {}
    assert strings == []
    assert condition is None


def test_parse_rule_rejects_invalid_section_order_and_missing_sections() -> None:
    invalid_sources = [
        "rule r { }",
        'rule r { strings: $a = "x" }',
        "rule r { strings: condition: true }",
        "rule r { meta: condition: true }",
        "rule r { condition: true condition: false }",
        'rule r { condition: true strings: $a = "x" }',
        "rule r { condition: true meta: x = 1 }",
        'rule r { strings: $a = "x" strings: $b = "y" condition: $a or $b }',
        "rule r { meta: x = 1 meta: y = 2 condition: true }",
        'rule r { strings: $a = "x" meta: x = 1 condition: $a }',
    ]

    for source in invalid_sources:
        for parser_factory in (Parser, CommentAwareParser):
            with pytest.raises(ParserError):
                parser_factory().parse(source)


def test_parse_rejects_duplicate_rule_identifiers() -> None:
    source = "rule dup { condition: true } rule dup { condition: false }"

    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match='duplicated identifier "dup"'):
            parser_factory().parse(source)


@pytest.mark.parametrize(
    "source",
    [
        "extern rule dup\nextern rule dup\nrule r { condition: true }",
        "extern rule dup\nrule dup { condition: true }",
        "rule dup { condition: true }\nextern rule dup",
    ],
)
def test_parse_rejects_conflicting_extern_rule_identifiers(source: str) -> None:
    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError, match='duplicated identifier "dup"'):
            parser_factory().parse(source)


def test_parse_import_include_and_rule_via_full_parse() -> None:
    ast = Parser(
        'import "pe" include "common.yar" private rule sample : t1 { meta: score = 1 strings: $a = "x" condition: true }'
    ).parse()
    assert ast.imports[0].module == "pe"
    assert ast.imports[0].alias is None
    assert ast.includes[0].path == "common.yar"
    assert ast.rules[0].name == "sample"
    assert [str(m) for m in ast.rules[0].modifiers] == ["private"]

    tokens = Lexer("rule only_condition { condition: true }").tokenize()
    parser = Parser("rule seed { condition: true }")
    parser.tokens = tokens
    parser.current = 0
    rule = parser._parse_rule()
    assert rule.name == "only_condition"


def test_parse_rejects_standard_import_alias() -> None:
    with pytest.raises(ParserError, match="Import aliases are not supported"):
        Parser('import "pe" as pe_mod rule r { condition: true }').parse()


@pytest.mark.parametrize(
    "source_template",
    [
        "rule {identifier} {{ condition: true }}",
        "rule r : {identifier} {{ condition: true }}",
        "rule r {{ meta: {identifier} = 1 condition: true }}",
        'import "pe" rule r {{ condition: pe.{identifier} == 1 }}',
    ],
)
def test_parse_rejects_identifiers_longer_than_libyara_limit(source_template: str) -> None:
    long_identifier = "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)

    with pytest.raises(LexerError, match="Identifier exceeds maximum length"):
        Parser(source_template.format(identifier=long_identifier)).parse()


@pytest.mark.parametrize(
    "source",
    [
        "rule café { condition: true }",
        "rule r : café { condition: true }",
        "rule r { meta: café = 1 condition: true }",
        'import "pe" rule r { condition: pe.café == 1 }',
        'rule r { strings: $café = "x" condition: $café }',
    ],
)
def test_parse_rejects_non_ascii_identifiers(source: str) -> None:
    with pytest.raises(LexerError, match="Unexpected character"):
        Parser(source).parse()


@pytest.mark.parametrize(
    "source",
    [
        "RULE r { condition: true }",
        "rule r { CONDITION: true }",
        'rule r { strings: $a = "x" WIDE condition: $a }',
    ],
)
def test_parse_rejects_uppercase_keywords(source: str) -> None:
    for parser_factory in (Parser, CommentAwareParser):
        with pytest.raises(ParserError):
            parser_factory().parse(source)


def test_parse_generated_extended_top_level_constructs() -> None:
    source = CodeGenerator().generate(
        YaraFile(
            extern_imports=[
                ExternImport(
                    "external.yar",
                    alias="ext",
                    rules=["ExternalRule", "legacy.LegacyRule"],
                )
            ],
            namespaces=[ExternNamespace("corp")],
            extern_rules=[
                ExternRule(
                    "ExternalRule",
                    modifiers=[RuleModifier.from_string("private")],
                    namespace="legacy",
                )
            ],
            rules=[Rule("uses_external", condition=BooleanLiteral(True))],
        )
    )

    ast = Parser(source).parse()
    comment_ast = CommentAwareParser().parse(source)

    for parsed in (ast, comment_ast):
        assert parsed.extern_imports[0].module_path == "external.yar"
        assert parsed.extern_imports[0].alias == "ext"
        assert parsed.extern_imports[0].rules == ["ExternalRule", "legacy.LegacyRule"]
        assert parsed.namespaces[0].name == "corp"
        assert parsed.extern_rules[0].name == "ExternalRule"
        assert parsed.extern_rules[0].namespace == "legacy"
        assert [str(modifier) for modifier in parsed.extern_rules[0].modifiers] == ["private"]
        assert parsed.rules[0].name == "uses_external"


def test_parse_generated_extern_rule_reference_conditions() -> None:
    source = CodeGenerator().generate(
        YaraFile(
            extern_rules=[ExternRule("ExternalRule", namespace="legacy")],
            rules=[
                Rule(
                    "uses_external",
                    condition=ExternRuleReference("ExternalRule", namespace="legacy"),
                )
            ],
        )
    )

    ast = Parser(source).parse()
    comment_ast = CommentAwareParser().parse(source)

    for parsed in (ast, comment_ast):
        condition = parsed.rules[0].condition

        assert isinstance(condition, ExternRuleReference)
        assert condition.rule_name == "ExternalRule"
        assert condition.namespace == "legacy"
        assert SemanticValidator().validate(parsed).errors == []


def test_parse_generated_nested_extern_rule_reference_conditions() -> None:
    source = CodeGenerator().generate(
        YaraFile(
            extern_rules=[ExternRule("ExternalRule", namespace="legacy.deep")],
            rules=[
                Rule(
                    "uses_nested_external",
                    condition=ExternRuleReference("ExternalRule", namespace="legacy.deep"),
                )
            ],
        )
    )

    ast = Parser(source).parse()
    comment_ast = CommentAwareParser().parse(source)

    for parsed in (ast, comment_ast):
        condition = parsed.rules[0].condition

        assert isinstance(condition, ExternRuleReference)
        assert condition.rule_name == "ExternalRule"
        assert condition.namespace == "legacy.deep"
        assert SemanticValidator().validate(parsed).errors == []


def test_parse_generated_aliased_nested_extern_import_references() -> None:
    source = CodeGenerator().generate(
        YaraFile(
            extern_imports=[
                ExternImport(
                    "external.yar",
                    alias="ext",
                    rules=["legacy.LegacyRule"],
                )
            ],
            rules=[
                Rule(
                    "uses_nested_alias",
                    condition=ExternRuleReference("LegacyRule", namespace="ext.legacy"),
                )
            ],
        )
    )

    ast = Parser(source).parse()
    comment_ast = CommentAwareParser().parse(source)

    for parsed in (ast, comment_ast):
        condition = parsed.rules[0].condition

        assert isinstance(condition, ExternRuleReference)
        assert condition.rule_name == "LegacyRule"
        assert condition.namespace == "ext.legacy"
        assert SemanticValidator().validate(parsed).errors == []


def test_parse_generated_file_pragmas() -> None:
    pragmas = [
        IncludeOncePragma(),
        DefineDirective("FEATURE", "1"),
        UndefDirective("OLD_FEATURE"),
        ConditionalDirective.ifdef("FEATURE"),
        ConditionalDirective.endif(),
        CustomPragma("optimize", ["on"]),
    ]
    source = CodeGenerator().generate(
        YaraFile(
            pragmas=pragmas,
            rules=[Rule("with_pragmas", condition=BooleanLiteral(True))],
        )
    )

    ast = Parser(source).parse()
    comment_ast = CommentAwareParser().parse(source)

    for parsed in (ast, comment_ast):
        assert [str(pragma) for pragma in parsed.pragmas] == [str(pragma) for pragma in pragmas]
        assert parsed.rules[0].name == "with_pragmas"


def test_parse_generated_namespace_extern_rules_stay_nested() -> None:
    source = CodeGenerator().generate(
        YaraFile(
            namespaces=[
                ExternNamespace(
                    "corp",
                    extern_rules=[ExternRule("Nested")],
                )
            ],
        )
    )

    ast = Parser(source).parse()
    comment_ast = CommentAwareParser().parse(source)

    for parsed in (ast, comment_ast):
        assert parsed.extern_rules == []
        assert parsed.namespaces[0].name == "corp"
        assert parsed.namespaces[0].extern_rules[0].name == "Nested"
        assert parsed.namespaces[0].extern_rules[0].namespace == "corp"


def test_parse_scoped_meta_entries() -> None:
    source = """
rule with_scoped_meta {
    meta:
        private:secret = "token"
        protected:classification = "restricted"
        owner = "team"
    condition:
        true
}
"""

    ast = Parser(source).parse()
    comment_ast = CommentAwareParser().parse(source)

    for parsed in (ast, comment_ast):
        meta = parsed.rules[0].meta

        assert [entry.key for entry in meta] == ["secret", "classification", "owner"]
        assert [entry.scope.value for entry in meta] == ["private", "protected", "public"]


def test_parse_generated_in_rule_pragmas() -> None:
    source = CodeGenerator().generate(
        YaraFile(
            rules=[
                Rule(
                    "with_rule_pragmas",
                    pragmas=[
                        InRulePragma(
                            DefineDirective("LIMIT", "10"),
                            position="before_condition",
                        )
                    ],
                    condition=BooleanLiteral(True),
                )
            ],
        )
    )

    assert "#define LIMIT 10" in source

    ast = Parser(source).parse()
    comment_ast = CommentAwareParser().parse(source)

    for parsed in (ast, comment_ast):
        pragmas = parsed.rules[0].pragmas

        assert len(pragmas) == 1
        assert isinstance(pragmas[0].pragma, DefineDirective)
        assert pragmas[0].pragma.macro_name == "LIMIT"
        assert pragmas[0].pragma.macro_value == "10"
        assert pragmas[0].position == "before_condition"
