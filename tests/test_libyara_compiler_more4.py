from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.libyara.compiler import YARA_AVAILABLE, LibyaraCompiler, normalize_libyara_externals
from yaraast.libyara.direct_compiler import DirectASTCompiler
from yaraast.parser.source import parse_yara_source


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compilers_reject_non_mapping_externals() -> None:
    with pytest.raises(TypeError, match="libyara externals must be a dictionary"):
        LibyaraCompiler(externals=cast(Any, []))

    with pytest.raises(TypeError, match="libyara externals must be a dictionary"):
        DirectASTCompiler(externals=cast(Any, []))


@pytest.mark.parametrize("externals", [{cast(Any, 1): 1}, {cast(Any, True): 1}])
def test_libyara_externals_reject_non_string_names(externals: dict[Any, object]) -> None:
    with pytest.raises(TypeError, match="libyara external names must be strings"):
        normalize_libyara_externals(cast(Any, externals))


@pytest.mark.parametrize("externals", [{"": 1}, {"   ": 1}])
def test_libyara_externals_reject_empty_names(externals: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="libyara external names must not be empty"):
        normalize_libyara_externals(externals)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_compile_file_success_and_save(tmp_path: Path) -> None:
    compiler = LibyaraCompiler()

    rule_file = tmp_path / "ok.yar"
    rule_file.write_text(
        """
rule ok {
    condition:
        true
}
""".strip() + "\n",
        encoding="utf-8",
    )

    result = compiler.compile_file(rule_file)
    assert result.success is True
    assert result.compiled_rules is not None

    out_file = tmp_path / "ok.compiled"
    assert compiler.save_compiled_rules(result.compiled_rules, out_file) is True
    assert out_file.exists()
    assert out_file.stat().st_size > 0


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_compile_file_resolves_relative_includes(tmp_path: Path) -> None:
    compiler = LibyaraCompiler()

    include_file = tmp_path / "shared.yar"
    include_file.write_text(
        "rule shared_rule { condition: true }\n",
        encoding="utf-8",
    )
    rule_file = tmp_path / "main.yar"
    rule_file.write_text(
        """
include "shared.yar"

rule main_rule {
    condition:
        shared_rule
}
""".lstrip(),
        encoding="utf-8",
    )

    result = compiler.compile_file(rule_file)

    assert result.success is True
    assert result.compiled_rules is not None
    assert result.source_code == rule_file.read_text(encoding="utf-8")
    matches = result.compiled_rules.match(data=b"")
    assert [match.rule for match in matches] == ["shared_rule", "main_rule"]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_compile_source_uses_include_mapping() -> None:
    compiler = LibyaraCompiler()

    result = compiler.compile_source(
        """
include "shared.yar"

rule main_rule {
    condition:
        shared_rule
}
""".lstrip(),
        includes={"shared.yar": "rule shared_rule { condition: true }\n"},
    )

    assert result.success is True
    assert result.compiled_rules is not None
    assert [match.rule for match in result.compiled_rules.match(data=b"")] == [
        "shared_rule",
        "main_rule",
    ]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_compile_file_uses_include_mapping(tmp_path: Path) -> None:
    compiler = LibyaraCompiler()
    rule_file = tmp_path / "main.yar"
    rule_file.write_text(
        """
include "virtual.yar"

rule main_rule {
    condition:
        virtual_rule
}
""".lstrip(),
        encoding="utf-8",
    )

    result = compiler.compile_file(
        rule_file,
        includes={"virtual.yar": "rule virtual_rule { condition: true }\n"},
    )

    assert result.success is True
    assert result.compiled_rules is not None
    assert [match.rule for match in result.compiled_rules.match(data=b"")] == [
        "virtual_rule",
        "main_rule",
    ]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_compile_ast_codegen_failure_and_syntax_error() -> None:
    compiler = LibyaraCompiler()

    compile_ast_result = compiler.compile_ast(cast(Any, None))
    assert compile_ast_result.success is False
    assert compile_ast_result.errors
    assert compile_ast_result.errors[0].startswith("AST compilation error:")

    syntax_result = compiler.compile_source("rule bad { condition: }")
    assert syntax_result.success is False
    assert syntax_result.errors
    assert syntax_result.errors[0].startswith("Syntax error:")


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_compile_ast_success() -> None:
    compiler = LibyaraCompiler()
    ast = YaraFile(rules=[Rule(name="ok", condition=BooleanLiteral(value=True))])

    result = compiler.compile_ast(ast)

    assert result.success is True
    assert result.compiled_rules is not None


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_libyara_compiler_rejects_yarax_ast_before_codegen() -> None:
    compiler = LibyaraCompiler()
    ast = parse_yara_source("rule x { condition: with xs = [1]: match xs { _ => true } }")

    result = compiler.compile_ast(ast)

    assert result.success is False
    assert result.errors
    message = result.errors[0]
    assert "Cannot compile YARA-X-only syntax with libyara" in message
    assert "pattern matching" in message
    assert "with statements" in message
