from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.libyara.compiler import YARA_AVAILABLE, LibyaraCompiler


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
""".strip()
        + "\n",
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
def test_libyara_compiler_compile_ast_codegen_failure_and_syntax_error() -> None:
    compiler = LibyaraCompiler()

    compile_ast_result = compiler.compile_ast(None)  # type: ignore[arg-type]
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
