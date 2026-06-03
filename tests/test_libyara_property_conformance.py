"""Property-based conformance: generated YARA always compiles under libyara.

The parse/generate round trip is exercised in test_parser_hypothesis; this adds
the faithfulness invariant that closes the loop -- for any rule libyara accepts,
``generate(parse(rule))`` must also be accepted by libyara, and regenerating it
must be byte-stable. Random rules are drawn from safe components so the inputs
are valid YARA; the property under test is our generator's fidelity, not the
engine's tolerance.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from yaraast.codegen import CodeGenerator
from yaraast.lexer.lexer_tables import KEYWORDS
from yaraast.parser.parser import Parser

yara = pytest.importorskip("yara")

_KEYWORDS = frozenset(KEYWORDS)


def _identifier() -> st.SearchStrategy[str]:
    return st.from_regex(r"[a-z_][a-z0-9_]{0,15}", fullmatch=True).filter(
        lambda name: name not in _KEYWORDS
    )


def _text_string() -> st.SearchStrategy[str]:
    # Printable ASCII plus high bytes as \xHH escapes (exercises the byte path).
    body = st.text(
        alphabet=st.sampled_from(
            "abcDEF0129 _-./:%@" + "".join(f"\\x{b:02x}" for b in (0xE9, 0x80))
        ),
        min_size=1,
        max_size=24,
    )
    return body


@st.composite
def _yara_rule(draw: st.DrawFn) -> str:
    name = draw(_identifier())
    string_ids = draw(st.lists(_identifier(), min_size=1, max_size=4, unique=True))
    string_lines = []
    for index, content in enumerate(
        draw(st.lists(_text_string(), min_size=len(string_ids), max_size=len(string_ids)))
    ):
        string_lines.append(f'        ${string_ids[index]} = "{content}"')
    refs = " or ".join(f"${sid}" for sid in string_ids)
    strings_block = "\n".join(string_lines)
    return f"rule rule_{name} {{\n    strings:\n{strings_block}\n    condition:\n        {refs}\n}}"


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(rule_text=_yara_rule())
def test_generated_rule_compiles_under_libyara(rule_text: str) -> None:
    try:
        yara.compile(source=rule_text)
    except yara.SyntaxError:
        # Only assert fidelity for inputs libyara itself accepts.
        return

    ast = Parser(rule_text).parse()
    generated = CodeGenerator().generate(ast)

    try:
        yara.compile(source=generated)
    except yara.SyntaxError as exc:
        pytest.fail(f"generated rule rejected by libyara:\n{generated}\n{exc}")

    # Regeneration must be byte-stable.
    regenerated = CodeGenerator().generate(Parser(generated).parse())
    assert regenerated == generated
