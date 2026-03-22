from __future__ import annotations

import io
import mmap
from pathlib import Path

from yaraast.performance.streaming_parser import StreamingParser


def test_streaming_parser_bytes_stream_remaining_buffer_and_reset(tmp_path: Path) -> None:
    parser = StreamingParser(buffer_size=8)

    raw = b"rule r1 {\n condition:\n true\n}"  # no trailing newline
    rules = list(parser.parse_stream(io.BytesIO(raw)))
    assert len(rules) == 1

    parser.reset_statistics()
    stats = parser.get_statistics()
    assert stats["rules_parsed"] == 0
    assert stats["bytes_processed"] == 0
    assert stats["parse_errors"] == 0
    assert stats["files_processed"] == 0
    assert stats["files_successful"] == 0
    assert stats["total_parse_time"] == 0

    # parse_rules_from_file exception path
    missing = tmp_path / "missing.yar"
    results = list(parser.parse_rules_from_file(missing))
    assert len(results) == 1
    assert results[0].status.name == "ERROR"


def test_streaming_parser_progress_cancel_and_memory_paths(tmp_path: Path) -> None:
    p1 = tmp_path / "a.yar"
    p2 = tmp_path / "b.yar"
    p1.write_text("rule a { condition: true }", encoding="utf-8")
    p2.write_text("rule b { condition: true }", encoding="utf-8")

    progress_calls: list[tuple[int, int, str]] = []
    parser = StreamingParser(
        progress_callback=lambda i, total, path: progress_calls.append((i, total, path))
    )
    rows = list(parser.parse_files([p1, p2]))
    assert len(rows) == 2
    assert progress_calls

    # cancel path for parse_files
    parser2 = StreamingParser()
    parser2.cancel()
    assert list(parser2.parse_files([p1, p2])) == []

    # _memory_limit_exceeded true path with 0MB threshold (current RSS > 0)
    parser3 = StreamingParser(max_memory_mb=0)
    assert parser3._memory_limit_exceeded() is True
    parser3._maybe_collect_garbage()


def test_streaming_parser_mmap_import_include_and_token_branches(tmp_path: Path) -> None:
    code = """
import "pe"
include "common.yar"
private rule r1 {
  condition:
    true
}
global rule r2 : t1 t2 {
  strings:
    $a = "x"
  condition:
    $a
}
"""
    f = tmp_path / "mm.yar"
    f.write_text(code.strip() + "\n", encoding="utf-8")

    parser = StreamingParser()
    rules = list(parser.parse_file(f))
    assert len(rules) == 2
    assert [r.name for r in rules] == ["r1", "r2"]


def test_streaming_parser_chunk_residual_callbacks_and_cancellation(tmp_path: Path) -> None:
    text = """
rule a {
  condition:
    true
}

rule b {
  condition:
    true
}

rule c {
  condition:
    true
}"""
    path = tmp_path / "three.yar"
    path.write_text(text, encoding="utf-8")

    parser = StreamingParser(buffer_size=7)
    chunks = list(parser.parse_file_chunked(path, chunk_size=2))
    assert [len(chunk) for chunk in chunks] == [2, 1]

    callback_names: list[str] = []
    stream_rules = list(
        parser.parse_stream(
            io.StringIO(text), callback=lambda rule: callback_names.append(rule.name)
        )
    )
    assert [r.name for r in stream_rules] == ["a", "b", "c"]
    assert callback_names == ["a", "b", "c"]

    parser2 = StreamingParser()
    parser2.cancel()
    assert list(parser2.parse_rules_from_file(path)) == []


def test_streaming_parser_parse_files_error_memory_except_and_rule_text_failures(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "nope.yar"
    parser = StreamingParser()
    results = list(parser.parse_files([missing]))
    assert len(results) == 1
    assert results[0].status.name == "ERROR"

    parser_bad_mem = StreamingParser(max_memory_mb="bad")  # type: ignore[arg-type]
    assert parser_bad_mem._memory_limit_exceeded() is False

    assert parser._parse_rule_text('import "pe"') is None


def test_streaming_parser_parse_stream_invalid_tail_and_mmap_invalid_forms(tmp_path: Path) -> None:
    parser = StreamingParser(buffer_size=8)
    invalid_tail = "rule tail {\n  condition:\n    true"
    assert list(parser.parse_stream(io.StringIO(invalid_tail))) == []
    assert parser.get_statistics()["parse_errors"] >= 1

    invalid_cases = [
        "private\n",
        "rule { condition: true }\n",
        "rule missing_name\n",
        'import "pe"\n',
        "import\n",
        "rule tagged : tag\n",
    ]
    for idx, content in enumerate(invalid_cases):
        path = tmp_path / f"invalid_{idx}.yar"
        path.write_text(content, encoding="utf-8")
        with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            assert list(parser._parse_mmap(mm)) == []


def test_streaming_parser_parse_rules_from_file_success_progress_recursive_and_estimate(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)

    file1 = root / "one.yar"
    file2 = nested / "two.yar"
    file1.write_text("rule one { condition: true }", encoding="utf-8")
    file2.write_text("rule two { condition: true }", encoding="utf-8")

    parser = StreamingParser(buffer_size=4)
    results = list(parser.parse_rules_from_file(file1))
    assert len(results) == 1
    assert results[0].status.name == "SUCCESS"
    assert results[0].rule_name == "one"
    assert results[0].rule_count == 1
    assert results[0].ast is not None

    progress_calls: list[tuple[int, int]] = []
    rules = parser.parse_with_progress(
        file1,
        lambda processed, total: progress_calls.append((processed, total)),
    )
    assert [rule.name for rule in rules] == ["one"]
    assert progress_calls

    recursive_results = list(parser.parse_directory(root, recursive=True))
    assert len(recursive_results) == 2
    assert {r.rule_name for r in recursive_results} == {"one", "two"}

    estimate = parser.estimate_memory_usage(file1)
    assert estimate["file_size_mb"] >= 0
    assert estimate["estimated_ast_mb"] >= estimate["file_size_mb"]
    assert estimate["estimated_peak_mb"] >= estimate["estimated_ast_mb"]


def test_streaming_parser_mmap_nested_brace_callback_and_invalid_parse_object(
    tmp_path: Path,
) -> None:
    nested_brace = "rule weird { condition: { true } }"
    path = tmp_path / "nested_brace.yar"
    path.write_text(nested_brace, encoding="utf-8")

    parser = StreamingParser()
    with path.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert list(parser._parse_mmap(mm, callback=lambda rule: None)) == []
        assert parser.get_statistics()["parse_errors"] >= 1
