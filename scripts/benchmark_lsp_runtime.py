#!/usr/bin/env python3
"""Benchmark the YARAAST LSP runtime on synthetic workspaces."""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from lsprotocol.types import Position

from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.hover import HoverProvider
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.runtime import LspRuntime, path_to_uri
from yaraast.lsp.symbols import SymbolsProvider


def _make_workspace(root: Path, file_count: int) -> list[Path]:
    files: list[Path] = []
    shared = root / "shared.yar"
    shared.write_text(
        'import "pe"\nrule shared_rule { strings: $a = "abc" condition: $a and pe.is_pe }\n',
        encoding="utf-8",
    )
    files.append(shared)
    for idx in range(file_count):
        path = root / f"rule_{idx}.yar"
        path.write_text(
            'include "shared.yar"\n'
            f"rule sample_{idx} {{\n"
            "  condition:\n"
            "    shared_rule\n"
            "}\n",
            encoding="utf-8",
        )
        files.append(path)
    return files


def _exercise(runtime: LspRuntime, user: Path) -> None:
    text = user.read_text(encoding="utf-8")
    uri = path_to_uri(user)
    runtime.open_document(uri, text)
    pos = Position(line=3, character=6)
    HoverProvider(runtime).get_hover(text, pos, uri)
    DefinitionProvider(runtime).get_definition(text, pos, uri)
    ReferencesProvider(runtime).get_references(text, pos, uri)
    SymbolsProvider(runtime).get_symbols(text, uri)
    DocumentLinksProvider(runtime).get_document_links(text, uri)
    runtime.workspace_symbols("shared")


def _make_single_document(rule_count: int) -> str:
    parts = ['import "pe"\n']
    for idx in range(rule_count):
        parts.append(
            f"rule sample_{idx} {{\n"
            "  strings:\n"
            f'    $a = "abc{idx}"\n'
            "  condition:\n"
            "    $a and pe.is_pe\n"
            "}\n"
        )
    return "\n".join(parts)


def run_benchmark(file_count: int, max_avg_ms: float) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        files = _make_workspace(root, file_count)
        runtime = LspRuntime()
        runtime.set_workspace_folders([str(root)])
        _exercise(runtime, files[-1])
        status = runtime.get_status()
        latency = status.get("latency", {})
        failures = {
            name: metric["avg_ms"]
            for name, metric in latency.items()
            if isinstance(metric, dict) and metric.get("avg_ms", 0.0) > max_avg_ms
        }
        return {
            "file_count": file_count,
            "threshold_ms": max_avg_ms,
            "status": status,
            "failures": failures,
            "ok": not failures,
        }


def run_single_document_benchmark(rule_count: int, max_avg_ms: float) -> dict[str, object]:
    runtime = LspRuntime()
    text = _make_single_document(rule_count)
    uri = "file:///benchmark/single.yar"
    runtime.open_document(uri, text)
    pos = Position(line=5, character=8)
    HoverProvider(runtime).get_hover(text, pos, uri)
    DefinitionProvider(runtime).get_definition(text, pos, uri)
    ReferencesProvider(runtime).get_references(text, pos, uri)
    SymbolsProvider(runtime).get_symbols(text, uri)
    DocumentLinksProvider(runtime).get_document_links(text, uri)
    status = runtime.get_status()
    latency = status.get("latency", {})
    failures = {
        name: metric["avg_ms"]
        for name, metric in latency.items()
        if isinstance(metric, dict) and metric.get("avg_ms", 0.0) > max_avg_ms
    }
    return {
        "rule_count": rule_count,
        "threshold_ms": max_avg_ms,
        "status": status,
        "failures": failures,
        "ok": not failures,
    }


def run_regression_suite() -> dict[str, object]:
    single_document = run_single_document_benchmark(rule_count=200, max_avg_ms=100.0)
    medium = run_benchmark(file_count=25, max_avg_ms=100.0)
    large = run_benchmark(file_count=100, max_avg_ms=150.0)
    return {
        "single_document": single_document,
        "medium": medium,
        "large": large,
        "ok": single_document["ok"] and medium["ok"] and large["ok"],
    }


def render_summary(payload: dict[str, object]) -> str:
    lines = [
        "# LSP Runtime Benchmark Summary",
        "",
        f"- generated_at: {datetime.now().isoformat(timespec='seconds')}",
        f"- ok: {payload.get('ok')}",
        "",
        "| scenario | ok | threshold | failures |",
        "| --- | --- | --- | --- |",
    ]
    for name in ("single_document", "medium", "large"):
        report = payload.get(name, {})
        threshold = report.get("threshold_ms", "n/a")
        failures = report.get("failures", {})
        lines.append(f"| {name} | {report.get('ok')} | {threshold} ms | {len(failures)} |")
    return "\n".join(lines) + "\n"


def render_history_index(history_dir: Path) -> str:
    rows = [
        "# LSP Runtime Benchmark History",
        "",
        "| file | scenario | ok | threshold | failures |",
        "| --- | --- | --- | --- | --- |",
    ]
    for json_path in sorted(history_dir.glob("lsp-runtime-*.json")):
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        for name in ("single_document", "medium", "large"):
            report = payload.get(name, {})
            rows.append(
                f"| {json_path.name} | {name} | {report.get('ok')} | "
                f"{report.get('threshold_ms', 'n/a')} ms | {len(report.get('failures', {}))} |"
            )
    return "\n".join(rows) + "\n"


def main() -> int:
    payload = run_regression_suite()
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    history_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    summary = render_summary(payload)
    print(rendered)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
        output_path.with_suffix(".md").write_text(summary, encoding="utf-8")
    if history_dir is not None:
        history_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        json_path = history_dir / f"lsp-runtime-{stamp}.json"
        md_path = history_dir / f"lsp-runtime-{stamp}.md"
        json_path.write_text(rendered + "\n", encoding="utf-8")
        md_path.write_text(summary, encoding="utf-8")
        (history_dir / "README.md").write_text(render_history_index(history_dir), encoding="utf-8")
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
