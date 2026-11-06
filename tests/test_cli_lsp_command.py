"""CLI tests for LSP command (no mocks)."""

from __future__ import annotations

import builtins
from collections.abc import Mapping
import importlib
import json
from pathlib import Path
import subprocess
import sys

import click
from click.testing import CliRunner, Result
import pytest

from yaraast.cli.commands.lsp import lsp


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


def test_lsp_stdio_startup_logs_lifecycle() -> None:
    try:
        importlib.import_module("yaraast.lsp.server")
    except ImportError as exc:
        from yaraast.lsp.optional_dependencies import is_missing_lsp_dependency

        if is_missing_lsp_dependency(exc):
            pytest.skip(
                "optional pygls and lsprotocol dependencies are unavailable; docs/test-skips.yml"
            )
        raise

    messages = (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
        {"jsonrpc": "2.0", "method": "initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": None},
        {"jsonrpc": "2.0", "method": "exit", "params": None},
    )
    wire_messages = b"".join(
        b"Content-Length: "
        + str(len(body := json.dumps(message).encode("utf-8"))).encode("ascii")
        + b"\r\n\r\n"
        + body
        for message in messages
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "yaraast",
            "--log-level",
            "INFO",
            "--log-format",
            "json",
            "lsp",
            "--stdio",
        ],
        cwd=Path(__file__).parents[1],
        input=wire_messages,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    responses = []
    output = result.stdout
    while output:
        header, output = output.split(b"\r\n\r\n", 1)
        content_length = int(
            next(
                line.split(b":", 1)[1]
                for line in header.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
        )
        responses.append(json.loads(output[:content_length]))
        output = output[content_length:]
    assert {response["id"] for response in responses if "id" in response} == {1, 2}, responses

    events = [
        json.loads(line)
        for line in result.stderr.decode("utf-8").splitlines()
        if line.startswith("{")
    ]
    assert [event["event_name"] for event in events] == [
        "cli.command.started",
        "cli.command.completed",
    ]
    assert all(event["operation"] == "lsp" for event in events)


def test_lsp_missing_dependency_abort_preserves_original_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__
    sentinel = ImportError("No module named pygls", name="pygls")

    def fail_lsp_services_import(
        name: str,
        globals_: Mapping[str, object] | None = None,
        locals_: Mapping[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "yaraast.cli.lsp_services":
            raise sentinel
        return original_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_lsp_services_import)

    result = CliRunner().invoke(lsp, [], standalone_mode=False)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert "Missing dependency" in result.stderr
    _assert_abort_preserves_cause(result, sentinel)


def test_lsp_start_error_abort_preserves_original_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = RuntimeError("lsp sentinel")

    def fail_create_lsp_server() -> object:
        raise sentinel

    monkeypatch.setattr("yaraast.lsp.server.create_server", fail_create_lsp_server)

    result = CliRunner().invoke(lsp, [], standalone_mode=False)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert "lsp sentinel" in result.stderr
    _assert_abort_preserves_cause(result, sentinel)
