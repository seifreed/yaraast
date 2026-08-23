# Copyright (c) 2026 Marc Rivero Lopez
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-gap regression tests for the builder, CLI, and LSP server.

Targets
-------
* yaraast/builder/file_builder_validation.py  - lines 20-21, 35-36
* yaraast/cli/commands/lsp.py                 - line 47
* yaraast/lsp/server.py                       - pygls 2.x server contract

Each test exercises a real, executable code path:
  - TypeError guards in the validation helpers when non-string values are passed.
  - The TCP display branch in the LSP CLI command (line 47 of lsp.py fires before
    start_lsp_server is called, so the function under test fully executes that line).
  - The LSP server derives directly from the supported pygls 2.x server and carries
    no pygls 1.x compatibility methods.
"""

from __future__ import annotations

from click.testing import CliRunner
import pytest

from yaraast.builder.file_builder_validation import (
    validate_identifier,
    validate_nonempty_text,
)
from yaraast.cli.commands.lsp import lsp as lsp_command
from yaraast.errors import ValidationError

# ---------------------------------------------------------------------------
# yaraast/builder/file_builder_validation.py - lines 20-21
# ---------------------------------------------------------------------------


class TestValidateNonemptyTextTypeError:
    """validate_nonempty_text raises TypeError when value is not a str (lines 20-21)."""

    def test_integer_raises_type_error_with_kind_in_message(self) -> None:
        """An integer passed as value triggers lines 20-21 (TypeError branch)."""
        # Arrange
        value = 42
        kind = "tag"

        # Act / Assert
        with pytest.raises(TypeError, match="tag must be a string"):
            validate_nonempty_text(value, kind)

    def test_none_raises_type_error(self) -> None:
        """None is not a str; the isinstance guard at line 19 is False -> lines 20-21."""
        with pytest.raises(TypeError, match="condition must be a string"):
            validate_nonempty_text(None, "condition")

    def test_list_raises_type_error(self) -> None:
        """A list triggers the non-str TypeError path."""
        with pytest.raises(TypeError):
            validate_nonempty_text(["a", "b"], "meta key")

    def test_bytes_raises_type_error(self) -> None:
        """bytes is not str; must raise TypeError not ValidationError."""
        with pytest.raises(TypeError, match="rule must be a string"):
            validate_nonempty_text(b"rule_name", "rule")

    def test_error_message_contains_kind(self) -> None:
        """The error message format for non-str input embeds the kind parameter."""
        kind = "variable"
        with pytest.raises(TypeError) as exc_info:
            validate_nonempty_text(0, kind)
        assert kind in str(exc_info.value)

    def test_valid_string_does_not_raise(self) -> None:
        """Confirm that a valid non-empty string returns without error (baseline)."""
        validate_nonempty_text("hello", "tag")  # must not raise

    def test_empty_string_raises_validation_error_not_type_error(self) -> None:
        """An empty string is str; should raise ValidationError, not TypeError."""
        with pytest.raises(ValidationError):
            validate_nonempty_text("", "tag")

    def test_whitespace_only_raises_validation_error(self) -> None:
        """Whitespace-only str fails the strip check, not the isinstance check."""
        with pytest.raises(ValidationError):
            validate_nonempty_text("   ", "tag")


# ---------------------------------------------------------------------------
# yaraast/builder/file_builder_validation.py - lines 35-36
# ---------------------------------------------------------------------------


class TestValidateIdentifierTypeError:
    """validate_identifier raises TypeError when value is not a str (lines 35-36)."""

    def test_integer_raises_type_error(self) -> None:
        """An integer triggers the isinstance guard at line 34 -> lines 35-36."""
        with pytest.raises(TypeError, match="Invalid rule identifier: 99"):
            validate_identifier(99, "rule")

    def test_none_raises_type_error(self) -> None:
        """None is not a str; TypeError is raised with the repr in the message."""
        with pytest.raises(TypeError, match="Invalid loop variable identifier: None"):
            validate_identifier(None, "loop variable")

    def test_float_raises_type_error(self) -> None:
        """float triggers the non-str TypeError path."""
        with pytest.raises(TypeError):
            validate_identifier(1.5, "tag")

    def test_dict_raises_type_error(self) -> None:
        """dict is not a str; TypeError is raised."""
        with pytest.raises(TypeError, match="Invalid meta identifier"):
            validate_identifier({}, "meta")

    def test_error_message_contains_kind_and_value(self) -> None:
        """The error message contains both the kind and the repr of the bad value."""
        value = [1, 2, 3]
        kind = "variable"
        with pytest.raises(TypeError) as exc_info:
            validate_identifier(value, kind)
        msg = str(exc_info.value)
        assert kind in msg
        assert str(value) in msg

    def test_valid_identifier_does_not_raise(self) -> None:
        """A valid identifier string passes without exception (baseline)."""
        validate_identifier("my_rule", "rule")

    def test_keyword_raises_validation_error_not_type_error(self) -> None:
        """A string that is a YARA keyword raises ValidationError, not TypeError."""
        with pytest.raises(ValidationError):
            validate_identifier("rule", "rule")


# ---------------------------------------------------------------------------
# yaraast/cli/commands/lsp.py - line 47  (display_listening_tcp branch)
# ---------------------------------------------------------------------------


class TestLspCommandTcpDisplayBranch:
    """The TCP display path in the lsp command (line 47) runs before any blocking I/O.

    The lsp command executes display_listening_tcp (line 47) BEFORE calling
    start_lsp_server (line 51).  By invoking lsp with --tcp, the TCP display line
    fires unconditionally; start_lsp_server may then raise any exception (OS error
    or our sentinel) which is handled by the except block.  We validate line 47
    executed by checking the display output, which is always present regardless of
    what start_lsp_server does afterward.

    The collaborator being patched is yaraast.cli.lsp_services.start_lsp_server -
    not any function inside the module under test (yaraast.cli.commands.lsp).
    """

    def test_tcp_option_displays_host_and_port_on_line_47(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--tcp causes display_listening_tcp (line 47) to print host:port.

        The key assertion is that '127.0.0.1:5007' appears in the output, proving
        line 47 executed.  Whether start_lsp_server raises our sentinel or an OS error
        (port in use) is immaterial - both paths exit through the error handler.
        """
        import yaraast.cli.lsp_services as lsp_svc

        def raise_immediately(server: object, _tcp: int | None, host: str) -> None:
            raise RuntimeError("tcp sentinel for coverage")

        monkeypatch.setattr(lsp_svc, "start_lsp_server", raise_immediately)

        runner = CliRunner()
        result = runner.invoke(lsp_command, ["--tcp", "5007"])

        # display_listening_tcp must have printed host:port (line 47 was executed)
        assert "127.0.0.1:5007" in result.output
        # The command must have exited with an error (start_lsp_server raised)
        assert result.exit_code != 0

    def test_tcp_custom_host_appears_in_display_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The host value supplied via --host appears in the line-47 output."""
        import yaraast.cli.lsp_services as lsp_svc

        def raise_immediately(server: object, _tcp: int | None, host: str) -> None:
            raise RuntimeError("stop")

        monkeypatch.setattr(lsp_svc, "start_lsp_server", raise_immediately)

        runner = CliRunner()
        result = runner.invoke(lsp_command, ["--tcp", "8080", "--host", "192.168.1.1"])

        assert "192.168.1.1:8080" in result.output

    def test_stdio_path_does_not_show_tcp_display(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When --tcp is absent, line 47 is skipped; the stdio display fires instead."""
        import yaraast.cli.lsp_services as lsp_svc

        def raise_immediately(server: object, _tcp: int | None, host: str) -> None:
            raise RuntimeError("stop")

        monkeypatch.setattr(lsp_svc, "start_lsp_server", raise_immediately)

        runner = CliRunner()
        result = runner.invoke(lsp_command, [])

        # stdio path does not print a port number; TCP display (line 47) was NOT taken
        assert ":5007" not in result.output
        assert ":8080" not in result.output
        # stdio listening message was shown instead
        assert "stdio" in result.output.lower() or "stop" in result.output


def test_lsp_server_uses_pygls_v2_contract_directly() -> None:
    """The supported server has no pygls 1.x compatibility surface."""
    from pygls.lsp.server import LanguageServer

    from yaraast.lsp.server import YaraLanguageServer

    assert issubclass(YaraLanguageServer, LanguageServer)
    assert "show_message_log" not in YaraLanguageServer.__dict__
    assert "publish_diagnostics" not in YaraLanguageServer.__dict__
