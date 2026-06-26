# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-gap regression tests for three modules.

Targets
-------
* yaraast/builder/file_builder_validation.py  - lines 20-21, 35-36
* yaraast/cli/commands/lsp.py                 - line 47
* yaraast/lsp/server.py                       - line 22, branches 82->89, 89->exit

Each test exercises a real, executable code path:
  - TypeError guards in the validation helpers when non-string values are passed.
  - The TCP display branch in the LSP CLI command (line 47 of lsp.py fires before
    start_lsp_server is called, so the function under test fully executes that line).
  - The pygls v1 fallback import path in server.py (line 22) triggered by temporarily
    replacing the pygls.lsp.server sys.modules entry with a module that raises the
    correct ImportError.
  - The class-body compatibility-shim skip branches in server.py (lines 82->89 and
    89->exit) triggered by temporarily injecting the shim methods onto LanguageServer
    before re-importing the module under test.

No module under test is mocked.  Collaborator state (sys.modules, module attributes)
is restored in finally blocks so tests do not interfere with each other.
"""

from __future__ import annotations

import contextlib
import importlib
import sys
import types
from types import ModuleType

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

        def raise_immediately(server: object, tcp: int | None, host: str) -> None:
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

        def raise_immediately(server: object, tcp: int | None, host: str) -> None:
            raise RuntimeError("stop")

        monkeypatch.setattr(lsp_svc, "start_lsp_server", raise_immediately)

        runner = CliRunner()
        result = runner.invoke(lsp_command, ["--tcp", "8080", "--host", "192.168.1.1"])

        assert "192.168.1.1:8080" in result.output

    def test_stdio_path_does_not_show_tcp_display(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When --tcp is absent, line 47 is skipped; the stdio display fires instead."""
        import yaraast.cli.lsp_services as lsp_svc

        def raise_immediately(server: object, tcp: int | None, host: str) -> None:
            raise RuntimeError("stop")

        monkeypatch.setattr(lsp_svc, "start_lsp_server", raise_immediately)

        runner = CliRunner()
        result = runner.invoke(lsp_command, [])

        # stdio path does not print a port number; TCP display (line 47) was NOT taken
        assert ":5007" not in result.output
        assert ":8080" not in result.output
        # stdio listening message was shown instead
        assert "stdio" in result.output.lower() or "stop" in result.output


# ---------------------------------------------------------------------------
# Helpers for sys.modules / package attribute cleanup in server.py tests
# ---------------------------------------------------------------------------


def _restore_server_module(orig_server_mod: ModuleType | None) -> None:
    """Restore yaraast.lsp.server in sys.modules and as a package attribute.

    Python's import system binds ``yaraast.lsp.server`` as an attribute on the
    ``yaraast.lsp`` package when a re-import runs.  Simply updating
    ``sys.modules`` is not enough: a subsequent ``import yaraast.lsp.server``
    statement will return the package attribute, not the sys.modules value.
    This helper synchronises both locations after our tests replace the module.
    """
    import yaraast.lsp as lsp_pkg

    # Remove whatever our test put in sys.modules
    sys.modules.pop("yaraast.lsp.server", None)

    if orig_server_mod is not None:
        # Restore the pre-test module into both locations
        sys.modules["yaraast.lsp.server"] = orig_server_mod
        lsp_pkg.server = orig_server_mod
    else:
        # Module was absent before; re-import to leave a consistent state
        with contextlib.suppress(ImportError):
            restored = importlib.import_module("yaraast.lsp.server")
            lsp_pkg.server = restored


# ---------------------------------------------------------------------------
# yaraast/lsp/server.py - line 22  (pygls v1 import fallback)
# ---------------------------------------------------------------------------


class TestServerPyPyglsV1FallbackImport:
    """Cover server.py line 22: the except-branch that falls back to pygls<2.0 API.

    The module-level try/except block in server.py (lines 17-22) imports
    LanguageServer from pygls.lsp.server (v2).  If that import raises ImportError
    whose .name is in the recognised v2 sentinel set, line 22 executes the v1
    fallback import.

    To exercise line 22 without modifying source:
    1. Inject a fake module at sys.modules['pygls.lsp.server'] that raises
       ImportError(name='pygls.lsp.server') when LanguageServer is accessed.
    2. Inject the real LanguageServer onto pygls.server so the fallback succeeds.
    3. Remove yaraast.lsp.server from sys.modules and re-import it.
    4. Restore all sys.modules entries in the finally block.
    """

    def test_line_22_pygls_v1_fallback_is_reached(self) -> None:
        """Re-importing server.py after making pygls.lsp.server fail covers line 22."""
        from pygls.lsp.server import LanguageServer as RealLanguageServer
        import pygls.server as pygls_server_mod

        # Build a fake pygls.lsp.server module whose LanguageServer access raises
        # with the sentinel name that _is_missing_pygls_v2_server recognises.
        def _make_failing_module() -> types.ModuleType:
            return types.ModuleType("pygls.lsp.server")

        # Save originals
        orig_pygls_lsp_server = sys.modules.get("pygls.lsp.server")
        orig_server_mod = sys.modules.pop("yaraast.lsp.server", None)
        had_ls_on_pygls_server = hasattr(pygls_server_mod, "LanguageServer")

        # Arrange: fake v2 module + v1 fallback attribute
        sys.modules["pygls.lsp.server"] = _make_failing_module()
        pygls_server_mod.LanguageServer = RealLanguageServer  # type: ignore[attr-defined]

        try:
            import yaraast.lsp.server as reloaded

            # Assert: the fallback (line 22) provided the real LanguageServer
            assert reloaded.LanguageServer is RealLanguageServer  # type: ignore[attr-defined]
        finally:
            # Restore pygls.lsp.server entry
            if orig_pygls_lsp_server is not None:
                sys.modules["pygls.lsp.server"] = orig_pygls_lsp_server
            else:
                with contextlib.suppress(KeyError):
                    del sys.modules["pygls.lsp.server"]
            # Restore LanguageServer attribute on pygls.server if we added it
            if not had_ls_on_pygls_server:
                with contextlib.suppress(AttributeError):
                    del pygls_server_mod.LanguageServer  # type: ignore[attr-defined]
            # Restore yaraast.lsp.server consistently in sys.modules and as pkg attr
            _restore_server_module(orig_server_mod)


# ---------------------------------------------------------------------------
# yaraast/lsp/server.py - branches 82->89 and 89->exit
#   (class-body compatibility-shim conditional skip paths)
# ---------------------------------------------------------------------------


class TestServerPyShimSkipBranches:
    """Cover branches 82->89 and 89->exit in server.py.

    Lines 82 and 89 are class-body ``if not hasattr(LanguageServer, ...)`` guards
    that define shim methods only when the base class lacks them (pygls v2 env).
    Branch ``82->89`` fires when LanguageServer ALREADY has ``show_message_log``
    (False branch -> skip to line 89).  Branch ``89->exit`` fires when it ALREADY
    has ``publish_diagnostics`` (False branch -> exit class body).

    In the current environment (pygls v2) both conditions are True, so both shims
    ARE defined and both False branches are never taken.

    To cover those False branches:
    1. Add both methods directly to LanguageServer before re-importing server.py.
    2. Re-import yaraast.lsp.server (with it removed from sys.modules).
    3. Verify neither shim was injected into YaraLanguageServer's own ``__dict__``.
    4. Restore the patched LanguageServer and sys.modules in a finally block.
    """

    def test_shim_skip_branches_when_language_server_already_has_both_methods(
        self,
    ) -> None:
        """Both shim-skip branches are taken when LanguageServer already has the methods."""
        from pygls.lsp.server import LanguageServer

        orig_server_mod = sys.modules.pop("yaraast.lsp.server", None)
        had_show = hasattr(LanguageServer, "show_message_log")
        had_publish = hasattr(LanguageServer, "publish_diagnostics")

        # Arrange: inject both shim methods onto the base class
        LanguageServer.show_message_log = (  # type: ignore[attr-defined]
            lambda self, msg, _=None: None
        )
        LanguageServer.publish_diagnostics = (  # type: ignore[attr-defined]
            lambda self, uri, diags=None: None
        )

        try:
            import yaraast.lsp.server as reloaded

            # Assert: YaraLanguageServer did NOT inject its own shim copies
            # (both 'if not hasattr' conditions were False -> both branches skipped)
            assert "show_message_log" not in reloaded.YaraLanguageServer.__dict__, (
                "show_message_log shim should NOT be in YaraLanguageServer.__dict__ "
                "when LanguageServer already has the method (branch 82->89 must fire)"
            )
            assert "publish_diagnostics" not in reloaded.YaraLanguageServer.__dict__, (
                "publish_diagnostics shim should NOT be in YaraLanguageServer.__dict__ "
                "when LanguageServer already has the method (branch 89->exit must fire)"
            )
            # The methods are still accessible via inheritance from LanguageServer
            assert hasattr(reloaded.YaraLanguageServer, "show_message_log")
            assert hasattr(reloaded.YaraLanguageServer, "publish_diagnostics")
        finally:
            if not had_show:
                with contextlib.suppress(AttributeError):
                    del LanguageServer.show_message_log  # type: ignore[attr-defined]
            if not had_publish:
                with contextlib.suppress(AttributeError):
                    del LanguageServer.publish_diagnostics  # type: ignore[attr-defined]
            _restore_server_module(orig_server_mod)

    def test_shim_skip_branch_show_message_log_only(self) -> None:
        """Only branch 82->89 fires when LanguageServer already has show_message_log."""
        from pygls.lsp.server import LanguageServer

        orig_server_mod = sys.modules.pop("yaraast.lsp.server", None)
        had_show = hasattr(LanguageServer, "show_message_log")
        had_publish = hasattr(LanguageServer, "publish_diagnostics")

        LanguageServer.show_message_log = lambda self, msg, _=None: None  # type: ignore[attr-defined]
        # Do NOT add publish_diagnostics - so its shim IS added by YaraLanguageServer

        try:
            import yaraast.lsp.server as reloaded

            # show_message_log was on LanguageServer -> shim skipped (branch 82->89)
            assert "show_message_log" not in reloaded.YaraLanguageServer.__dict__
            # publish_diagnostics was absent -> shim defined (branch 89 taken)
            assert "publish_diagnostics" in reloaded.YaraLanguageServer.__dict__
        finally:
            if not had_show:
                with contextlib.suppress(AttributeError):
                    del LanguageServer.show_message_log  # type: ignore[attr-defined]
            if not had_publish:
                with contextlib.suppress(AttributeError):
                    del LanguageServer.publish_diagnostics  # type: ignore[attr-defined]
            _restore_server_module(orig_server_mod)

    def test_shim_skip_branch_publish_diagnostics_only(self) -> None:
        """Only branch 89->exit fires when LanguageServer already has publish_diagnostics."""
        from pygls.lsp.server import LanguageServer

        orig_server_mod = sys.modules.pop("yaraast.lsp.server", None)
        had_show = hasattr(LanguageServer, "show_message_log")
        had_publish = hasattr(LanguageServer, "publish_diagnostics")

        # Do NOT add show_message_log - so its shim IS added
        LanguageServer.publish_diagnostics = lambda self, uri, diags=None: None  # type: ignore[attr-defined]

        try:
            import yaraast.lsp.server as reloaded

            # show_message_log was absent -> shim defined (branch 82 taken)
            assert "show_message_log" in reloaded.YaraLanguageServer.__dict__
            # publish_diagnostics was on LanguageServer -> shim skipped (branch 89->exit)
            assert "publish_diagnostics" not in reloaded.YaraLanguageServer.__dict__
        finally:
            if not had_show:
                with contextlib.suppress(AttributeError):
                    del LanguageServer.show_message_log  # type: ignore[attr-defined]
            if not had_publish:
                with contextlib.suppress(AttributeError):
                    del LanguageServer.publish_diagnostics  # type: ignore[attr-defined]
            _restore_server_module(orig_server_mod)
