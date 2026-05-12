"""Top-level feature registration helpers for the YARA language server."""

from __future__ import annotations

from yaraast.lsp.server_feature_document_handlers import register_document_handlers
from yaraast.lsp.server_feature_language_handlers import register_language_handlers
from yaraast.lsp.server_protocol import FeatureRegistrationServer


def register_server_features(server: FeatureRegistrationServer) -> None:
    """Register text-document and workspace features on the server."""
    register_document_handlers(server)
    register_language_handlers(server)
