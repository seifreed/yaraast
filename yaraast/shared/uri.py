"""File URI conversion helpers shared across package boundaries."""

from pathlib import Path
from urllib.parse import unquote, urlparse


def uri_to_path(uri: object) -> Path | None:
    if not isinstance(uri, str) or not uri.strip() or "\x00" in uri:
        return None
    if uri.lower().startswith("file:"):
        parsed = urlparse(uri)
        if parsed.netloc and parsed.netloc.lower() != "localhost":
            return None
        decoded = unquote(parsed.path)
        if not decoded or "\x00" in decoded:
            return None
        if not decoded.startswith("/") and not (
            len(decoded) >= 2 and decoded[0].isalpha() and decoded[1] == ":"
        ):
            return None
        if len(decoded) >= 3 and decoded[0] == "/" and decoded[2] == ":":
            decoded = decoded[1:]
        return Path(decoded)
    return None


def path_to_uri(path: Path) -> str:
    if not isinstance(path, Path):
        msg = "path must be a pathlib.Path"
        raise TypeError(msg)
    if "\x00" in str(path):
        msg = "path must not contain null bytes"
        raise ValueError(msg)
    return path.absolute().as_uri()
