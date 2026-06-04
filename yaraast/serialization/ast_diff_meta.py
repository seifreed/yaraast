"""Meta diff helpers."""

from __future__ import annotations

from typing import Any

__all__ = ["emit_meta_diff", "meta_payloads"]

MetaEntryPayload = dict[str, Any]
MetaPayloadValue = MetaEntryPayload | list[MetaEntryPayload]


def _meta_entry_payload(item: Any, fallback_key: str) -> tuple[str, MetaEntryPayload]:
    scope = getattr(item, "scope", None)
    key = getattr(item, "key", fallback_key)
    entry = {"value": getattr(item, "value", item)}
    if scope is not None:
        entry["scope"] = getattr(scope, "value", str(scope))
    return key, entry


def _sort_duplicate_entries(entries: list[MetaEntryPayload]) -> list[MetaEntryPayload]:
    return sorted(
        entries,
        key=lambda entry: (
            repr(entry.get("value")),
            str(entry.get("scope", "")),
        ),
    )


def _meta_to_dict(meta: Any) -> dict[str, MetaPayloadValue]:
    """Convert meta (list[MetaEntry]) to a comparable dict."""
    payload: dict[str, MetaPayloadValue] = {}
    for i, item in enumerate(meta):
        key, entry = _meta_entry_payload(item, str(i))
        existing = payload.get(key)
        if existing is None:
            payload[key] = entry
        elif isinstance(existing, list):
            existing.append(entry)
        else:
            payload[key] = [existing, entry]
    for key, value in payload.items():
        if isinstance(value, list):
            payload[key] = _sort_duplicate_entries(value)
    return payload


def meta_payloads(
    old_rule: Any,
    new_rule: Any,
) -> tuple[dict[str, MetaPayloadValue], dict[str, MetaPayloadValue]]:
    """Return comparable meta payloads."""
    return _meta_to_dict(old_rule.meta), _meta_to_dict(new_rule.meta)


def emit_meta_diff(
    base_path: str,
    result: Any,
    diff_node: Any,
    diff_type: Any,
    old_meta: dict[str, MetaPayloadValue],
    new_meta: dict[str, MetaPayloadValue],
) -> None:
    """Record meta diff."""
    result.differences.append(
        diff_node(
            path=f"{base_path}/meta",
            diff_type=diff_type.MODIFIED,
            old_value=old_meta,
            new_value=new_meta,
            node_type="RuleMeta",
        ),
    )
