"""String analysis services for metrics CLI (logic without IO)."""

from __future__ import annotations

from typing import Any


def _analyze_string_patterns(ast: Any) -> dict[str, Any]:
    """Analyze string patterns in AST and return analysis data."""
    analysis = _initialize_string_analysis()
    lengths: list[int] = []

    for rule in ast.rules:
        if rule.strings:
            rule_info = _analyze_rule_strings(rule, analysis, lengths)
            analysis["rules"][rule.name] = rule_info

    _calculate_length_statistics(analysis, lengths)
    return analysis


def _initialize_string_analysis() -> dict[str, Any]:
    """Initialize analysis data structure."""
    return {
        "total_strings": 0,
        "type_distribution": {"plain": 0, "hex": 0, "regex": 0},
        "length_stats": {"min": float("inf"), "max": 0, "avg": 0},
        "rules": {},
        "modifiers": {},
        "patterns": {"short_strings": 0, "hex_patterns": 0},
    }


def _analyze_rule_strings(
    rule: Any, analysis: dict[str, Any], lengths: list[int]
) -> dict[str, Any]:
    """Analyze strings in a single rule."""
    rule_info = {
        "string_count": len(rule.strings),
        "types": [],
        "identifiers": [],
    }

    for string_def in rule.strings:
        analysis["total_strings"] += 1
        rule_info["identifiers"].append(string_def.identifier)

        if hasattr(string_def, "value"):  # Plain string
            _process_plain_string(string_def, analysis, rule_info, lengths)
        elif hasattr(string_def, "tokens"):  # Hex string
            _process_hex_string(string_def, analysis, rule_info)
        elif hasattr(string_def, "regex"):  # Regex string
            _process_regex_string(string_def, analysis, rule_info)

    return rule_info


def _process_plain_string(
    string_def: Any, analysis: dict[str, Any], rule_info: dict[str, Any], lengths: list[int]
) -> None:
    """Process a plain string definition."""
    analysis["type_distribution"]["plain"] += 1
    rule_info["types"].append("plain")

    str_len = len(string_def.value)
    lengths.append(str_len)

    if str_len < 4:
        analysis["patterns"]["short_strings"] += 1

    # Count modifiers
    if hasattr(string_def, "modifiers"):
        for mod in string_def.modifiers:
            mod_name = mod.name if hasattr(mod, "name") else str(mod)
            analysis["modifiers"][mod_name] = analysis["modifiers"].get(mod_name, 0) + 1


def _process_hex_string(
    _string_def: Any, analysis: dict[str, Any], rule_info: dict[str, Any]
) -> None:
    """Process a hex string definition."""
    analysis["type_distribution"]["hex"] += 1
    rule_info["types"].append("hex")
    analysis["patterns"]["hex_patterns"] += 1


def _process_regex_string(
    _string_def: Any, analysis: dict[str, Any], rule_info: dict[str, Any]
) -> None:
    """Process a regex string definition."""
    analysis["type_distribution"]["regex"] += 1
    rule_info["types"].append("regex")


def _calculate_length_statistics(analysis: dict[str, Any], lengths: list[int]) -> None:
    """Calculate string length statistics."""
    if lengths:
        analysis["length_stats"]["min"] = min(lengths)
        analysis["length_stats"]["max"] = max(lengths)
        analysis["length_stats"]["avg"] = sum(lengths) / len(lengths)
    else:
        analysis["length_stats"]["min"] = 0
        analysis["length_stats"]["max"] = 0
        analysis["length_stats"]["avg"] = 0
