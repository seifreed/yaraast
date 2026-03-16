"""Additional tests for fluent CLI service helpers."""

from __future__ import annotations

from yaraast.cli import fluent_services as fs


def test_create_template_rule_supports_trojan_packed_and_generic_types() -> None:
    trojan_rule = fs.create_template_rule("trojan_demo", "trojan", "tester", ["tag1"])
    packed_rule = fs.create_template_rule("packed_demo", "packed", "tester", ["tag2"])
    generic_rule = fs.create_template_rule("generic_demo", "custom", "tester", ["tag3"])

    trojan_code = fs.generate_code(trojan_rule)
    packed_code = fs.generate_code(packed_rule)
    generic_code = fs.generate_code(generic_rule)

    assert "rule trojan_demo" in trojan_code
    assert "trojan" in trojan_code
    assert "tag1" in trojan_code

    assert "rule packed_demo" in packed_code
    assert "packed" in packed_code
    assert "tag2" in packed_code

    assert "rule generic_demo" in generic_code
    assert "custom" in generic_code
    assert "tag3" in generic_code
