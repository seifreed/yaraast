# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for DependencyGraph._compact_unique_rule_occurrence.

A redundant ``node is None or node.type != "rule"`` re-check was removed: the
``old_key`` is taken from ``_rule_node_keys_for_name``, which only yields keys
that are present in ``self.nodes`` with ``type == "rule"``, so the node can
never be missing or a non-rule at that point.
"""

from __future__ import annotations

from yaraast.resolution.dependency_graph import DependencyGraph, DependencyNode


def test_compact_renames_unique_indexed_occurrence_to_bare_key() -> None:
    graph = DependencyGraph()
    graph.nodes["rule:foo#1"] = DependencyNode(name="foo", type="rule")

    graph._compact_unique_rule_occurrence("foo")

    assert "rule:foo" in graph.nodes
    assert "rule:foo#1" not in graph.nodes
    assert graph.nodes["rule:foo"].name == "foo"
    assert graph.nodes["rule:foo"].type == "rule"


def test_compact_updates_dependency_references() -> None:
    graph = DependencyGraph()
    graph.nodes["rule:foo#1"] = DependencyNode(name="foo", type="rule")
    dependent = DependencyNode(name="bar", type="rule")
    dependent.dependencies.add("rule:foo#1")
    graph.nodes["rule:bar"] = dependent

    graph._compact_unique_rule_occurrence("foo")

    assert "rule:foo" in graph.nodes
    assert "rule:foo#1" not in graph.nodes["rule:bar"].dependencies
    assert "rule:foo" in graph.nodes["rule:bar"].dependencies


def test_compact_noop_when_bare_key_already_present() -> None:
    graph = DependencyGraph()
    graph.nodes["rule:foo"] = DependencyNode(name="foo", type="rule")
    graph.nodes["rule:foo#1"] = DependencyNode(name="foo", type="rule")

    graph._compact_unique_rule_occurrence("foo")

    # Bare key already existed, so nothing is renamed.
    assert "rule:foo#1" in graph.nodes


def test_compact_noop_when_multiple_occurrences() -> None:
    graph = DependencyGraph()
    graph.nodes["rule:foo#1"] = DependencyNode(name="foo", type="rule")
    graph.nodes["rule:foo#2"] = DependencyNode(name="foo", type="rule")

    graph._compact_unique_rule_occurrence("foo")

    # Two occurrences, so no compaction happens.
    assert "rule:foo" not in graph.nodes
    assert "rule:foo#1" in graph.nodes
    assert "rule:foo#2" in graph.nodes
