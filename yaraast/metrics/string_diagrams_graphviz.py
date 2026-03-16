"""Graphviz construction helpers for string diagram graphs."""

from __future__ import annotations

import graphviz

from yaraast.metrics.graphviz_factory import create_digraph


def create_pattern_flow_graph() -> graphviz.Digraph:
    dot = create_digraph("YARA String Pattern Flow", "dot")
    dot.attr(rankdir="TB", bgcolor="white", fontname="Arial", fontsize="12")
    dot.attr("node", fontname="Arial", fontsize="10")
    dot.attr("edge", fontname="Arial", fontsize="9")
    return dot


def create_complexity_graph() -> graphviz.Digraph:
    dot = create_digraph("YARA Pattern Complexity", "neato")
    dot.attr(bgcolor="white", fontname="Arial", overlap="false", splines="true")
    return dot


def create_similarity_graph() -> graphviz.Digraph:
    dot = create_digraph("YARA Pattern Similarity", "fdp")
    dot.attr(bgcolor="white", fontname="Arial", overlap="scale", sep="+20")
    return dot


def create_hex_graph() -> graphviz.Digraph:
    dot = create_digraph("YARA Hex Pattern Analysis", "dot")
    dot.attr(rankdir="LR", bgcolor="white", fontname="Arial")
    return dot
