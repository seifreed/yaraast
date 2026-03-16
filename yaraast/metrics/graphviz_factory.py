"""Small factory helpers for graphviz diagram construction."""

from __future__ import annotations

import graphviz


def create_digraph(comment: str, engine: str, **attrs: str) -> graphviz.Digraph:
    dot = graphviz.Digraph(comment=comment, engine=engine)
    if attrs:
        dot.attr(**attrs)
    return dot
