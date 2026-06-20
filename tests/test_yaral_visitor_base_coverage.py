"""Coverage for the YARA-L visitor base default dispatch.

Every ``visit_yaral_*`` method forwards to ``_default_visit`` via
``_visit_yaral_node``; subclasses override only what they need. Parametrizing
over every handler confirms the forward and covers the base.
"""

from __future__ import annotations

import pytest

from yaraast.yaral.visitor_base import YaraLVisitor

_VISIT_METHODS = sorted(name for name in dir(YaraLVisitor) if name.startswith("visit_yaral_"))


class _Collector(YaraLVisitor[str]):
    def _default_visit(self, node: object) -> str:
        return "default"


@pytest.mark.parametrize("method_name", _VISIT_METHODS)
def test_yaral_visit_methods_forward_to_default(method_name: str) -> None:
    assert getattr(_Collector(), method_name)(object()) == "default"
