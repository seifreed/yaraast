from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

class _Repeated:
    def add(self) -> Any: ...
    def append(self, value: Any) -> None: ...
    def __getitem__(self, index: int) -> Any: ...
    def __iter__(self) -> Iterator[Any]: ...
    def __len__(self) -> int: ...

class YaraFile:
    metadata: Any
    imports: _Repeated
    includes: _Repeated
    rules: _Repeated

    SerializeToString: Callable[[], bytes]
    ParseFromString: Callable[[bytes], int]

class Expression:
    identifier: Any
    string_identifier: Any
    string_count: Any
    integer_literal: Any
    double_literal: Any
    string_literal: Any
    boolean_literal: Any
    binary_expression: Any
    unary_expression: Any
