"""Comment-aware code generator (thin shell over the unified CodeGenerator)."""

from __future__ import annotations

from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions


class CommentAwareCodeGenerator(CodeGenerator):
    """Generate YARA code with preserved comments.

    The behaviour lives in :class:`CodeGenerator`, selected by
    :meth:`GeneratorOptions.comment_aware`; this subclass only fixes the
    comment-preserving defaults.
    """

    def __init__(self, indent_size: int = 4, preserve_comments: bool = True) -> None:
        super().__init__(
            options=GeneratorOptions.comment_aware(
                indent_size=indent_size,
                preserve_comments=preserve_comments,
            )
        )
