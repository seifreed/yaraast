"""Options for the unified YARA code generator.

A single ``CodeGenerator`` is driven by these options instead of a class
hierarchy. The simple knobs (indent, comments, section spacing) select between
the plain and comment-aware behaviours; ``pretty`` and ``advanced`` carry the
richer formatting engines' configuration when those layouts are requested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.codegen.formatting import FormattingConfig
    from yaraast.codegen.pretty_printer import PrettyPrintOptions


@dataclass
class GeneratorOptions:
    """Behaviour selection for :class:`CodeGenerator`.

    - ``preserve_comments`` emits leading/trailing comments (comment-aware mode).
    - ``blank_line_between_sections`` inserts a blank line after the meta and
      strings sections (the plain layout does; the comment-aware layout does not).
    - ``pretty`` / ``advanced`` request the richer layout engines; when set they
      take precedence over the plain/comment-aware knobs.
    """

    indent_size: int = 4
    preserve_comments: bool = False
    blank_line_between_sections: bool = True
    pretty: PrettyPrintOptions | None = None
    advanced: FormattingConfig | None = None

    @classmethod
    def comment_aware(
        cls, *, indent_size: int = 4, preserve_comments: bool = True
    ) -> GeneratorOptions:
        """Options reproducing the former CommentAwareCodeGenerator behaviour."""
        return cls(
            indent_size=indent_size,
            preserve_comments=preserve_comments,
            blank_line_between_sections=False,
        )
