"""YARA-X syntax adapter for converting between YARA and YARA-X syntax."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, cast

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.expressions import Expression
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexJump, HexString, PlainString, RegexString, StringDefinition
from yaraast.visitor import ASTTransformer
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.string_lengths import plain_string_byte_length

if TYPE_CHECKING:
    from yaraast.ast.pragmas import InRulePragma
    from yaraast.yarax.compatibility_checker import CompatibilityIssue

_ASTNodeT = TypeVar("_ASTNodeT", bound=ASTNode)


class YaraXSyntaxAdapter(ASTTransformer):
    """Adapt YARA rules to YARA-X syntax."""

    def __init__(
        self,
        features: YaraXFeatures | None = None,
        target: str = "yarax",
    ) -> None:
        """Initialize adapter.

        Args:
            features: Feature configuration
            target: Target format ("yarax" or "yara")

        """
        self.features = features or YaraXFeatures.yarax_strict()
        self.target = target
        self.adaptations_count = 0

    def _copy_node_metadata(self, source: ASTNode, target: _ASTNodeT) -> _ASTNodeT:
        target.location = source.location
        target.leading_comments = list(source.leading_comments)
        target.trailing_comment = source.trailing_comment
        return target

    def adapt(self, yara_file: YaraFile) -> tuple[YaraFile, int]:
        """Adapt YARA file syntax and return adapted file with adaptation count."""
        self.adaptations_count = 0
        adapted = cast(YaraFile, self.visit(yara_file))
        return adapted, self.adaptations_count

    def adapt_with_count(self, yara_file: YaraFile) -> tuple[YaraFile, int]:
        """Adapt YARA file syntax and return adapted file with adaptation count."""
        self.adaptations_count = 0
        adapted = cast(YaraFile, self.visit(yara_file))
        return adapted, self.adaptations_count

    def visit_rule(self, node: Rule) -> Rule:
        """Adapt rule syntax."""
        # Remove duplicate modifiers if targeting YARA-X
        if self.target == "yarax" and self.features.disallow_duplicate_modifiers:
            modifiers = list(dict.fromkeys(node.modifiers))  # Remove duplicates
            if len(modifiers) != len(node.modifiers):
                self.adaptations_count += 1
        else:
            modifiers = node.modifiers

        # Visit components
        meta = [self.visit(m) for m in node.meta]
        strings = [cast(StringDefinition, self.visit(s)) for s in node.strings]
        pragmas = [cast("InRulePragma", self.visit(pragma)) for pragma in node.pragmas]
        condition = (
            cast(Expression, self.visit(node.condition)) if node.condition is not None else None
        )

        return self._copy_node_metadata(
            node,
            Rule(
                name=node.name,
                modifiers=modifiers,
                tags=node.tags,
                meta=meta,
                strings=strings,
                condition=condition,
                pragmas=pragmas,
            ),
        )

    def visit_plain_string(self, node: PlainString) -> PlainString:
        """Adapt plain string syntax."""
        modifiers = list(node.modifiers)

        # Check base64 length for YARA-X
        if self.target == "yarax":
            has_base64 = any(
                self._modifier_name(modifier) in ("base64", "base64wide") for modifier in modifiers
            )
            byte_length = plain_string_byte_length(node.value)
            if has_base64 and byte_length < self.features.minimum_base64_length:
                # Pad the string to minimum length
                # Pad with null bytes (\x00) to preserve semantic neutrality
                # Using 'A' would change the base64-decoded result
                padding_needed = self.features.minimum_base64_length - byte_length
                if isinstance(node.value, bytes):
                    new_value: str | bytes = node.value + (b"\x00" * padding_needed)
                else:
                    new_value = node.value + ("\x00" * padding_needed)
                self.adaptations_count += 1
                return self._copy_node_metadata(
                    node,
                    PlainString(
                        identifier=node.identifier,
                        value=new_value,
                        modifiers=modifiers,
                        is_anonymous=node.is_anonymous,
                    ),
                )

        return node

    def _modifier_name(self, modifier: object) -> str:
        return str(getattr(modifier, "name", modifier))

    def visit_regex_string(self, node: RegexString) -> RegexString:
        """Adapt regex string syntax."""
        if self.target == "yarax" and self.features.strict_regex_escaping:
            # Escape unescaped braces
            adapted_regex = self._escape_braces(node.regex)
            if adapted_regex != node.regex:
                self.adaptations_count += 1
                return self._copy_node_metadata(
                    node,
                    RegexString(
                        identifier=node.identifier,
                        regex=adapted_regex,
                        modifiers=node.modifiers,
                        is_anonymous=node.is_anonymous,
                    ),
                )

        elif self.target == "yara" and not self.features.strict_regex_escaping:
            # Unescape braces for YARA compatibility
            adapted_regex = self._unescape_braces(node.regex)
            if adapted_regex != node.regex:
                self.adaptations_count += 1
                return self._copy_node_metadata(
                    node,
                    RegexString(
                        identifier=node.identifier,
                        regex=adapted_regex,
                        modifiers=node.modifiers,
                        is_anonymous=node.is_anonymous,
                    ),
                )

        return node

    def _escape_braces(self, regex: str) -> str:
        """Escape unescaped braces in regex."""
        result = []
        i = 0
        while i < len(regex):
            if regex[i] == "\\":
                # Already escaped, skip next char
                result.append(regex[i : i + 2])
                i += 2
            elif regex[i] == "{":
                # Check if this is a repetition quantifier
                if self._is_quantifier_brace(regex, i):
                    result.append(regex[i])
                else:
                    # Escape it
                    result.append("\\{")
                i += 1
            else:
                result.append(regex[i])
                i += 1

        return "".join(result)

    def _unescape_braces(self, regex: str) -> str:
        """Unescape braces for YARA compatibility.

        Only a backslash that directly escapes a brace is removed. A backslash
        that is itself escaped (``\\\\``) is preserved so that a quantifier
        applied to a literal backslash, such as ``\\\\{2,3}``, keeps its
        meaning instead of being corrupted into ``\\{2,3}``.
        """
        result: list[str] = []
        i = 0
        while i < len(regex):
            if regex[i] == "\\" and i + 1 < len(regex):
                nxt = regex[i + 1]
                if nxt in "{}":
                    result.append(nxt)
                else:
                    result.append(regex[i : i + 2])
                i += 2
            else:
                result.append(regex[i])
                i += 1
        return "".join(result)

    def _is_quantifier_brace(self, regex: str, pos: int) -> bool:
        """Check if brace at position is part of a quantifier."""
        if pos == 0:
            return False

        # Look for pattern like x{n}, x{n,}, x{n,m}
        # Must be preceded by atom (char, group, class)
        prev = pos - 1

        # Skip back to find the atom
        if regex[prev] in ")]}":
            return True  # After group/class

        if regex[prev].isalnum() or regex[prev] in ".\\":
            # Look ahead for valid quantifier
            j = pos + 1
            digits = 0
            comma = False

            while j < len(regex) and regex[j] != "}":
                if regex[j].isdigit():
                    digits += 1
                elif regex[j] == "," and not comma:
                    comma = True
                else:
                    return False  # Invalid quantifier content
                j += 1

            return j < len(regex) and regex[j] == "}" and digits > 0

        return False

    def visit_hex_string(self, node: HexString) -> HexString:
        """Adapt hex string syntax."""
        from typing import cast

        from yaraast.ast.strings import HexToken

        tokens = [cast("HexToken", self.visit(token)) for token in node.tokens]

        return self._copy_node_metadata(
            node,
            HexString(
                identifier=node.identifier,
                tokens=tokens,
                modifiers=node.modifiers,
                is_anonymous=node.is_anonymous,
            ),
        )

    def visit_hex_jump(self, node: HexJump) -> HexJump:
        """Adapt hex jump syntax."""
        # YARA-X accepts hex/octal values in jumps
        # This is actually an enhancement, no adaptation needed
        return node

    def generate_migration_guide(self, issues: list[CompatibilityIssue]) -> str:
        """Generate a migration guide based on compatibility issues."""
        guide = ["# YARA to YARA-X Migration Guide\n"]

        # Group issues by type
        by_type: dict[str, list[CompatibilityIssue]] = {}
        for issue in issues:
            if issue.issue_type not in by_type:
                by_type[issue.issue_type] = []
            by_type[issue.issue_type].append(issue)

        # Generate sections
        if "unescaped_brace" in by_type:
            guide.append("## Regex Brace Escaping\n")
            guide.append("YARA-X requires braces to be escaped in regex patterns:\n")
            guide.append("```")
            guide.append("# YARA:   /abc{/")
            guide.append("# YARA-X: /abc\\{/")
            guide.append("```\n")

        if "invalid_escape" in by_type:
            guide.append("## Invalid Escape Sequences\n")
            guide.append("YARA-X validates escape sequences more strictly:\n")
            unique_escapes = set()
            for issue in by_type["invalid_escape"]:
                # Extract escape from message
                if r"'\\" in issue.message:
                    escape = issue.message.split("'\\")[1].split("'")[0]
                    unique_escapes.add(escape)

            for escape in sorted(unique_escapes):
                guide.append(f"- `\\{escape}` is not a valid escape sequence\n")
            guide.append("\n")

        if "base64_too_short" in by_type:
            guide.append("## Base64 Pattern Length\n")
            guide.append(
                f"YARA-X requires base64 patterns to be at least {self.features.minimum_base64_length} characters.\n",
            )
            guide.append("Short patterns should be padded or reconsidered.\n\n")

        if "duplicate_modifier" in by_type:
            guide.append("## Duplicate Modifiers\n")
            guide.append("YARA-X does not allow duplicate rule modifiers.\n")
            guide.append("Remove any duplicate 'global' or 'private' modifiers.\n\n")

        if "yarax_feature" in by_type:
            guide.append("## YARA-X Specific Features\n")
            guide.append("Your rules use features specific to YARA-X:\n")
            for issue in by_type["yarax_feature"]:
                feature = issue.message.split(": ", 1)[1]
                guide.append(f"- {feature}\n")
            guide.append("\nThese features are not backward compatible with YARA.\n")

        return "".join(guide)
