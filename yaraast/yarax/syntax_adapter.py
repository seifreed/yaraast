"""YARA-X syntax adapter for converting between YARA and YARA-X syntax."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexJump, HexString, PlainString, RegexString
from yaraast.visitor import ASTTransformer
from yaraast.yarax.feature_flags import YaraXFeatures

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.yarax.compatibility_checker import CompatibilityIssue


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

    def adapt(self, yara_file: YaraFile) -> YaraFile:
        """Adapt YARA file syntax."""
        self.adaptations_count = 0
        return self.visit(yara_file)

    def adapt_with_count(self, yara_file: YaraFile) -> tuple[YaraFile, int]:
        """Adapt YARA file syntax and return adapted file with adaptation count."""
        self.adaptations_count = 0
        adapted = self.visit(yara_file)
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
        strings = [self.visit(s) for s in node.strings]
        condition = self.visit(node.condition)

        return Rule(
            name=node.name,
            modifiers=modifiers,
            tags=node.tags,
            meta=meta,
            strings=strings,
            condition=condition,
        )

    def visit_plain_string(self, node: PlainString) -> PlainString:
        """Adapt plain string syntax."""
        modifiers = list(node.modifiers)

        # Check base64 length for YARA-X
        if self.target == "yarax":
            has_base64 = any(m.name in ("base64", "base64wide") for m in modifiers)
            if has_base64 and len(node.value) < self.features.minimum_base64_length:
                # Pad the string to minimum length
                padding_needed = self.features.minimum_base64_length - len(node.value)
                new_value = node.value + "A" * padding_needed
                self.adaptations_count += 1
                return PlainString(
                    identifier=node.identifier,
                    value=new_value,
                    modifiers=modifiers,
                )

        return node

    def visit_regex_string(self, node: RegexString) -> RegexString:
        """Adapt regex string syntax."""
        if self.target == "yarax" and self.features.strict_regex_escaping:
            # Escape unescaped braces
            adapted_regex = self._escape_braces(node.regex)
            if adapted_regex != node.regex:
                self.adaptations_count += 1
                return RegexString(
                    identifier=node.identifier,
                    regex=adapted_regex,
                    modifiers=node.modifiers,
                )

        elif self.target == "yara" and not self.features.strict_regex_escaping:
            # Unescape braces for YARA compatibility
            adapted_regex = self._unescape_braces(node.regex)
            if adapted_regex != node.regex:
                self.adaptations_count += 1
                return RegexString(
                    identifier=node.identifier,
                    regex=adapted_regex,
                    modifiers=node.modifiers,
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
        """Unescape braces for YARA compatibility."""
        # Only unescape braces that aren't part of quantifiers
        return regex.replace("\\{", "{").replace("\\}", "}")

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

        return HexString(
            identifier=node.identifier,
            tokens=tokens,
            modifiers=node.modifiers,
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


# Alias for compatibility
SyntaxAdapter = YaraXSyntaxAdapter
