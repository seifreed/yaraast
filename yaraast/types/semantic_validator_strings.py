"""String identifier semantic validation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.base import ASTNode
from yaraast.ast.modifiers import StringModifierType
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.visitor.defaults import DefaultASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import StringDefinition


class StringIdentifierValidator(DefaultASTVisitor[None]):
    """Validator for string identifier uniqueness within rules."""

    def __init__(self, result: ValidationResult) -> None:
        super().__init__(default=None)
        self.result = result
        self.current_rule_strings: set[str] = set()
        self.current_rule_name: str | None = None

    def visit_rule(self, node: Rule) -> None:
        self.current_rule_strings.clear()
        self.current_rule_name = node.name

        for string_def in node.strings:
            self.visit(string_def)

    def visit_string_definition(self, node: StringDefinition) -> None:
        # Normalize: always use $ prefix for consistency with type environment
        identifier = node.identifier if node.identifier.startswith("$") else f"${node.identifier}"

        if identifier == "$":
            self.result.add_error(
                f"Invalid empty string identifier '$' in rule '{self.current_rule_name}'",
                node.location,
                "String identifiers must have a name after '$', e.g. '$s1'.",
            )
            return

        if identifier in self.current_rule_strings:
            self.result.add_error(
                f"Duplicate string identifier '{identifier}' in rule '{self.current_rule_name}'",
                node.location,
                f"String identifiers must be unique within each rule. Consider renaming to '{identifier}_2' or similar.",
            )
        else:
            self.current_rule_strings.add(identifier)

    def visit_plain_string(self, node) -> None:
        self.visit_string_definition(node)

    def visit_hex_string(self, node) -> None:
        self.visit_string_definition(node)

    def visit_regex_string(self, node) -> None:
        self.visit_string_definition(node)


class StringModifierApplicabilityValidator(DefaultASTVisitor[None]):
    """Validator for string modifier applicability and compatibility."""

    _REGEX_ONLY_MODIFIERS = {
        StringModifierType.DOTALL.value,
        StringModifierType.MULTILINE.value,
    }
    _HEX_ALLOWED_MODIFIERS = {
        StringModifierType.PRIVATE.value,
    }
    _REGEX_DISALLOWED_MODIFIERS = {
        StringModifierType.XOR.value,
        StringModifierType.BASE64.value,
        StringModifierType.BASE64WIDE.value,
    }
    _BASE64_MODIFIERS = {
        StringModifierType.BASE64.value,
        StringModifierType.BASE64WIDE.value,
    }
    _BASE64_INCOMPATIBLE_MODIFIERS = {
        StringModifierType.NOCASE.value,
        StringModifierType.XOR.value,
        StringModifierType.FULLWORD.value,
    }
    _XOR_INCOMPATIBLE_MODIFIERS = {
        StringModifierType.NOCASE.value,
        StringModifierType.BASE64.value,
        StringModifierType.BASE64WIDE.value,
    }

    def __init__(self, result: ValidationResult) -> None:
        super().__init__(default=None)
        self.result = result
        self.current_rule_name: str | None = None

    def visit_rule(self, node: Rule) -> None:
        self.current_rule_name = node.name
        for string_def in node.strings:
            self.visit(string_def)

    def visit_plain_string(self, node: PlainString) -> None:
        self._check_plain_string_content(node)
        self._check_non_regex_string(node, "plain")
        self._check_text_string_combinations(node)
        self._check_text_string_modifier_values(node)

    def visit_hex_string(self, node: HexString) -> None:
        if not node.tokens:
            self.result.add_error(
                f"Empty hex string '{node.identifier}' in rule '{self.current_rule_name}'",
                node.location,
                "Hex strings must contain at least one token.",
            )

        for modifier in node.modifiers:
            name = self._modifier_name(modifier)
            if name in self._HEX_ALLOWED_MODIFIERS:
                continue
            self.result.add_error(
                f"String modifier '{name}' used on hex string '{node.identifier}' in rule '{self.current_rule_name}'",
                node.location,
                "Hex strings only support the private string modifier.",
            )

    def visit_regex_string(self, node: RegexString) -> None:
        for modifier in node.modifiers:
            name = self._modifier_name(modifier)
            if name not in self._REGEX_DISALLOWED_MODIFIERS:
                continue
            self.result.add_error(
                f"String modifier '{name}' used on regex string '{node.identifier}' in rule '{self.current_rule_name}'",
                node.location,
                "Use base64, base64wide, and xor only on text strings.",
            )

    def _check_plain_string_content(self, node: PlainString) -> None:
        if len(node.value) > 0:
            return

        self.result.add_error(
            f"Empty text string '{node.identifier}' in rule '{self.current_rule_name}'",
            node.location,
            "Text strings must contain at least one byte.",
        )

    def _check_non_regex_string(self, node: StringDefinition, string_type: str) -> None:
        for modifier in node.modifiers:
            name = self._modifier_name(modifier)
            if name not in self._REGEX_ONLY_MODIFIERS:
                continue

            self.result.add_error(
                f"Regex-only modifier '{name}' used on {string_type} string '{node.identifier}' in rule '{self.current_rule_name}'",
                node.location,
                "Use the modifier on a regex string or remove it from this string definition.",
            )

    def _check_text_string_combinations(self, node: PlainString) -> None:
        modifier_names = {self._modifier_name(modifier) for modifier in node.modifiers}
        for base64_name in sorted(modifier_names & self._BASE64_MODIFIERS):
            for incompatible_name in sorted(modifier_names & self._BASE64_INCOMPATIBLE_MODIFIERS):
                self.result.add_error(
                    f"String modifier '{incompatible_name}' cannot be combined with '{base64_name}' on string '{node.identifier}' in rule '{self.current_rule_name}'",
                    node.location,
                    "Remove one of the incompatible string modifiers.",
                )

        if StringModifierType.XOR.value not in modifier_names:
            return

        for incompatible_name in sorted(modifier_names & self._XOR_INCOMPATIBLE_MODIFIERS):
            self.result.add_error(
                f"String modifier '{incompatible_name}' cannot be combined with 'xor' on string '{node.identifier}' in rule '{self.current_rule_name}'",
                node.location,
                "Remove one of the incompatible string modifiers.",
            )

    def _check_text_string_modifier_values(self, node: PlainString) -> None:
        for modifier in node.modifiers:
            name = self._modifier_name(modifier)
            value = getattr(modifier, "value", None)
            if name == StringModifierType.XOR.value:
                self._check_xor_value(node, value)
            elif name in self._BASE64_MODIFIERS:
                self._check_base64_value(node, value)

    def _check_xor_value(self, node: PlainString, value: object) -> None:
        if value is None:
            return

        if isinstance(value, tuple | list) and len(value) == 2:
            self._check_xor_range(node, value[0], value[1])
            return

        if isinstance(value, str) and "-" in value:
            low_text, high_text = value.split("-", maxsplit=1)
            self._check_xor_range(node, low_text, high_text)
            return

        self._check_xor_key(node, value)

    def _check_xor_range(self, node: PlainString, low_value: object, high_value: object) -> None:
        low = self._parse_xor_key(low_value)
        high = self._parse_xor_key(high_value)
        if low is None or high is None:
            self.result.add_error(
                f"xor range for string '{node.identifier}' must contain integer bounds in rule '{self.current_rule_name}'",
                node.location,
                "Use integer byte values such as xor(0x01-0xff).",
            )
            return

        self._check_xor_key(node, low)
        self._check_xor_key(node, high)
        if low > high:
            self.result.add_error(
                f"xor range for string '{node.identifier}' must have a lower bound no greater than the upper bound in rule '{self.current_rule_name}'",
                node.location,
                "Use an ascending range such as xor(0x01-0xff).",
            )

    def _check_xor_key(self, node: PlainString, value: object) -> None:
        key = self._parse_xor_key(value)
        if key is not None and 0 <= key <= 255:
            return

        self.result.add_error(
            f"xor key for string '{node.identifier}' must be between 0 and 255 in rule '{self.current_rule_name}'",
            node.location,
            "Use a single-byte XOR key.",
        )

    def _parse_xor_key(self, value: object) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            text = value.strip()
            try:
                if text.lower().startswith("0x"):
                    return int(text, 16)
                if any(char in "abcdefABCDEF" for char in text):
                    return int(text, 16)
                return int(text, 10)
            except ValueError:
                return None
        return None

    def _check_base64_value(self, node: PlainString, value: object) -> None:
        if value is None:
            return

        if isinstance(value, str):
            try:
                encoded_value = value.encode("ascii")
            except UnicodeEncodeError:
                encoded_value = b""
            if len(encoded_value) == 64:
                return

        self.result.add_error(
            f"base64 alphabet for string '{node.identifier}' must be 64 bytes in rule '{self.current_rule_name}'",
            node.location,
            "Use a 64-byte ASCII alphabet or remove the custom alphabet.",
        )

    def _modifier_name(self, modifier: object) -> str:
        return str(getattr(modifier, "name", modifier))


class UndefinedStringDetector:
    """Detects string identifiers used in conditions but not defined in strings section."""

    def __init__(self, result: ValidationResult) -> None:
        self.result = result

    def check_rule(self, rule: Rule) -> None:
        """Check a rule for undefined string references in its condition."""
        if not rule.condition:
            return

        # Collect defined string identifiers (normalized to $name format)
        defined = set()
        for string_def in rule.strings:
            sid = string_def.identifier
            if not sid.startswith("$"):
                sid = f"${sid}"
            defined.add(sid)

        # Walk condition to find string references
        referenced = set()
        self._collect_string_refs(rule.condition, referenced)

        # Report undefined strings
        for ref in referenced:
            normalized = ref if ref.startswith("$") else f"${ref}"
            # Check exact match and wildcard patterns
            if normalized.endswith("*"):
                prefix = normalized[:-1]
                if not any(d.startswith(prefix) for d in defined):
                    self.result.add_error(
                        f"Undefined string pattern '{normalized}' in rule '{rule.name}'",
                        suggestion="Define matching strings in the strings section.",
                    )
            elif normalized not in defined:
                self.result.add_error(
                    f"Undefined string '{normalized}' in rule '{rule.name}'",
                    suggestion="Add a string definition in the strings section.",
                )

        used = set()
        self._collect_used_string_defs(rule.condition, defined, used)
        for sid in sorted(defined - used):
            self.result.add_error(
                f"Unreferenced string '{sid}' in rule '{rule.name}'",
                suggestion="Reference the string in the condition or remove the definition.",
            )

    def _collect_string_refs(
        self, node: ASTNode, refs: set[str], implicit_string_allowed: bool = False
    ) -> None:
        """Recursively collect string identifier references from an expression."""
        from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
        from yaraast.ast.expressions import (
            StringCount,
            StringIdentifier,
            StringLength,
            StringOffset,
            StringWildcard,
        )

        if isinstance(node, StringIdentifier):
            if implicit_string_allowed and node.name == "$":
                return
            refs.add(node.name)
        elif isinstance(node, StringWildcard):
            refs.add(node.pattern)
        elif isinstance(node, StringCount | StringOffset | StringLength):
            ref = f"${node.string_id}" if not node.string_id.startswith("$") else node.string_id
            if implicit_string_allowed and ref == "$":
                return
            refs.add(ref)
        elif isinstance(node, AtExpression):
            refs.add(node.string_id if node.string_id.startswith("$") else f"${node.string_id}")
        elif isinstance(node, InExpression) and isinstance(node.subject, str):
            refs.add(node.subject if node.subject.startswith("$") else f"${node.subject}")
        elif isinstance(node, ForOfExpression):
            if hasattr(node.quantifier, "accept"):
                self._collect_string_refs(node.quantifier, refs)
            self._collect_string_set_refs(node.string_set, refs)
            if node.condition:
                self._collect_string_refs(node.condition, refs, implicit_string_allowed=True)
            return
        elif isinstance(node, OfExpression):
            if hasattr(node.quantifier, "accept"):
                self._collect_string_refs(node.quantifier, refs)
            self._collect_string_set_refs(node.string_set, refs)
            return

        # Recurse into children
        for child in node.children():
            self._collect_string_refs(child, refs, implicit_string_allowed)

    def _collect_string_set_refs(self, string_set: object, refs: set[str]) -> None:
        from yaraast.ast.expressions import (
            ParenthesesExpression,
            SetExpression,
            StringIdentifier,
            StringLiteral,
            StringWildcard,
        )

        if isinstance(string_set, str):
            if string_set != "them":
                refs.add(string_set)
            return

        if isinstance(string_set, list | tuple | set | frozenset):
            for item in string_set:
                self._collect_string_set_refs(item, refs)
            return

        if isinstance(string_set, ParenthesesExpression):
            self._collect_string_set_refs(string_set.expression, refs)
            return

        if isinstance(string_set, StringIdentifier):
            refs.add(string_set.name)
        elif isinstance(string_set, StringWildcard):
            refs.add(string_set.pattern)
        elif isinstance(string_set, StringLiteral):
            self._collect_string_set_refs(string_set.value, refs)
        elif isinstance(string_set, SetExpression):
            for element in string_set.elements:
                self._collect_string_set_refs(element, refs)

    def _collect_used_string_defs(
        self,
        node: ASTNode,
        defined: set[str],
        used: set[str],
        implicit_string_allowed: bool = False,
    ) -> None:
        from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
        from yaraast.ast.expressions import (
            StringCount,
            StringIdentifier,
            StringLength,
            StringOffset,
            StringWildcard,
        )

        if isinstance(node, StringIdentifier):
            if not (implicit_string_allowed and node.name == "$"):
                self._mark_used_string_ref(node.name, defined, used)
        elif isinstance(node, StringWildcard):
            self._mark_used_string_ref(node.pattern, defined, used)
        elif isinstance(node, StringCount | StringOffset | StringLength):
            ref = f"${node.string_id}" if not node.string_id.startswith("$") else node.string_id
            if not (implicit_string_allowed and ref == "$"):
                self._mark_used_string_ref(ref, defined, used)
        elif isinstance(node, AtExpression):
            self._mark_used_string_ref(node.string_id, defined, used)
        elif isinstance(node, InExpression) and isinstance(node.subject, str):
            self._mark_used_string_ref(node.subject, defined, used)
        elif isinstance(node, ForOfExpression):
            if hasattr(node.quantifier, "accept"):
                self._collect_used_string_defs(node.quantifier, defined, used)
            self._mark_used_string_set(node.string_set, defined, used)
            if node.condition:
                self._collect_used_string_defs(node.condition, defined, used, True)
            return
        elif isinstance(node, OfExpression):
            if hasattr(node.quantifier, "accept"):
                self._collect_used_string_defs(node.quantifier, defined, used)
            self._mark_used_string_set(node.string_set, defined, used)
            return

        for child in node.children():
            self._collect_used_string_defs(child, defined, used, implicit_string_allowed)

    def _mark_used_string_set(self, string_set: object, defined: set[str], used: set[str]) -> None:
        from yaraast.ast.expressions import (
            Identifier,
            ParenthesesExpression,
            SetExpression,
            StringIdentifier,
            StringLiteral,
            StringWildcard,
        )

        if isinstance(string_set, str):
            if string_set == "them":
                used.update(defined)
            else:
                self._mark_used_string_ref(string_set, defined, used)
            return

        if isinstance(string_set, list | tuple | set | frozenset):
            for item in string_set:
                self._mark_used_string_set(item, defined, used)
            return

        if isinstance(string_set, ParenthesesExpression):
            self._mark_used_string_set(string_set.expression, defined, used)
        elif isinstance(string_set, StringIdentifier):
            self._mark_used_string_ref(string_set.name, defined, used)
        elif isinstance(string_set, StringWildcard):
            self._mark_used_string_ref(string_set.pattern, defined, used)
        elif isinstance(string_set, StringLiteral):
            self._mark_used_string_set(string_set.value, defined, used)
        elif isinstance(string_set, Identifier) and string_set.name == "them":
            used.update(defined)
        elif isinstance(string_set, SetExpression):
            for element in string_set.elements:
                self._mark_used_string_set(element, defined, used)

    def _mark_used_string_ref(self, ref: str, defined: set[str], used: set[str]) -> None:
        normalized = ref if ref.startswith("$") else f"${ref}"
        if normalized == "$*":
            used.update(defined)
            return
        if normalized.endswith("*"):
            prefix = normalized[:-1]
            used.update(sid for sid in defined if sid.startswith(prefix))
            return
        if normalized in defined:
            used.add(normalized)
