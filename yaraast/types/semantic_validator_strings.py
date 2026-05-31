"""String identifier semantic validation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.base import ASTNode
from yaraast.ast.modifiers import StringModifierType
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.visitor.defaults import DefaultASTVisitor
from yaraast.xor_keys import parse_xor_key_text

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
        if getattr(node, "is_anonymous", False):
            return

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
    _CLASSIC_UNSUPPORTED_NAMED_MODIFIERS = {
        StringModifierType.CASE.value,
        StringModifierType.UTF8.value,
        StringModifierType.UTF16.value,
        StringModifierType.UTF16LE.value,
        StringModifierType.UTF16BE.value,
    }
    _TEXT_UNSUPPORTED_MODIFIERS = _CLASSIC_UNSUPPORTED_NAMED_MODIFIERS | {
        "i",
        "m",
        "s",
    }
    _HEX_ALLOWED_MODIFIERS = {
        StringModifierType.PRIVATE.value,
    }
    _REGEX_DISALLOWED_MODIFIERS = {
        StringModifierType.XOR.value,
        StringModifierType.BASE64.value,
        StringModifierType.BASE64WIDE.value,
    }
    _REGEX_UNSUPPORTED_MODIFIERS = {
        "m",
        StringModifierType.MULTILINE.value,
    } | _CLASSIC_UNSUPPORTED_NAMED_MODIFIERS
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
        self._check_duplicate_modifiers(node)
        self._check_plain_string_content(node)
        self._check_unsupported_modifiers(node, self._TEXT_UNSUPPORTED_MODIFIERS, "string")
        self._check_non_regex_string(node, "plain")
        self._check_text_string_combinations(node)
        self._check_text_string_modifier_values(node)

    def visit_hex_string(self, node: HexString) -> None:
        self._check_duplicate_modifiers(node)
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
        self._check_duplicate_modifiers(node)
        for modifier in node.modifiers:
            name = self._modifier_name(modifier)
            if name in self._REGEX_UNSUPPORTED_MODIFIERS:
                self.result.add_error(
                    f"Unsupported regex modifier '{name}' used on regex string '{node.identifier}' in rule '{self.current_rule_name}'",
                    node.location,
                    "YARA regex strings support dotall ('s') but not multiline ('m').",
                )
                continue
            if name not in self._REGEX_DISALLOWED_MODIFIERS:
                continue
            self.result.add_error(
                f"String modifier '{name}' used on regex string '{node.identifier}' in rule '{self.current_rule_name}'",
                node.location,
                "Use base64, base64wide, and xor only on text strings.",
            )

    def _check_unsupported_modifiers(
        self,
        node: StringDefinition,
        unsupported_modifiers: set[str],
        label: str,
    ) -> None:
        for modifier in node.modifiers:
            name = self._modifier_name(modifier)
            if name not in unsupported_modifiers:
                continue

            self.result.add_error(
                f"Unsupported {label} modifier '{name}' used on string '{node.identifier}' in rule '{self.current_rule_name}'",
                node.location,
                "Remove modifiers that are not supported by classic YARA syntax.",
            )

    def _check_plain_string_content(self, node: PlainString) -> None:
        if len(node.value) > 0:
            return

        self.result.add_error(
            f"Empty text string '{node.identifier}' in rule '{self.current_rule_name}'",
            node.location,
            "Text strings must contain at least one byte.",
        )

    def _check_duplicate_modifiers(self, node: StringDefinition) -> None:
        seen: set[str] = set()
        for modifier in node.modifiers:
            name = self._modifier_name(modifier)
            if name in seen:
                self.result.add_error(
                    f"Duplicate string modifier '{name}' on string '{node.identifier}' in rule '{self.current_rule_name}'",
                    node.location,
                    "Remove the repeated string modifier.",
                )
            else:
                seen.add(name)

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
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return parse_xor_key_text(value)
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
        self._local_string_scopes: list[set[str]] = []

    def check_rule(self, rule: Rule) -> None:
        """Check a rule for undefined string references in its condition."""
        if not rule.condition:
            return
        self._local_string_scopes.clear()

        # Collect defined string identifiers (normalized to $name format)
        defined = set()
        anonymous = set()
        for string_def in rule.strings:
            sid = string_def.identifier
            if not sid.startswith("$"):
                sid = f"${sid}"
            defined.add(sid)
            if getattr(string_def, "is_anonymous", False):
                anonymous.add(sid)

        # Walk condition to find string references
        referenced = set()
        self._collect_string_refs(rule.condition, referenced)

        # Report undefined strings
        for ref in referenced:
            normalized = ref if ref.startswith("$") else f"${ref}"
            # Check exact match and wildcard patterns
            if normalized.endswith("*"):
                if not self._matches_defined_pattern(normalized, defined, anonymous):
                    self.result.add_error(
                        f"Undefined string pattern '{normalized}' in rule '{rule.name}'",
                        suggestion="Define matching strings in the strings section.",
                    )
            elif normalized not in defined:
                self.result.add_error(
                    f"Undefined string '{normalized}' in rule '{rule.name}'",
                    suggestion="Add a string definition in the strings section.",
                )

        self._check_invalid_string_sets(rule.condition, defined, rule.name)

        used = set()
        self._local_string_scopes.clear()
        self._collect_used_string_defs(rule.condition, defined, anonymous, used)
        for sid in sorted(defined - used):
            self.result.add_error(
                f"Unreferenced string '{sid}' in rule '{rule.name}'",
                suggestion="Reference the string in the condition or remove the definition.",
            )

    def _normalize_ref(self, ref: str) -> str:
        return ref if ref.startswith("$") else f"${ref}"

    def _is_local_string_ref(self, ref: str) -> bool:
        normalized = self._normalize_ref(ref)
        return any(normalized in scope for scope in reversed(self._local_string_scopes))

    def _add_local_string_declaration(self, identifier: str) -> None:
        if not identifier.startswith("$") or not self._local_string_scopes:
            return
        self._local_string_scopes[-1].add(identifier)

    def _collect_with_statement_refs(
        self,
        node: ASTNode,
        refs: set[str],
        implicit_string_allowed: bool,
    ) -> None:
        self._local_string_scopes.append(set())
        try:
            for declaration in node.declarations:
                self._collect_string_refs(declaration.value, refs, implicit_string_allowed)
                self._add_local_string_declaration(declaration.identifier)
            self._collect_string_refs(node.body, refs, implicit_string_allowed)
        finally:
            self._local_string_scopes.pop()

    def _collect_with_statement_used(
        self,
        node: ASTNode,
        defined: set[str],
        anonymous: set[str],
        used: set[str],
        implicit_string_allowed: bool,
    ) -> None:
        self._local_string_scopes.append(set())
        try:
            for declaration in node.declarations:
                self._collect_used_string_defs(
                    declaration.value,
                    defined,
                    anonymous,
                    used,
                    implicit_string_allowed,
                )
                self._add_local_string_declaration(declaration.identifier)
            self._collect_used_string_defs(
                node.body,
                defined,
                anonymous,
                used,
                implicit_string_allowed,
            )
        finally:
            self._local_string_scopes.pop()

    def _matches_defined_pattern(
        self, pattern: str, defined: set[str], anonymous: set[str]
    ) -> bool:
        if pattern == "$*":
            return bool(defined)
        prefix = pattern[:-1]
        return any(sid.startswith(prefix) for sid in defined - anonymous)

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
        from yaraast.yarax.ast_nodes import WithStatement

        if isinstance(node, StringIdentifier):
            if (implicit_string_allowed and node.name == "$") or self._is_local_string_ref(
                node.name
            ):
                return
            refs.add(node.name)
        elif isinstance(node, StringWildcard):
            if not self._is_local_string_ref(node.pattern):
                refs.add(node.pattern)
        elif isinstance(node, StringCount | StringOffset | StringLength):
            ref = f"${node.string_id}" if not node.string_id.startswith("$") else node.string_id
            if (implicit_string_allowed and ref == "$") or self._is_local_string_ref(ref):
                return
            refs.add(ref)
        elif isinstance(node, AtExpression):
            if isinstance(node.string_id, str):
                ref = node.string_id if node.string_id.startswith("$") else f"${node.string_id}"
                if not ((implicit_string_allowed and ref == "$") or self._is_local_string_ref(ref)):
                    refs.add(ref)
            else:
                self._collect_string_refs(node.string_id, refs, implicit_string_allowed)
        elif isinstance(node, InExpression) and isinstance(node.subject, str):
            ref = node.subject if node.subject.startswith("$") else f"${node.subject}"
            if not ((implicit_string_allowed and ref == "$") or self._is_local_string_ref(ref)):
                refs.add(ref)
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
        elif isinstance(node, WithStatement):
            self._collect_with_statement_refs(node, refs, implicit_string_allowed)
            return

        # Recurse into children
        for child in node.children():
            self._collect_string_refs(child, refs, implicit_string_allowed)

    def _collect_string_set_refs(self, string_set: object, refs: set[str]) -> None:
        from yaraast.ast.expressions import (
            Identifier,
            ParenthesesExpression,
            SetExpression,
            StringIdentifier,
            StringLiteral,
            StringWildcard,
        )

        if isinstance(string_set, str):
            if string_set != "them" and not self._is_local_string_ref(string_set):
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
            if not self._is_local_string_ref(string_set.name):
                refs.add(string_set.name)
        elif isinstance(string_set, StringWildcard):
            if not self._is_local_string_ref(string_set.pattern):
                refs.add(string_set.pattern)
        elif isinstance(string_set, StringLiteral):
            self._collect_string_set_refs(string_set.value, refs)
        elif isinstance(string_set, Identifier) and string_set.name == "them":
            refs.add("$*")
        elif isinstance(string_set, SetExpression):
            for element in string_set.elements:
                self._collect_string_set_refs(element, refs)

    def _check_invalid_string_sets(self, node: ASTNode, defined: set[str], rule_name: str) -> None:
        from yaraast.ast.conditions import ForOfExpression, OfExpression

        if isinstance(node, ForOfExpression | OfExpression):
            if self._is_parenthesized_them(node.string_set):
                self.result.add_error(
                    f"Invalid parenthesized 'them' string set in rule '{rule_name}'",
                    suggestion="Use 'of them' without parentheses.",
                )
            elif self._is_them_string_set(node.string_set) and not defined:
                self.result.add_error(
                    f"Undefined string pattern '$*' in rule '{rule_name}'",
                    suggestion="Define at least one string or remove the 'of them' condition.",
                )

        for child in node.children():
            self._check_invalid_string_sets(child, defined, rule_name)

    def _is_parenthesized_them(self, string_set: object) -> bool:
        from yaraast.ast.expressions import Identifier, ParenthesesExpression

        return (
            isinstance(string_set, ParenthesesExpression)
            and isinstance(string_set.expression, Identifier)
            and string_set.expression.name == "them"
        )

    def _is_them_string_set(self, string_set: object) -> bool:
        from yaraast.ast.expressions import Identifier

        return (isinstance(string_set, str) and string_set == "them") or (
            isinstance(string_set, Identifier) and string_set.name == "them"
        )

    def _collect_used_string_defs(
        self,
        node: ASTNode,
        defined: set[str],
        anonymous: set[str],
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
        from yaraast.yarax.ast_nodes import WithStatement

        if isinstance(node, StringIdentifier):
            if not (
                (implicit_string_allowed and node.name == "$")
                or self._is_local_string_ref(node.name)
            ):
                self._mark_used_string_ref(node.name, defined, anonymous, used)
        elif isinstance(node, StringWildcard):
            if not self._is_local_string_ref(node.pattern):
                self._mark_used_string_ref(node.pattern, defined, anonymous, used)
        elif isinstance(node, StringCount | StringOffset | StringLength):
            ref = f"${node.string_id}" if not node.string_id.startswith("$") else node.string_id
            if not ((implicit_string_allowed and ref == "$") or self._is_local_string_ref(ref)):
                self._mark_used_string_ref(ref, defined, anonymous, used)
        elif isinstance(node, AtExpression):
            if isinstance(node.string_id, str):
                ref = node.string_id if node.string_id.startswith("$") else f"${node.string_id}"
                if not ((implicit_string_allowed and ref == "$") or self._is_local_string_ref(ref)):
                    self._mark_used_string_ref(ref, defined, anonymous, used)
            else:
                self._collect_used_string_defs(
                    node.string_id,
                    defined,
                    anonymous,
                    used,
                    implicit_string_allowed,
                )
        elif isinstance(node, InExpression) and isinstance(node.subject, str):
            ref = node.subject if node.subject.startswith("$") else f"${node.subject}"
            if not ((implicit_string_allowed and ref == "$") or self._is_local_string_ref(ref)):
                self._mark_used_string_ref(ref, defined, anonymous, used)
        elif isinstance(node, ForOfExpression):
            if hasattr(node.quantifier, "accept"):
                self._collect_used_string_defs(node.quantifier, defined, anonymous, used)
            self._mark_used_string_set(node.string_set, defined, anonymous, used)
            if node.condition:
                self._collect_used_string_defs(node.condition, defined, anonymous, used, True)
            return
        elif isinstance(node, OfExpression):
            if hasattr(node.quantifier, "accept"):
                self._collect_used_string_defs(node.quantifier, defined, anonymous, used)
            self._mark_used_string_set(node.string_set, defined, anonymous, used)
            return
        elif isinstance(node, WithStatement):
            self._collect_with_statement_used(
                node,
                defined,
                anonymous,
                used,
                implicit_string_allowed,
            )
            return

        for child in node.children():
            self._collect_used_string_defs(child, defined, anonymous, used, implicit_string_allowed)

    def _mark_used_string_set(
        self, string_set: object, defined: set[str], anonymous: set[str], used: set[str]
    ) -> None:
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
            elif not self._is_local_string_ref(string_set):
                self._mark_used_string_ref(string_set, defined, anonymous, used)
            return

        if isinstance(string_set, list | tuple | set | frozenset):
            for item in string_set:
                self._mark_used_string_set(item, defined, anonymous, used)
            return

        if isinstance(string_set, ParenthesesExpression):
            self._mark_used_string_set(string_set.expression, defined, anonymous, used)
        elif isinstance(string_set, StringIdentifier):
            if not self._is_local_string_ref(string_set.name):
                self._mark_used_string_ref(string_set.name, defined, anonymous, used)
        elif isinstance(string_set, StringWildcard):
            if not self._is_local_string_ref(string_set.pattern):
                self._mark_used_string_ref(string_set.pattern, defined, anonymous, used)
        elif isinstance(string_set, StringLiteral):
            self._mark_used_string_set(string_set.value, defined, anonymous, used)
        elif isinstance(string_set, Identifier) and string_set.name == "them":
            used.update(defined)
        elif isinstance(string_set, SetExpression):
            for element in string_set.elements:
                self._mark_used_string_set(element, defined, anonymous, used)

    def _mark_used_string_ref(
        self, ref: str, defined: set[str], anonymous: set[str], used: set[str]
    ) -> None:
        normalized = ref if ref.startswith("$") else f"${ref}"
        if normalized == "$*":
            used.update(defined)
            return
        if normalized.endswith("*"):
            prefix = normalized[:-1]
            used.update(sid for sid in defined - anonymous if sid.startswith(prefix))
            return
        if normalized in defined:
            used.add(normalized)
