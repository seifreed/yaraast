"""String usage analyzer for YARA rules."""

from __future__ import annotations

from collections import Counter, defaultdict
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from yaraast.ast.expressions import (
    Identifier,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.string_references import normalize_string_reference_id
from yaraast.visitor.base import BaseVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
    from yaraast.ast.expressions import (
        StringCount,
        StringLength,
        StringOffset,
    )
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import HexString, PlainString, RegexString, StringDefinition


class StringUsageAnalyzer(BaseVisitor[None]):
    """Analyze string usage in YARA rules."""

    _LOCAL_WITHOUT_VALUE = object()
    _MISSING_LOCAL = object()

    def __init__(self) -> None:
        self.defined_strings: dict[str, set[str]] = {}  # rule_name -> set of string ids
        self.anonymous_strings: dict[str, set[str]] = {}  # rule_name -> anonymous internal ids
        self.used_strings: dict[str, set[str]] = {}  # rule_name -> set of string ids
        self.current_rule: str | None = None
        self.current_rule_key: str | None = None
        self.rule_usage_keys: dict[int, str] = {}
        self.in_condition: bool = False
        self.implicit_current_string_allowed: bool = False
        self.local_scopes: list[dict[str, Any]] = []

    def analyze(self, yara_file: YaraFile) -> dict[str, dict[str, Any]]:
        """Analyze string usage in YARA file."""
        self.defined_strings.clear()
        self.anonymous_strings.clear()
        self.used_strings.clear()
        self.rule_usage_keys.clear()
        self.local_scopes.clear()
        self.current_rule_key = None

        self.visit(yara_file)

        # Build analysis results
        results = {}
        for rule_name in self.defined_strings:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())
            defined_used = defined & used

            unused = defined - used
            undefined = used - defined

            results[rule_name] = {
                "defined": sorted(defined),
                "used": sorted(used),
                "unused": sorted(unused),
                "undefined": sorted(undefined),
                "usage_rate": len(defined_used) / len(defined) if defined else 0,
            }

        return results

    def _normalize_string_id(self, string_id: str) -> str:
        """Normalize string ids while rejecting embedded reference operators."""
        return normalize_string_reference_id(string_id)

    def get_unused_strings(self, rule_name: str | None = None) -> dict[str, list[str]]:
        """Get unused strings for a specific rule or all rules."""
        if rule_name:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())
            return {rule_name: sorted(defined - used)}

        unused = {}
        for rule in self.defined_strings:
            defined = self.defined_strings[rule]
            used = self.used_strings.get(rule, set())
            unused_in_rule = sorted(defined - used)
            if unused_in_rule:
                unused[rule] = unused_in_rule

        return unused

    def get_undefined_strings(
        self,
        rule_name: str | None = None,
    ) -> dict[str, list[str]]:
        """Get undefined but used strings for a specific rule or all rules."""
        if rule_name:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())
            return {rule_name: sorted(used - defined)}

        undefined = {}
        for rule in self.used_strings:
            defined = self.defined_strings.get(rule, set())
            used = self.used_strings[rule]
            undefined_in_rule = sorted(used - defined)
            if undefined_in_rule:
                undefined[rule] = undefined_in_rule

        return undefined

    # Visitor methods
    def visit_yara_file(self, node: YaraFile) -> None:
        rule_counts = Counter(rule.name for rule in node.rules)
        seen_rules: defaultdict[str, int] = defaultdict(int)
        for rule in node.rules:
            seen_rules[rule.name] += 1
            self.rule_usage_keys[id(rule)] = self._rule_usage_key(
                rule.name,
                seen_rules[rule.name],
                rule_counts,
            )
            self.visit(rule)

    def visit_rule(self, node: Rule) -> None:
        self.current_rule = node.name
        self.current_rule_key = self._usage_key_for_rule(node)
        self.defined_strings[self.current_rule_key] = set()
        self.anonymous_strings[self.current_rule_key] = set()
        self.used_strings[self.current_rule_key] = set()
        self.in_condition = False
        self.local_scopes.clear()

        # Visit strings section
        for string in node.strings:
            self.visit(string)

        # Visit condition section
        try:
            self.in_condition = True
            if node.condition is not None:
                self.visit(node.condition)
        finally:
            self.in_condition = False
            self.current_rule = None
            self.current_rule_key = None
            self.local_scopes.clear()

    def _rule_usage_key(self, rule_name: str, occurrence: int, counts: Counter[str]) -> str:
        if counts[rule_name] == 1:
            return rule_name
        return f"{rule_name}#{occurrence}"

    def _usage_key_for_rule(self, rule: Rule) -> str:
        return self.rule_usage_keys.get(id(rule), rule.name)

    def _active_rule_key(self) -> str | None:
        return self.current_rule_key or self.current_rule

    def visit_string_definition(self, node: StringDefinition) -> None:
        rule_key = self._active_rule_key()
        if rule_key:
            normalized = self._normalize_string_id(node.identifier)
            self.defined_strings[rule_key].add(normalized)
            if getattr(node, "is_anonymous", False):
                self.anonymous_strings[rule_key].add(normalized)

    def visit_plain_string(self, node: PlainString) -> None:
        self.visit_string_definition(node)

    def visit_hex_string(self, node: HexString) -> None:
        self.visit_string_definition(node)

    def visit_regex_string(self, node: RegexString) -> None:
        self.visit_string_definition(node)

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        self._mark_condition_string_identifier(node.name)

    def visit_string_wildcard(self, node: StringWildcard) -> None:
        if self.current_rule and self.in_condition:
            self._mark_wildcard_string_set(node.pattern)

    def visit_string_count(self, node: StringCount) -> None:
        self._mark_condition_string_ref(node.string_id)

    def visit_string_offset(self, node: StringOffset) -> None:
        """Visit string offset expression - marks string as used."""
        self._mark_condition_string_ref(node.string_id)
        # Additionally visit index if present for offset expressions
        if hasattr(node, "index") and node.index is not None:
            self.visit(node.index)

    def visit_string_length(self, node: StringLength) -> None:
        """Visit string length expression - marks string as used."""
        self._mark_condition_string_ref(node.string_id)
        # Additionally visit index if present for length expressions
        if hasattr(node, "index") and node.index is not None:
            self.visit(node.index)

    def visit_at_expression(self, node: AtExpression) -> None:
        if isinstance(node.string_id, str):
            self._mark_condition_string_ref(node.string_id)
        else:
            self.visit(node.string_id)
        self.visit(node.offset)

    def visit_in_expression(self, node: InExpression) -> None:
        if isinstance(node.subject, str):
            self._mark_condition_string_ref(node.subject)
        else:
            self.visit(node.subject)
        self.visit(node.range)

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_string_set_value(node.string_set)

        if node.condition is not None:
            previous = self.implicit_current_string_allowed
            self.implicit_current_string_allowed = True
            try:
                self.visit(node.condition)
            finally:
                self.implicit_current_string_allowed = previous

    def visit_of_expression(self, node: OfExpression) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_string_set_value(node.string_set)

    def visit_for_expression(self, node: Any) -> None:
        self._visit_ast_value(node.quantifier)
        self.visit(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_statement(self, node: Any) -> None:
        self._push_local_scope()
        try:
            for declaration in node.declarations:
                self.visit(declaration)
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_declaration(self, node: Any) -> None:
        self._visit_ast_value(node.value)
        self._define_local(node.identifier, node.value)

    def visit_array_comprehension(self, node: Any) -> None:
        self._visit_ast_value(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.expression)
        finally:
            self._pop_local_scope()

    def visit_dict_comprehension(self, node: Any) -> None:
        self._visit_ast_value(node.iterable)
        names = [node.key_variable]
        if node.value_variable:
            names.append(node.value_variable)
        self._push_local_scope(*names)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.key_expression)
            self._visit_ast_value(node.value_expression)
        finally:
            self._pop_local_scope()

    def visit_lambda_expression(self, node: Any) -> None:
        self._push_local_scope(*node.parameters)
        try:
            self._visit_ast_value(node.body)
        finally:
            self._pop_local_scope()

    def _is_local(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self.local_scopes))

    def _local_value(self, name: str) -> object:
        for scope in reversed(self.local_scopes):
            if name in scope:
                return scope[name]
        return self._MISSING_LOCAL

    def _push_local_scope(self, *names: str) -> None:
        scope: dict[str, Any] = {}
        for name in names:
            for local_name in self._local_name_variants(name):
                scope[local_name] = self._LOCAL_WITHOUT_VALUE
        self.local_scopes.append(scope)

    def _pop_local_scope(self) -> None:
        self.local_scopes.pop()

    def _define_local(self, name: str, value: object = _LOCAL_WITHOUT_VALUE) -> None:
        if self.local_scopes:
            for local_name in self._local_name_variants(name):
                self.local_scopes[-1][local_name] = value

    @staticmethod
    def _local_name_variants(name: str) -> set[str]:
        if not isinstance(name, str):
            msg = "Local variable name must be a string"
            raise TypeError(msg)
        names = [part.strip() for part in name.split(",")]
        return {local_name for local_name in names if local_name}

    def _visit_ast_value(self, value: Any) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list):
            for item in value:
                self._visit_ast_value(item)

    def _visit_string_set_value(self, string_set: Any) -> None:
        if isinstance(string_set, str):
            self._mark_string_set_text(string_set)
            return
        if isinstance(string_set, list | tuple | set | frozenset):
            for item in string_set:
                self._visit_string_set_value(item)
            return
        if isinstance(string_set, Identifier):
            name = self._require_string_reference(string_set.name)
            if name == "them":
                self._mark_all_current_rule_strings()
            else:
                self._visit_ast_value(string_set)
            return
        if isinstance(string_set, StringLiteral):
            self._mark_string_set_text(string_set.value)
            return
        if isinstance(string_set, StringIdentifier):
            self._mark_string_set_text(string_set.name)
            return
        if isinstance(string_set, StringWildcard):
            self._mark_string_set_text(string_set.pattern)
            return
        if isinstance(string_set, ParenthesesExpression):
            self._visit_string_set_value(string_set.expression)
            return
        if isinstance(string_set, SetExpression):
            for element in string_set.elements:
                self._visit_string_set_value(element)
            return
        self._visit_ast_value(string_set)

    def _mark_string_set_text(self, text: str) -> None:
        self._require_string_reference(text)
        rule_key = self._active_rule_key()
        if not (rule_key and self.in_condition):
            return
        if text == "them":
            self._mark_all_current_rule_strings()
            return

        normalized = self._normalize_string_id(text)
        local_value = self._local_value(normalized)
        if local_value is not self._MISSING_LOCAL:
            if local_value is not self._LOCAL_WITHOUT_VALUE:
                self._visit_string_set_value(local_value)
            return
        if "*" in text and not text.startswith("$"):
            return
        if "*" in normalized:
            self._mark_wildcard_string_set(text)
        else:
            self.used_strings[rule_key].add(normalized)

    def _mark_condition_string_ref(self, string_id: str) -> None:
        rule_key = self._active_rule_key()
        if not (rule_key and self.in_condition):
            return
        normalized = self._normalize_string_id(string_id)
        if (self.implicit_current_string_allowed and normalized == "$") or self._is_local(
            normalized
        ):
            return
        self.used_strings[rule_key].add(normalized)

    def _mark_condition_string_identifier(self, string_id: str) -> None:
        normalized = self._require_string_reference(string_id)
        if self._is_local(normalized):
            return
        self._mark_condition_string_ref(normalized)

    @staticmethod
    def _require_string_reference(value: Any) -> str:
        if not isinstance(value, str):
            msg = "String reference must be a string"
            raise TypeError(msg)
        return value

    def _mark_wildcard_string_set(self, pattern: str) -> None:
        rule_key = self._active_rule_key()
        if not rule_key:
            return

        normalized = self._normalize_string_id(pattern)
        if normalized == "$*":
            self._mark_all_current_rule_strings()
            return

        anonymous = self.anonymous_strings.get(rule_key, set())
        matches = {
            string_id
            for string_id in self.defined_strings.get(rule_key, set())
            if string_id not in anonymous and fnmatchcase(string_id, normalized)
        }
        if matches:
            self.used_strings[rule_key].update(matches)
            return

        self.used_strings[rule_key].add(normalized)

    def _mark_all_current_rule_strings(self) -> None:
        rule_key = self._active_rule_key()
        if rule_key:
            self.used_strings[rule_key].update(
                self.defined_strings[rule_key],
            )

    def visit_set_expression(self, node: SetExpression) -> None:
        for element in node.elements:
            self.visit(element)
