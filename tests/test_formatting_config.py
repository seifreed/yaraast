"""Tests for formatting configuration.

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from yaraast.codegen.formatting import (
    BraceStyle,
    FormattingConfig,
    HexStyle,
    IndentStyle,
    PredefinedStyles,
    StringStyle,
)


class TestFormattingEnums:
    """Test formatting enum definitions."""

    def test_indent_style_enum_values(self) -> None:
        """IndentStyle should have SPACES and TABS."""
        assert IndentStyle.SPACES.value == "spaces"
        assert IndentStyle.TABS.value == "tabs"

    def test_brace_style_enum_values(self) -> None:
        """BraceStyle should have correct values."""
        assert BraceStyle.SAME_LINE.value == "same_line"
        assert BraceStyle.NEW_LINE.value == "new_line"
        assert BraceStyle.K_AND_R.value == "k_and_r"

    def test_string_style_enum_values(self) -> None:
        """StringStyle should have correct values."""
        assert StringStyle.COMPACT.value == "compact"
        assert StringStyle.ALIGNED.value == "aligned"
        assert StringStyle.TABULAR.value == "tabular"

    def test_hex_style_enum_values(self) -> None:
        """HexStyle should have correct values."""
        assert HexStyle.LOWERCASE.value == "lowercase"
        assert HexStyle.UPPERCASE.value == "uppercase"


class TestFormattingConfigDefaults:
    """Test default configuration values."""

    def test_config_default_initialization(self) -> None:
        """FormattingConfig should initialize with sensible defaults."""
        config = FormattingConfig()

        assert config.indent_style == IndentStyle.SPACES
        assert config.indent_size == 4
        assert config.brace_style == BraceStyle.SAME_LINE
        assert config.space_before_colon is True
        assert config.space_after_colon is True
        assert config.space_around_operators is True
        assert config.space_after_comma is True
        assert config.string_style == StringStyle.ALIGNED
        assert config.align_string_modifiers is True
        assert config.hex_style == HexStyle.LOWERCASE
        assert config.hex_group_size == 0
        assert config.blank_lines_between_rules == 1
        assert config.blank_lines_between_sections == 1
        assert config.max_line_length == 120
        assert config.sort_imports is False
        assert config.sort_rules is False
        assert config.sort_meta is False
        assert config.sort_strings is False
        assert config.section_order == ["meta", "strings", "condition"]
        assert config.preserve_comments is True
        assert config.comment_style == "//"

    def test_config_custom_initialization(self) -> None:
        """FormattingConfig should accept custom values."""
        config = FormattingConfig(
            indent_style=IndentStyle.TABS,
            indent_size=2,
            brace_style=BraceStyle.NEW_LINE,
            space_before_colon=False,
        )

        assert config.indent_style == IndentStyle.TABS
        assert config.indent_size == 2
        assert config.brace_style == BraceStyle.NEW_LINE
        assert config.space_before_colon is False


class TestFormattingConfigSerialization:
    """Test configuration serialization."""

    def test_to_dict_includes_all_fields(self) -> None:
        """To_dict should include all configuration fields."""
        config = FormattingConfig()

        result = config.to_dict()

        assert "indent_style" in result
        assert "indent_size" in result
        assert "brace_style" in result
        assert "space_before_colon" in result
        assert "space_after_colon" in result
        assert "space_around_operators" in result
        assert "space_after_comma" in result
        assert "string_style" in result
        assert "align_string_modifiers" in result
        assert "hex_style" in result
        assert "hex_group_size" in result
        assert "blank_lines_between_rules" in result
        assert "blank_lines_between_sections" in result
        assert "max_line_length" in result
        assert "sort_imports" in result
        assert "sort_rules" in result
        assert "sort_meta" in result
        assert "sort_strings" in result
        assert "section_order" in result
        assert "preserve_comments" in result
        assert "comment_style" in result

    def test_to_dict_converts_enums_to_values(self) -> None:
        """To_dict should convert enum values to strings."""
        config = FormattingConfig(indent_style=IndentStyle.TABS, brace_style=BraceStyle.NEW_LINE)

        result = config.to_dict()

        assert result["indent_style"] == "tabs"
        assert result["brace_style"] == "new_line"
        assert isinstance(result["indent_style"], str)
        assert isinstance(result["brace_style"], str)

    def test_to_dict_preserves_primitive_types(self) -> None:
        """To_dict should preserve int, bool, and list types."""
        config = FormattingConfig(
            indent_size=2,
            space_before_colon=False,
            section_order=["condition", "strings", "meta"],
        )

        result = config.to_dict()

        assert result["indent_size"] == 2
        assert isinstance(result["indent_size"], int)
        assert result["space_before_colon"] is False
        assert isinstance(result["space_before_colon"], bool)
        assert result["section_order"] == ["condition", "strings", "meta"]
        assert isinstance(result["section_order"], list)

    def test_from_dict_creates_config(self) -> None:
        """From_dict should create FormattingConfig from dictionary."""
        data = {
            "indent_style": "tabs",
            "indent_size": 2,
            "brace_style": "new_line",
            "space_before_colon": False,
        }

        config = FormattingConfig.from_dict(data)

        assert isinstance(config, FormattingConfig)
        assert config.indent_style == IndentStyle.TABS
        assert config.indent_size == 2
        assert config.brace_style == BraceStyle.NEW_LINE
        assert config.space_before_colon is False

    def test_from_dict_with_all_fields(self) -> None:
        """From_dict should handle all configuration fields."""
        data = {
            "indent_style": "spaces",
            "indent_size": 4,
            "brace_style": "same_line",
            "space_before_colon": True,
            "space_after_colon": True,
            "space_around_operators": True,
            "space_after_comma": True,
            "string_style": "aligned",
            "align_string_modifiers": True,
            "hex_style": "uppercase",
            "hex_group_size": 8,
            "blank_lines_between_rules": 2,
            "blank_lines_between_sections": 1,
            "max_line_length": 100,
            "sort_imports": True,
            "sort_rules": True,
            "sort_meta": True,
            "sort_strings": True,
            "section_order": ["meta", "condition", "strings"],
            "preserve_comments": False,
            "comment_style": "/*",
        }

        config = FormattingConfig.from_dict(data)

        assert config.indent_style == IndentStyle.SPACES
        assert config.indent_size == 4
        assert config.hex_style == HexStyle.UPPERCASE
        assert config.hex_group_size == 8
        assert config.max_line_length == 100
        assert config.sort_imports is True
        assert config.section_order == ["meta", "condition", "strings"]
        assert config.preserve_comments is False
        assert config.comment_style == "/*"

    def test_from_dict_with_partial_data(self) -> None:
        """From_dict should use defaults for missing fields."""
        data = {"indent_size": 2, "brace_style": "new_line"}

        config = FormattingConfig.from_dict(data)

        assert config.indent_size == 2
        assert config.brace_style == BraceStyle.NEW_LINE
        # Should use defaults for missing fields
        assert config.indent_style == IndentStyle.SPACES
        assert config.space_before_colon is True

    def test_from_dict_with_empty_dict(self) -> None:
        """From_dict should work with empty dictionary."""
        config = FormattingConfig.from_dict({})

        assert isinstance(config, FormattingConfig)
        assert config.indent_style == IndentStyle.SPACES
        assert config.indent_size == 4

    def test_roundtrip_serialization(self) -> None:
        """Config should survive to_dict/from_dict roundtrip."""
        original = FormattingConfig(
            indent_style=IndentStyle.TABS,
            indent_size=2,
            brace_style=BraceStyle.K_AND_R,
            hex_style=HexStyle.UPPERCASE,
            section_order=["condition", "meta", "strings"],
        )

        dict_repr = original.to_dict()
        restored = FormattingConfig.from_dict(dict_repr)

        assert restored.indent_style == original.indent_style
        assert restored.indent_size == original.indent_size
        assert restored.brace_style == original.brace_style
        assert restored.hex_style == original.hex_style
        assert restored.section_order == original.section_order


class TestPredefinedStylesCompact:
    """Test compact predefined style."""

    def test_compact_style_minimal_spacing(self) -> None:
        """Compact style should have minimal spacing."""
        config = PredefinedStyles.compact()

        assert config.indent_size == 2
        assert config.brace_style == BraceStyle.SAME_LINE
        assert config.space_before_colon is False
        assert config.space_after_colon is False
        assert config.space_around_operators is False
        assert config.space_after_comma is False
        assert config.string_style == StringStyle.COMPACT
        assert config.blank_lines_between_rules == 0
        assert config.blank_lines_between_sections == 0

    def test_compact_via_class_method(self) -> None:
        """FormattingConfig.compact should call PredefinedStyles.compact."""
        config = FormattingConfig.compact()

        assert config.indent_size == 2
        assert config.brace_style == BraceStyle.SAME_LINE
        assert config.space_before_colon is False


class TestPredefinedStylesReadable:
    """Test readable predefined style."""

    def test_readable_style_balanced_spacing(self) -> None:
        """Readable style should have balanced spacing."""
        config = PredefinedStyles.readable()

        assert config.indent_size == 4
        assert config.brace_style == BraceStyle.SAME_LINE
        assert config.space_before_colon is True
        assert config.space_after_colon is True
        assert config.space_around_operators is True
        assert config.space_after_comma is True
        assert config.string_style == StringStyle.ALIGNED
        assert config.blank_lines_between_rules == 1
        assert config.blank_lines_between_sections == 1


class TestPredefinedStylesVerbose:
    """Test verbose predefined style."""

    def test_verbose_style_maximum_readability(self) -> None:
        """Verbose style should maximize readability."""
        config = PredefinedStyles.verbose()

        assert config.indent_size == 4
        assert config.brace_style == BraceStyle.NEW_LINE
        assert config.space_before_colon is True
        assert config.space_after_colon is True
        assert config.space_around_operators is True
        assert config.space_after_comma is True
        assert config.string_style == StringStyle.TABULAR
        assert config.align_string_modifiers is True
        assert config.blank_lines_between_rules == 2
        assert config.blank_lines_between_sections == 1
        assert config.sort_imports is True
        assert config.sort_meta is True
        assert config.sort_strings is True

    def test_expanded_via_class_method(self) -> None:
        """FormattingConfig.expanded should call PredefinedStyles.verbose."""
        config = FormattingConfig.expanded()

        assert config.indent_size == 4
        assert config.brace_style == BraceStyle.NEW_LINE
        assert config.sort_imports is True


class TestPredefinedStylesYaraDefault:
    """Test YARA default predefined style."""

    def test_yara_default_style(self) -> None:
        """YARA default style should match typical YARA formatting."""
        config = PredefinedStyles.yara_default()

        assert config.indent_size == 2
        assert config.brace_style == BraceStyle.SAME_LINE
        assert config.space_before_colon is True
        assert config.space_after_colon is True
        assert config.space_around_operators is True
        assert config.space_after_comma is True
        assert config.string_style == StringStyle.ALIGNED


class TestFormattingConfigIndentation:
    """Test indentation configuration."""

    def test_spaces_indentation(self) -> None:
        """Config should support space-based indentation."""
        config = FormattingConfig(indent_style=IndentStyle.SPACES, indent_size=4)

        assert config.indent_style == IndentStyle.SPACES
        assert config.indent_size == 4

    def test_tabs_indentation(self) -> None:
        """Config should support tab-based indentation."""
        config = FormattingConfig(indent_style=IndentStyle.TABS, indent_size=1)

        assert config.indent_style == IndentStyle.TABS
        assert config.indent_size == 1

    def test_custom_indent_size(self) -> None:
        """Config should support custom indent sizes."""
        config2 = FormattingConfig(indent_size=2)
        config8 = FormattingConfig(indent_size=8)

        assert config2.indent_size == 2
        assert config8.indent_size == 8


class TestFormattingConfigBraceStyles:
    """Test brace style configuration."""

    def test_same_line_brace_style(self) -> None:
        """Config should support same-line brace style."""
        config = FormattingConfig(brace_style=BraceStyle.SAME_LINE)

        assert config.brace_style == BraceStyle.SAME_LINE

    def test_new_line_brace_style(self) -> None:
        """Config should support new-line brace style."""
        config = FormattingConfig(brace_style=BraceStyle.NEW_LINE)

        assert config.brace_style == BraceStyle.NEW_LINE

    def test_k_and_r_brace_style(self) -> None:
        """Config should support K&R brace style."""
        config = FormattingConfig(brace_style=BraceStyle.K_AND_R)

        assert config.brace_style == BraceStyle.K_AND_R


class TestFormattingConfigSpacing:
    """Test spacing configuration."""

    def test_spacing_options_all_enabled(self) -> None:
        """Config should support all spacing options enabled."""
        config = FormattingConfig(
            space_before_colon=True,
            space_after_colon=True,
            space_around_operators=True,
            space_after_comma=True,
        )

        assert config.space_before_colon is True
        assert config.space_after_colon is True
        assert config.space_around_operators is True
        assert config.space_after_comma is True

    def test_spacing_options_all_disabled(self) -> None:
        """Config should support all spacing options disabled."""
        config = FormattingConfig(
            space_before_colon=False,
            space_after_colon=False,
            space_around_operators=False,
            space_after_comma=False,
        )

        assert config.space_before_colon is False
        assert config.space_after_colon is False
        assert config.space_around_operators is False
        assert config.space_after_comma is False


class TestFormattingConfigStringStyles:
    """Test string style configuration."""

    def test_compact_string_style(self) -> None:
        """Config should support compact string style."""
        config = FormattingConfig(string_style=StringStyle.COMPACT)

        assert config.string_style == StringStyle.COMPACT

    def test_aligned_string_style(self) -> None:
        """Config should support aligned string style."""
        config = FormattingConfig(string_style=StringStyle.ALIGNED)

        assert config.string_style == StringStyle.ALIGNED

    def test_tabular_string_style(self) -> None:
        """Config should support tabular string style."""
        config = FormattingConfig(string_style=StringStyle.TABULAR)

        assert config.string_style == StringStyle.TABULAR

    def test_align_string_modifiers(self) -> None:
        """Config should support modifier alignment toggle."""
        enabled = FormattingConfig(align_string_modifiers=True)
        disabled = FormattingConfig(align_string_modifiers=False)

        assert enabled.align_string_modifiers is True
        assert disabled.align_string_modifiers is False


class TestFormattingConfigHexStyles:
    """Test hex string style configuration."""

    def test_lowercase_hex_style(self) -> None:
        """Config should support lowercase hex style."""
        config = FormattingConfig(hex_style=HexStyle.LOWERCASE)

        assert config.hex_style == HexStyle.LOWERCASE

    def test_uppercase_hex_style(self) -> None:
        """Config should support uppercase hex style."""
        config = FormattingConfig(hex_style=HexStyle.UPPERCASE)

        assert config.hex_style == HexStyle.UPPERCASE

    def test_hex_group_size_options(self) -> None:
        """Config should support various hex group sizes."""
        no_grouping = FormattingConfig(hex_group_size=0)
        group_by_4 = FormattingConfig(hex_group_size=4)
        group_by_8 = FormattingConfig(hex_group_size=8)

        assert no_grouping.hex_group_size == 0
        assert group_by_4.hex_group_size == 4
        assert group_by_8.hex_group_size == 8


class TestFormattingConfigLineBreaks:
    """Test line break configuration."""

    def test_blank_lines_between_rules(self) -> None:
        """Config should support blank lines between rules."""
        none_config = FormattingConfig(blank_lines_between_rules=0)
        single_config = FormattingConfig(blank_lines_between_rules=1)
        double_config = FormattingConfig(blank_lines_between_rules=2)

        assert none_config.blank_lines_between_rules == 0
        assert single_config.blank_lines_between_rules == 1
        assert double_config.blank_lines_between_rules == 2

    def test_blank_lines_between_sections(self) -> None:
        """Config should support blank lines between sections."""
        config = FormattingConfig(blank_lines_between_sections=1)

        assert config.blank_lines_between_sections == 1

    def test_max_line_length(self) -> None:
        """Config should support max line length configuration."""
        config80 = FormattingConfig(max_line_length=80)
        config120 = FormattingConfig(max_line_length=120)

        assert config80.max_line_length == 80
        assert config120.max_line_length == 120


class TestFormattingConfigSorting:
    """Test sorting configuration."""

    def test_sort_options_all_disabled(self) -> None:
        """Config should support all sorting disabled."""
        config = FormattingConfig(
            sort_imports=False, sort_rules=False, sort_meta=False, sort_strings=False
        )

        assert config.sort_imports is False
        assert config.sort_rules is False
        assert config.sort_meta is False
        assert config.sort_strings is False

    def test_sort_options_all_enabled(self) -> None:
        """Config should support all sorting enabled."""
        config = FormattingConfig(
            sort_imports=True, sort_rules=True, sort_meta=True, sort_strings=True
        )

        assert config.sort_imports is True
        assert config.sort_rules is True
        assert config.sort_meta is True
        assert config.sort_strings is True

    def test_selective_sorting(self) -> None:
        """Config should support selective sorting."""
        config = FormattingConfig(sort_imports=True, sort_meta=True)

        assert config.sort_imports is True
        assert config.sort_meta is True
        assert config.sort_rules is False
        assert config.sort_strings is False


class TestFormattingConfigSectionOrder:
    """Test section order configuration."""

    def test_default_section_order(self) -> None:
        """Config should have default section order."""
        config = FormattingConfig()

        assert config.section_order == ["meta", "strings", "condition"]

    def test_custom_section_order(self) -> None:
        """Config should support custom section order."""
        custom_order = ["condition", "meta", "strings"]
        config = FormattingConfig(section_order=custom_order)

        assert config.section_order == custom_order

    def test_section_order_modification(self) -> None:
        """Section order should be modifiable."""
        config = FormattingConfig()
        config.section_order = ["strings", "condition", "meta"]

        assert config.section_order == ["strings", "condition", "meta"]


class TestFormattingConfigComments:
    """Test comment configuration."""

    def test_preserve_comments_enabled(self) -> None:
        """Config should support comment preservation."""
        config = FormattingConfig(preserve_comments=True)

        assert config.preserve_comments is True

    def test_preserve_comments_disabled(self) -> None:
        """Config should support disabling comment preservation."""
        config = FormattingConfig(preserve_comments=False)

        assert config.preserve_comments is False

    def test_single_line_comment_style(self) -> None:
        """Config should support single-line comment style."""
        config = FormattingConfig(comment_style="//")

        assert config.comment_style == "//"

    def test_multi_line_comment_style(self) -> None:
        """Config should support multi-line comment style."""
        config = FormattingConfig(comment_style="/*")

        assert config.comment_style == "/*"
