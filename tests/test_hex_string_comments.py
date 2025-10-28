"""Tests for hex string comment handling.

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3

These tests verify that the lexer correctly handles comments containing
braces inside hex strings, which previously caused parsing errors.
"""

from __future__ import annotations

from yaraast.ast.strings import HexByte, HexJump, HexNibble, HexString, HexWildcard
from yaraast.parser.parser import Parser


class TestHexStringComments:
    """Tests for comments inside hex strings."""

    def test_hex_string_with_single_line_comment_containing_brace(self) -> None:
        """Single-line comment with brace should not confuse lexer."""
        yara_code = """rule Test {
            strings:
                $a = {
                    4? 63 [3]        // comment with {brace}
                    4? 8b [2-6]
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        assert len(ast.rules[0].strings) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)
        assert string_def.identifier == "$a"

        # Verify tokens parsed correctly: 4? 63 [3] 4? 8b [2-6]
        assert len(string_def.tokens) == 6
        # First line: 4? 63 [3]
        assert isinstance(string_def.tokens[0], HexNibble)
        assert string_def.tokens[0].high is True
        assert string_def.tokens[0].value == 4

        assert isinstance(string_def.tokens[1], HexByte)
        assert string_def.tokens[1].value == 0x63

        assert isinstance(string_def.tokens[2], HexJump)
        assert string_def.tokens[2].min_jump == 3
        assert string_def.tokens[2].max_jump == 3

        # Second line: 4? 8b [2-6]
        assert isinstance(string_def.tokens[3], HexNibble)
        assert string_def.tokens[3].high is True
        assert string_def.tokens[3].value == 4

        assert isinstance(string_def.tokens[4], HexByte)
        assert string_def.tokens[4].value == 0x8B

        assert isinstance(string_def.tokens[5], HexJump)
        assert string_def.tokens[5].min_jump == 2
        assert string_def.tokens[5].max_jump == 6

    def test_hex_string_with_multiline_comment_containing_brace(self) -> None:
        """Multi-line comment with brace should not confuse lexer."""
        yara_code = """rule Test {
            strings:
                $a = {
                    4? 63 [3]        /* comment with {brace} */
                    4? 8b [2-6]
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        assert len(ast.rules[0].strings) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)
        assert string_def.identifier == "$a"

        # Verify tokens parsed correctly: 4? 63 [3] 4? 8b [2-6]
        assert len(string_def.tokens) == 6
        assert isinstance(string_def.tokens[0], HexNibble)
        assert isinstance(string_def.tokens[1], HexByte)
        assert isinstance(string_def.tokens[2], HexJump)
        assert isinstance(string_def.tokens[3], HexNibble)
        assert isinstance(string_def.tokens[4], HexByte)
        assert isinstance(string_def.tokens[5], HexJump)

    def test_hex_string_with_multiple_comments_with_braces(self) -> None:
        """Multiple comments with braces should all be handled correctly."""
        yara_code = """rule Test {
            strings:
                $a = {
                    4? 63  // first {comment}
                    FF     /* second {comment} */
                    AA BB  // third {brace} here
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        assert len(ast.rules[0].strings) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify all hex bytes parsed correctly: 4? 63, FF, AA BB
        assert len(string_def.tokens) == 5
        assert isinstance(string_def.tokens[0], HexNibble)
        assert string_def.tokens[0].value == 4

        assert isinstance(string_def.tokens[1], HexByte)
        assert string_def.tokens[1].value == 0x63

        assert isinstance(string_def.tokens[2], HexByte)
        assert string_def.tokens[2].value == 0xFF

        assert isinstance(string_def.tokens[3], HexByte)
        assert string_def.tokens[3].value == 0xAA

        assert isinstance(string_def.tokens[4], HexByte)
        assert string_def.tokens[4].value == 0xBB

    def test_hex_string_with_nested_braces_in_comment(self) -> None:
        """Comment with multiple levels of braces should be handled."""
        yara_code = """rule Test {
            strings:
                $a = {
                    48 65  // nested {{braces}}
                    6C 6C
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify tokens
        assert len(string_def.tokens) == 4
        assert all(isinstance(token, HexByte) for token in string_def.tokens)
        assert string_def.tokens[0].value == 0x48
        assert string_def.tokens[1].value == 0x65
        assert string_def.tokens[2].value == 0x6C
        assert string_def.tokens[3].value == 0x6C

    def test_hex_string_without_comments(self) -> None:
        """Hex string without comments should still work (regression test)."""
        yara_code = """rule Test {
            strings:
                $a = { 48 65 6C 6C 6F }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify tokens: "Hello"
        assert len(string_def.tokens) == 5
        expected_values = [0x48, 0x65, 0x6C, 0x6C, 0x6F]
        for i, expected in enumerate(expected_values):
            assert isinstance(string_def.tokens[i], HexByte)
            assert string_def.tokens[i].value == expected

    def test_hex_string_with_closing_brace_in_comment(self) -> None:
        """Comment containing closing brace should not end hex string."""
        yara_code = """rule Test {
            strings:
                $a = {
                    AA BB  // closing } brace in comment
                    CC DD
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify all 4 bytes parsed correctly
        assert len(string_def.tokens) == 4
        assert string_def.tokens[0].value == 0xAA
        assert string_def.tokens[1].value == 0xBB
        assert string_def.tokens[2].value == 0xCC
        assert string_def.tokens[3].value == 0xDD

    def test_real_world_example_from_harfanglab(self) -> None:
        """Real-world example from HarfangLab that caused the bug."""
        yara_code = """rule Test {
            strings:
                $s_packer_xor = {
                    4? 63 [3]                       // movsxd  rax, dword [rsp+0x50 {var_78}]
                    4? 8b [2-6]                     // mov     rcx, qword [rsp+0xd0 {arg_8}]
                }
            condition:
                $s_packer_xor
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        assert ast.rules[0].name == "Test"
        assert len(ast.rules[0].strings) == 1

        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)
        assert string_def.identifier == "$s_packer_xor"

        # Verify structure: 4? 63 [3] 4? 8b [2-6]
        assert len(string_def.tokens) == 6

        # First pattern: 4? 63 [3]
        assert isinstance(string_def.tokens[0], HexNibble)
        assert string_def.tokens[0].high is True
        assert string_def.tokens[0].value == 4

        assert isinstance(string_def.tokens[1], HexByte)
        assert string_def.tokens[1].value == 0x63

        assert isinstance(string_def.tokens[2], HexJump)
        assert string_def.tokens[2].min_jump == 3
        assert string_def.tokens[2].max_jump == 3

        # Second pattern: 4? 8b [2-6]
        assert isinstance(string_def.tokens[3], HexNibble)
        assert string_def.tokens[3].high is True
        assert string_def.tokens[3].value == 4

        assert isinstance(string_def.tokens[4], HexByte)
        assert string_def.tokens[4].value == 0x8B

        assert isinstance(string_def.tokens[5], HexJump)
        assert string_def.tokens[5].min_jump == 2
        assert string_def.tokens[5].max_jump == 6

    def test_hex_string_comment_with_brackets_and_braces(self) -> None:
        """Comment with both brackets and braces should work."""
        yara_code = """rule Test {
            strings:
                $a = {
                    48 65  // array[index] {brace}
                    6C 6F
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify tokens
        assert len(string_def.tokens) == 4
        assert string_def.tokens[0].value == 0x48
        assert string_def.tokens[1].value == 0x65
        assert string_def.tokens[2].value == 0x6C
        assert string_def.tokens[3].value == 0x6F

    def test_hex_string_multiline_comment_spanning_multiple_lines(self) -> None:
        """Multi-line comment spanning several lines with braces."""
        yara_code = """rule Test {
            strings:
                $a = {
                    48 65  /* This is a comment
                              that spans multiple lines
                              and contains {braces} */
                    6C 6F
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify tokens
        assert len(string_def.tokens) == 4
        assert isinstance(string_def.tokens[0], HexByte)
        assert string_def.tokens[0].value == 0x48
        assert isinstance(string_def.tokens[1], HexByte)
        assert string_def.tokens[1].value == 0x65
        assert isinstance(string_def.tokens[2], HexByte)
        assert string_def.tokens[2].value == 0x6C
        assert isinstance(string_def.tokens[3], HexByte)
        assert string_def.tokens[3].value == 0x6F

    def test_hex_string_empty_comment(self) -> None:
        """Empty comments should not break parsing."""
        yara_code = """rule Test {
            strings:
                $a = {
                    48 65  //
                    6C 6F  /* */
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify tokens
        assert len(string_def.tokens) == 4
        assert string_def.tokens[0].value == 0x48
        assert string_def.tokens[1].value == 0x65
        assert string_def.tokens[2].value == 0x6C
        assert string_def.tokens[3].value == 0x6F

    def test_hex_string_with_wildcard_and_comment_with_brace(self) -> None:
        """Hex wildcard with comment containing brace."""
        yara_code = """rule Test {
            strings:
                $a = {
                    48 ??  // wildcard {here}
                    ?? 6F
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify tokens: byte, wildcard, wildcard, byte
        assert len(string_def.tokens) == 4
        assert isinstance(string_def.tokens[0], HexByte)
        assert string_def.tokens[0].value == 0x48

        assert isinstance(string_def.tokens[1], HexWildcard)
        assert isinstance(string_def.tokens[2], HexWildcard)

        assert isinstance(string_def.tokens[3], HexByte)
        assert string_def.tokens[3].value == 0x6F

    def test_hex_string_with_jump_and_comment_with_brace(self) -> None:
        """Hex jump with comment containing brace."""
        yara_code = """rule Test {
            strings:
                $a = {
                    48 [4-8]  /* jump {range} */
                    6F
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify tokens: byte, jump, byte
        assert len(string_def.tokens) == 3
        assert isinstance(string_def.tokens[0], HexByte)
        assert string_def.tokens[0].value == 0x48

        assert isinstance(string_def.tokens[1], HexJump)
        assert string_def.tokens[1].min_jump == 4
        assert string_def.tokens[1].max_jump == 8

        assert isinstance(string_def.tokens[2], HexByte)
        assert string_def.tokens[2].value == 0x6F

    def test_hex_string_with_mixed_comment_styles(self) -> None:
        """Mix of single-line and multi-line comments with braces."""
        yara_code = """rule Test {
            strings:
                $a = {
                    48 65  // single {line}
                    6C 6C  /* multi {line} */
                    6F 21  // another {one}
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify all 6 bytes parsed correctly
        assert len(string_def.tokens) == 6
        expected_values = [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21]
        for i, expected in enumerate(expected_values):
            assert isinstance(string_def.tokens[i], HexByte)
            assert string_def.tokens[i].value == expected

    def test_hex_string_with_low_nibble_and_comment(self) -> None:
        """Low nibble pattern (?X) with comment containing brace."""
        yara_code = """rule Test {
            strings:
                $a = {
                    ?5 ?A  // low nibbles {pattern}
                    48 6F
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify tokens: low nibble, low nibble, byte, byte
        assert len(string_def.tokens) == 4

        assert isinstance(string_def.tokens[0], HexNibble)
        assert string_def.tokens[0].high is False
        assert string_def.tokens[0].value == 5

        assert isinstance(string_def.tokens[1], HexNibble)
        assert string_def.tokens[1].high is False
        assert string_def.tokens[1].value == 0xA

        assert isinstance(string_def.tokens[2], HexByte)
        assert string_def.tokens[2].value == 0x48

        assert isinstance(string_def.tokens[3], HexByte)
        assert string_def.tokens[3].value == 0x6F

    def test_hex_string_complex_real_world_scenario(self) -> None:
        """Complex real-world hex string with multiple comment types."""
        yara_code = """rule ComplexPattern {
            strings:
                $complex = {
                    // Signature header
                    4D 5A       // MZ header {DOS}
                    [0-100]     // Variable offset
                    50 45       /* PE signature {magic} */
                    00 00       // padding
                    4C 01       // Machine type {x86}
                    [2-4]       /* Section count {variable} */
                    ?? ??       // Timestamp (wildcard)
                }
            condition:
                $complex
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        assert ast.rules[0].name == "ComplexPattern"
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)
        assert string_def.identifier == "$complex"

        # Verify structure: MZ, jump, PE, 00, 00, 4C, 01, jump, wildcard, wildcard
        assert len(string_def.tokens) == 12

        # MZ header
        assert isinstance(string_def.tokens[0], HexByte)
        assert string_def.tokens[0].value == 0x4D
        assert isinstance(string_def.tokens[1], HexByte)
        assert string_def.tokens[1].value == 0x5A

        # Variable offset jump
        assert isinstance(string_def.tokens[2], HexJump)
        assert string_def.tokens[2].min_jump == 0
        assert string_def.tokens[2].max_jump == 100

        # PE signature
        assert isinstance(string_def.tokens[3], HexByte)
        assert string_def.tokens[3].value == 0x50
        assert isinstance(string_def.tokens[4], HexByte)
        assert string_def.tokens[4].value == 0x45

        # Padding
        assert isinstance(string_def.tokens[5], HexByte)
        assert string_def.tokens[5].value == 0x00
        assert isinstance(string_def.tokens[6], HexByte)
        assert string_def.tokens[6].value == 0x00

        # Machine type: 4C 01
        assert isinstance(string_def.tokens[7], HexByte)
        assert string_def.tokens[7].value == 0x4C

        assert isinstance(string_def.tokens[8], HexByte)
        assert string_def.tokens[8].value == 0x01

        # Section count jump
        assert isinstance(string_def.tokens[9], HexJump)
        assert string_def.tokens[9].min_jump == 2
        assert string_def.tokens[9].max_jump == 4

        # Wildcards
        assert isinstance(string_def.tokens[10], HexWildcard)
        assert isinstance(string_def.tokens[11], HexWildcard)

    def test_hex_string_comment_at_end_with_brace(self) -> None:
        """Comment at the very end of hex string with brace."""
        yara_code = """rule Test {
            strings:
                $a = {
                    48 65 6C 6F  // end comment {final}
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify all tokens parsed
        assert len(string_def.tokens) == 4
        assert string_def.tokens[0].value == 0x48
        assert string_def.tokens[1].value == 0x65
        assert string_def.tokens[2].value == 0x6C
        assert string_def.tokens[3].value == 0x6F

    def test_hex_string_comment_at_start_with_brace(self) -> None:
        """Comment at the very start of hex string with brace."""
        yara_code = """rule Test {
            strings:
                $a = {
                    // start comment {initial}
                    48 65 6C 6F
                }
            condition:
                $a
        }"""

        parser = Parser(yara_code)
        ast = parser.parse()

        assert len(ast.rules) == 1
        string_def = ast.rules[0].strings[0]
        assert isinstance(string_def, HexString)

        # Verify all tokens parsed
        assert len(string_def.tokens) == 4
        assert string_def.tokens[0].value == 0x48
        assert string_def.tokens[1].value == 0x65
        assert string_def.tokens[2].value == 0x6C
        assert string_def.tokens[3].value == 0x6F
