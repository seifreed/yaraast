"""Test YARA evaluation API."""

from yaraast.evaluation import MockMath, MockModuleRegistry, MockPE, StringMatcher, YaraEvaluator
from yaraast.parser import Parser


class TestStringMatcher:
    """Test string matching functionality."""

    def test_plain_string_match(self) -> None:
        """Test plain string matching."""
        from yaraast.ast.strings import PlainString

        matcher = StringMatcher()
        data = b"Hello World! This is a test string."

        # Create string definition
        string1 = PlainString(identifier="$a", value="Hello", modifiers=[])
        string2 = PlainString(identifier="$b", value="test", modifiers=[])
        string3 = PlainString(identifier="$c", value="missing", modifiers=[])

        # Match strings
        matches = matcher.match_all(data, [string1, string2, string3])

        # Verify matches
        assert "$a" in matches
        assert "$b" in matches
        assert "$c" in matches
        assert len(matches["$a"]) == 1
        assert len(matches["$b"]) == 1
        assert len(matches["$c"]) == 0

        # Check offsets
        assert matches["$a"][0].offset == 0
        assert matches["$b"][0].offset == 23  # "test" appears at position 23

    def test_nocase_modifier(self) -> None:
        """Test case-insensitive matching."""
        from yaraast.ast.strings import PlainString, StringModifier

        matcher = StringMatcher()
        data = b"HELLO world"

        # Case-sensitive (no match)
        string1 = PlainString(identifier="$a", value="hello", modifiers=[])
        matches = matcher.match_all(data, [string1])
        assert len(matches["$a"]) == 0

        # Case-insensitive (match)
        string2 = PlainString(
            identifier="$b",
            value="hello",
            modifiers=[StringModifier(name="nocase")],
        )
        matches = matcher.match_all(data, [string2])
        assert len(matches["$b"]) == 1

    def test_wide_modifier(self) -> None:
        """Test wide string matching."""
        from yaraast.ast.strings import PlainString, StringModifier

        matcher = StringMatcher()
        # UTF-16LE encoded "Hello"
        data = b"H\x00e\x00l\x00l\x00o\x00"

        string = PlainString(
            identifier="$a",
            value="Hello",
            modifiers=[StringModifier(name="wide")],
        )
        matches = matcher.match_all(data, [string])
        assert len(matches["$a"]) == 1

    def test_hex_string_match(self) -> None:
        """Test hex string matching."""
        from yaraast.ast.strings import HexByte, HexString

        matcher = StringMatcher()
        data = b"\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64"  # "Hello World"

        # { 48 65 6c 6c 6f }  # "Hello"
        hex_string = HexString(
            identifier="$hex1",
            tokens=[
                HexByte(value=0x48),
                HexByte(value=0x65),
                HexByte(value=0x6C),
                HexByte(value=0x6C),
                HexByte(value=0x6F),
            ],
        )

        matches = matcher.match_all(data, [hex_string])
        assert len(matches["$hex1"]) == 1
        assert matches["$hex1"][0].offset == 0

    def test_hex_wildcard(self) -> None:
        """Test hex string with wildcards."""
        from yaraast.ast.strings import HexByte, HexString, HexWildcard

        matcher = StringMatcher()
        data = b"\x48\x65\x6c\x6c\x6f"

        # { 48 ?? 6c ?? 6f }
        hex_string = HexString(
            identifier="$hex1",
            tokens=[
                HexByte(value=0x48),
                HexWildcard(),
                HexByte(value=0x6C),
                HexWildcard(),
                HexByte(value=0x6F),
            ],
        )

        matches = matcher.match_all(data, [hex_string])
        assert len(matches["$hex1"]) == 1

    def test_regex_string(self) -> None:
        """Test regex string matching."""
        from yaraast.ast.strings import RegexString

        matcher = StringMatcher()
        data = b"The quick brown fox jumps over the lazy dog"

        # /f[oO]x/
        regex = RegexString(identifier="$re1", regex="f[oO]x", modifiers=[])

        matches = matcher.match_all(data, [regex])
        assert len(matches["$re1"]) == 1
        assert matches["$re1"][0].offset == 16  # Position of "fox"


class TestYaraEvaluator:
    """Test YARA condition evaluation."""

    def test_simple_string_match(self) -> None:
        """Test simple string matching rule."""
        parser = Parser()
        rule_text = """
        rule test_rule {
            strings:
                $a = "hello"
                $b = "world"
            condition:
                $a and $b
        }
        """
        ast = parser.parse(rule_text)

        # Test data containing both strings
        data = b"hello world"
        evaluator = YaraEvaluator(data)
        results = evaluator.evaluate_file(ast)

        assert results["test_rule"] is True

        # Test data missing one string
        data2 = b"hello there"
        evaluator2 = YaraEvaluator(data2)
        results2 = evaluator2.evaluate_file(ast)

        assert results2["test_rule"] is False

    def test_string_count(self) -> None:
        """Test string count functionality."""
        parser = Parser()
        rule_text = """
        rule count_test {
            strings:
                $a = "test"
            condition:
                #a > 2
        }
        """
        ast = parser.parse(rule_text)

        # Data with 3 occurrences
        data = b"test this test is a test"
        evaluator = YaraEvaluator(data)
        results = evaluator.evaluate_file(ast)

        assert results["count_test"] is True

    def test_string_at(self) -> None:
        """Test string at specific offset."""
        parser = Parser()
        rule_text = """
        rule at_test {
            strings:
                $mz = "MZ"
            condition:
                $mz at 0
        }
        """
        ast = parser.parse(rule_text)

        # MZ at beginning
        data1 = b"MZ\x90\x00\x03"
        evaluator1 = YaraEvaluator(data1)
        assert evaluator1.evaluate_file(ast)["at_test"] is True

        # MZ not at beginning
        data2 = b"\x00\x00MZ\x90"
        evaluator2 = YaraEvaluator(data2)
        assert evaluator2.evaluate_file(ast)["at_test"] is False

    def test_of_expression(self) -> None:
        """Test 'of' expression."""
        parser = Parser()
        rule_text = """
        rule of_test {
            strings:
                $a = "one"
                $b = "two"
                $c = "three"
            condition:
                2 of them
        }
        """
        ast = parser.parse(rule_text)

        # Data with 2 strings
        data = b"one and two"
        evaluator = YaraEvaluator(data)
        assert evaluator.evaluate_file(ast)["of_test"] is True

        # Data with only 1 string
        data2 = b"only one"
        evaluator2 = YaraEvaluator(data2)
        assert evaluator2.evaluate_file(ast)["of_test"] is False

    def test_filesize(self) -> None:
        """Test filesize built-in."""
        parser = Parser()
        rule_text = """
        rule size_test {
            condition:
                filesize > 10 and filesize < 100
        }
        """
        ast = parser.parse(rule_text)

        # 50 bytes
        data = b"a" * 50
        evaluator = YaraEvaluator(data)
        assert evaluator.evaluate_file(ast)["size_test"] is True

        # 5 bytes (too small)
        data2 = b"small"
        evaluator2 = YaraEvaluator(data2)
        assert evaluator2.evaluate_file(ast)["size_test"] is False

    def test_integer_functions(self) -> None:
        """Test integer reading functions."""
        parser = Parser()
        rule_text = """
        rule int_test {
            condition:
                uint16(0) == 0x5A4D and
                uint32(4) == 0x12345678
        }
        """
        ast = parser.parse(rule_text)

        # Little-endian data
        data = b"\x4d\x5a\x00\x00\x78\x56\x34\x12"
        evaluator = YaraEvaluator(data)
        assert evaluator.evaluate_file(ast)["int_test"] is True

    def test_pe_module(self) -> None:
        """Test PE module functionality."""
        parser = Parser()
        rule_text = """
        import "pe"

        rule pe_test {
            condition:
                pe.is_pe and
                pe.machine == 0x14c
        }
        """
        ast = parser.parse(rule_text)

        # Minimal PE header
        data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"  # PE offset at 0x40
        data += b"PE\x00\x00"  # PE signature
        data += b"\x4c\x01"  # Machine type (0x14c)
        data += b"\x00" * 100  # Padding

        evaluator = YaraEvaluator(data)
        results = evaluator.evaluate_file(ast)

        assert results["pe_test"] is True

    def test_math_module(self) -> None:
        """Test math module functionality."""
        parser = Parser()
        rule_text = """
        import "math"

        rule entropy_test {
            condition:
                math.entropy(0, 100) > 3.0
        }
        """
        ast = parser.parse(rule_text)

        # High entropy data (pseudo-random pattern for testing)
        # Using deterministic pattern instead of random for consistent testing
        data = bytes((i * 37 + 123) % 256 for i in range(200))

        evaluator = YaraEvaluator(data)
        results = evaluator.evaluate_file(ast)

        # Random data should have high entropy
        assert results["entropy_test"] is True

    def test_for_expression(self) -> None:
        """Test for loop expression."""
        parser = Parser()
        rule_text = """
        rule for_test {
            strings:
                $a = "test"
            condition:
                for all i in (0..2): ( @a[i] < 100 )
        }
        """
        ast = parser.parse(rule_text)

        # Multiple matches within first 100 bytes
        data = b"test " * 3 + b"x" * 100
        evaluator = YaraEvaluator(data)
        results = evaluator.evaluate_file(ast)

        assert results["for_test"] is True

    def test_module_alias(self) -> None:
        """Test module import with alias."""
        parser = Parser()
        rule_text = """
        import "pe" as windows

        rule alias_test {
            condition:
                windows.is_pe
        }
        """
        ast = parser.parse(rule_text)

        # PE file
        data = b"MZ" + b"\x00" * 100
        evaluator = YaraEvaluator(data)
        results = evaluator.evaluate_file(ast)

        assert results["alias_test"] is True

    def test_complex_condition(self) -> None:
        """Test complex nested conditions."""
        parser = Parser()
        rule_text = """
        rule complex {
            strings:
                $a = "foo"
                $b = "bar"
                $c = /[0-9]+/
            condition:
                ($a or $b) and $c and
                (@a < @b or not defined $b) and
                filesize > 10
        }
        """
        ast = parser.parse(rule_text)

        data = b"foo something 12345 bar"
        evaluator = YaraEvaluator(data)
        results = evaluator.evaluate_file(ast)

        assert results["complex"] is True


class TestMockModules:
    """Test mock module implementations."""

    def test_mock_pe(self) -> None:
        """Test MockPE functionality."""
        # Valid PE data
        # MZ header (64 bytes total)
        pe_data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"  # PE offset at 0x3c
        # PE header at offset 0x40 (64 bytes)
        pe_data += b"PE\x00\x00"  # PE signature
        pe_data += b"\x4c\x01"  # Machine (0x14c = i386)
        pe_data += b"\x03\x00"  # Number of sections
        pe_data += b"\x00\x00\x00\x00"  # Timestamp
        pe_data += b"\x00" * 8  # Symbol table pointer and number of symbols
        pe_data += b"\x00\x00"  # Size of optional header
        pe_data += b"\x00\x20"  # Characteristics (DLL flag = 0x2000)

        pe = MockPE(pe_data)

        assert pe.is_pe is True
        assert pe.machine == 0x14C
        assert pe.number_of_sections == 3
        assert pe.is_dll is True  # 0x2000 bit is set

    def test_mock_math(self) -> None:
        """Test MockMath functionality."""
        data = b"\x00" * 100
        math = MockMath(data)

        # Test basic functions
        assert math.abs(-5) == 5
        assert math.min(3, 7) == 3
        assert math.max(3, 7) == 7
        assert math.to_string(255, 16) == "ff"
        assert math.to_number("0xff") == 255

        # Test entropy
        # All zeros should have entropy of 0
        assert abs(math.entropy(0, 50) - 0.0) < 1e-9

    def test_module_registry(self) -> None:
        """Test module registry."""
        registry = MockModuleRegistry()
        data = b"test data"

        # Create modules
        pe = registry.create_module("pe", data)
        math = registry.create_module("math", data)

        assert pe is not None
        assert math is not None
        assert isinstance(pe, MockPE)
        assert isinstance(math, MockMath)

        # Get existing modules
        assert registry.get_module("pe") is pe
        assert registry.get_module("math") is math
