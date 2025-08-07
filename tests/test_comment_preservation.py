"""Test comment preservation in AST."""

from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator
from yaraast.parser.comment_aware_parser import CommentAwareParser


def test_single_line_comments() -> None:
    """Test single-line comment preservation."""
    yara_code = """
// This is a file header comment
// It explains the purpose of this rule

rule test_rule {
    // Meta comment
    meta:
        author = "test"  // inline comment
        description = "test rule"

    // String definitions
    strings:
        $str1 = "test"  // This is a test string
        $str2 = { 48 65 6C 6C 6F }  // Hello in hex

    condition:
        // Check for both strings
        $str1 and $str2
}
"""

    parser = CommentAwareParser()
    ast = parser.parse(yara_code)

    # Verify comments are attached
    assert len(ast.rules) == 1
    rule = ast.rules[0]
    assert len(rule.leading_comments) > 0
    assert "file header comment" in rule.leading_comments[0].text

    # Generate code with comments
    generator = CommentAwareCodeGenerator()
    output = generator.generate(ast)

    # Verify comments are preserved
    assert "file header comment" in output
    assert "inline comment" in output
    assert "This is a test string" in output
    assert "Hello in hex" in output
    assert "Check for both strings" in output


def test_multiline_comments() -> None:
    """Test multi-line comment preservation."""
    yara_code = """
/*
 * Multi-line header comment
 * Author: Test
 * Date: 2023
 */

rule multiline_test {
    /*
     * This section defines metadata
     */
    meta:
        version = 1

    /* String patterns to match */
    strings:
        $pattern = "test" /* important pattern */

    condition:
        $pattern
}
"""

    parser = CommentAwareParser()
    ast = parser.parse(yara_code)

    # Generate code with comments
    generator = CommentAwareCodeGenerator()
    output = generator.generate(ast)

    # Verify multiline comments are preserved
    assert "Multi-line header comment" in output
    assert "This section defines metadata" in output
    assert "String patterns to match" in output
    assert "important pattern" in output


def test_comment_preservation_disabled() -> None:
    """Test disabling comment preservation."""
    yara_code = """
// This comment should not appear

rule no_comments {
    meta:
        test = true  // Neither should this

    strings:
        $str = "test"

    condition:
        $str
}
"""

    parser = CommentAwareParser()
    ast = parser.parse(yara_code)

    # Generate without comments
    generator = CommentAwareCodeGenerator(preserve_comments=False)
    output = generator.generate(ast)

    # Verify no comments in output
    assert "//" not in output
    assert "/*" not in output


if __name__ == "__main__":
    test_single_line_comments()
    test_multiline_comments()
    test_comment_preservation_disabled()
    print("✓ All comment preservation tests passed")
