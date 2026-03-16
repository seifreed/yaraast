"""Documentation metadata for LSP providers."""

from __future__ import annotations

KEYWORD_DOCS: dict[str, str] = {
    "rule": "Defines a YARA rule. Each rule has a name, optional tags, meta section, strings section, and condition section.",
    "private": "Makes a rule private. Private rules are not reported by YARA, but can be used by other rules.",
    "global": "Makes a rule global. Global rules are applied to all files.",
    "meta": "Metadata section containing key-value pairs describing the rule.",
    "strings": "Section where string patterns are defined using $identifier syntax.",
    "condition": "Boolean expression that determines if the rule matches.",
    "import": "Import a YARA module to access additional functions and data structures.",
    "include": "Include another YARA file.",
    "and": "Logical AND operator",
    "or": "Logical OR operator",
    "not": "Logical NOT operator",
    "all": "Quantifier meaning 'all of'",
    "any": "Quantifier meaning 'any of'",
    "of": "Used in quantifier expressions like 'any of them'",
    "them": "Refers to all string identifiers in the current rule",
    "for": "Loop construct for iterating over collections",
    "in": "Membership operator or part of for loop",
    "at": "Tests if a string appears at a specific offset",
    "filesize": "Built-in variable containing the size of the file being scanned in bytes",
    "entrypoint": "Built-in variable containing the entry point address of PE files",
    "true": "Boolean true value",
    "false": "Boolean false value",
    "defined": "Tests if an expression is defined (useful for optional module fields)",
}

BUILTIN_DOCS: dict[str, str] = {
    "uint8": "```yara\nuint8(offset) -> integer\n```\n\nReads an unsigned 8-bit integer at the given offset.",
    "uint16": "```yara\nuint16(offset) -> integer\n```\n\nReads an unsigned 16-bit integer at the given offset (little-endian).",
    "uint32": "```yara\nuint32(offset) -> integer\n```\n\nReads an unsigned 32-bit integer at the given offset (little-endian).",
    "uint16le": "```yara\nuint16le(offset) -> integer\n```\n\nReads an unsigned 16-bit integer at the given offset (little-endian).",
    "uint32le": "```yara\nuint32le(offset) -> integer\n```\n\nReads an unsigned 32-bit integer at the given offset (little-endian).",
    "uint16be": "```yara\nuint16be(offset) -> integer\n```\n\nReads an unsigned 16-bit integer at the given offset (big-endian).",
    "uint32be": "```yara\nuint32be(offset) -> integer\n```\n\nReads an unsigned 32-bit integer at the given offset (big-endian).",
    "int8": "```yara\nint8(offset) -> integer\n```\n\nReads a signed 8-bit integer at the given offset.",
    "int16": "```yara\nint16(offset) -> integer\n```\n\nReads a signed 16-bit integer at the given offset (little-endian).",
    "int32": "```yara\nint32(offset) -> integer\n```\n\nReads a signed 32-bit integer at the given offset (little-endian).",
}

MODULE_DOCS: dict[str, str] = {
    "pe": "PE file format module. Provides access to PE headers, sections, imports, exports, and resources.",
    "elf": "ELF file format module. Provides access to ELF headers, sections, and segments.",
    "math": "Mathematical operations module. Provides entropy calculation and other math functions.",
    "hash": "Hash calculation module. Provides MD5, SHA1, SHA256, and checksum functions.",
    "dotnet": ".NET module. Provides access to .NET assembly metadata.",
    "time": "Time module. Provides functions for time-based operations.",
    "magic": "Magic module. Provides file type identification.",
    "console": "Console module. Provides console output for debugging.",
    "cuckoo": "Cuckoo sandbox integration module.",
    "string": "String manipulation module.",
}
