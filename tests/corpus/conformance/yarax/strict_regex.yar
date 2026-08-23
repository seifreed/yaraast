rule strict_regex {
    strings:
        $pattern = /abc\{/
    condition:
        $pattern
}
