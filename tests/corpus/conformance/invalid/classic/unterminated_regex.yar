rule unterminated_regex {
    strings:
        $a = /abc
    condition:
        $a
}
