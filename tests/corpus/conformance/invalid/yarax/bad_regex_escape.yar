rule bad_regex_escape {
    strings:
        $a = /a\q/
    condition:
        $a
}
