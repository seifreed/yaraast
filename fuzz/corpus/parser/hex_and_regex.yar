rule hex_and_regex {
    strings:
        $hex = { 4D 5A [0-16] 50 45 }
        $regex = /https?:\\/\\/[a-z0-9.-]+/ nocase
    condition:
        any of them
}
