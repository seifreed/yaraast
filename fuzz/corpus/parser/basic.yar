rule basic {
    strings:
        $text = "example" ascii wide
    condition:
        $text
}
