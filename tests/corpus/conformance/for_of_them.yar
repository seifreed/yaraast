rule any_string_match
{
    strings:
        $a = "alpha"
        $b = "beta"
        $c = "gamma"
    condition:
        any of them and 2 of ($a, $b, $c)
}

private rule private_tagged
{
    strings:
        $marker = "private"
    condition:
        $marker
}
