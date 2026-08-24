rule yarax_string_sets
{
    strings:
        $alpha = "alpha"
        $beta = "beta"
    condition:
        1 of ($alpha, $beta)
}
