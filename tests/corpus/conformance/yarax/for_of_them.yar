rule yarax_quantifiers
{
    strings:
        $one = "one"
        $two = "two"
    condition:
        1 of them and any of them
}
