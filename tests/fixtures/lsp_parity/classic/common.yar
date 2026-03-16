import "pe"

rule shared_rule {
    meta:
        author = "sec"
    strings:
        $a = "abc"
    condition:
        $a and pe.is_pe
}
