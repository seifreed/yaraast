global private rule gate
{
    condition:
        filesize < 50MB
}

rule tagged_with_meta : malware trojan
{
    meta:
        author = "conformance corpus"
        description = "exercises metadata and tags"
        version = 3
        active = true
    strings:
        $a = "marker"
    condition:
        $a
}

private rule helper
{
    strings:
        $h = "helper"
    condition:
        $h
}

rule references_other_rule
{
    condition:
        helper
}
