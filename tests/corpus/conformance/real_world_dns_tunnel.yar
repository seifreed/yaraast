rule real_world_dns_tunnel {
    meta:
        source = "YARA documentation and public rule corpus pattern (adapted)"
        family = "dns"
    strings:
        $long_label = /[a-z0-9]{40,}\.[a-z]{2,}/ nocase
        $txt = "TXT" ascii wide nocase
        $nslookup = "nslookup" ascii wide nocase
    condition:
        1 of ($txt, $nslookup) or $long_label
}
