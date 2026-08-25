rule real_world_loader_hex {
    meta:
        purpose = "Portable executable loader markers"
        source = "public malware-analysis pattern"

    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $api = "VirtualAlloc" nocase ascii wide
        $thread = "CreateRemoteThread" nocase ascii wide

    condition:
        $mz at 0 and $pe and 1 of ($api, $thread)
}
