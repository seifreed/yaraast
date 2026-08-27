rule real_world_powershell_encoded {
    meta:
        source = "YARA documentation and public rule corpus pattern (adapted)"
        family = "powershell"
    strings:
        $encoded = /powershell(\.exe)?\s+-enc(odedcommand)?\s+[a-z0-9+\/=]{20,}/ nocase
        $amsi = "AmsiUtils" ascii wide nocase
    condition:
        any of them
}
