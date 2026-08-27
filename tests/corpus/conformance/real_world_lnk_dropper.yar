rule real_world_lnk_dropper {
    meta:
        source = "YARA documentation and public rule corpus pattern (adapted)"
        family = "windows-lnk"
    strings:
        $lnk = ".lnk" ascii wide nocase
        $powershell = "powershell" ascii wide nocase
        $cmd = "cmd.exe /c" ascii wide nocase
        $mshta = "mshta" ascii wide nocase
    condition:
        $lnk and 1 of ($powershell, $cmd, $mshta)
}
