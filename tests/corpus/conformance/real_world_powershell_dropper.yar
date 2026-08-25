rule real_world_powershell_dropper {
    meta:
        purpose = "PowerShell downloader behavior"
        source = "public malware-analysis pattern"

    strings:
        $ps = "powershell" nocase ascii wide
        $download = "DownloadString" nocase ascii wide
        $encoded = "-enc" nocase ascii wide
        $hidden = "-windowstyle hidden" nocase ascii wide

    condition:
        $ps and 2 of ($download, $encoded, $hidden)
}
