rule real_world_webshell {
    meta:
        purpose = "Web shell command execution markers"
        source = "public malware-analysis pattern"

    strings:
        $cmd = "cmd.exe" nocase ascii wide
        $shell = "shell_exec" nocase ascii wide
        $passthru = "passthru" nocase ascii wide
        $upload = "multipart/form-data" nocase ascii wide

    condition:
        2 of ($shell, $passthru, $cmd) and $upload
}
