rule real_world_elf_persistence {
    meta:
        source = "YARA documentation and public rule corpus pattern (adapted)"
        family = "elf"
    strings:
        $cron = "/etc/cron" ascii
        $ld_preload = "LD_PRELOAD" ascii
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0 and 1 of ($cron, $ld_preload)
}
