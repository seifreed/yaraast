rule real_world_ransomware_note {
    meta:
        purpose = "Ransom note markers"
        source = "public malware-analysis pattern"

    strings:
        $bitcoin = "bitcoin" nocase ascii wide
        $decrypt = "decrypt" nocase ascii wide
        $files = "your files" nocase ascii wide
        $contact = "contact us" nocase ascii wide

    condition:
        3 of them
}
