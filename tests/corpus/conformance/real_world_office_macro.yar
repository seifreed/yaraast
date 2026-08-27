rule real_world_office_macro {
    meta:
        source = "YARA documentation and public rule corpus pattern (adapted)"
        family = "office"
    strings:
        $auto_open = "AutoOpen" ascii wide nocase
        $create_object = "CreateObject" ascii wide nocase
        $wscript = "WScript.Shell" ascii wide nocase
        $document_open = "Document_Open" ascii wide nocase
    condition:
        2 of them
}
