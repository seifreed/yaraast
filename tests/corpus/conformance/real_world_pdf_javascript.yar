rule real_world_pdf_javascript {
    meta:
        source = "YARA documentation and public rule corpus pattern (adapted)"
        family = "pdf"
    strings:
        $javascript = "/JavaScript" ascii nocase
        $open_action = "/OpenAction" ascii nocase
        $eval = "eval(" ascii wide nocase
    condition:
        2 of them
}
