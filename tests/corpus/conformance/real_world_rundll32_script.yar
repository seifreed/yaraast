rule real_world_rundll32_script {
    meta:
        source = "YARA documentation and public rule corpus pattern (adapted)"
        family = "windows-loader"
    strings:
        $rundll32 = "rundll32" ascii wide nocase
        $javascript = "javascript:" ascii wide nocase
        $scrobj = "scrobj.dll" ascii wide nocase
    condition:
        $rundll32 and 1 of ($javascript, $scrobj)
}
