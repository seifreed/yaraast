rule real_world_php_webshell {
    meta:
        source = "YARA documentation and public rule corpus pattern (adapted)"
        family = "webshell"
    strings:
        $php = "<?php" ascii nocase
        $eval = "eval(" ascii nocase
        $decode = "base64_decode" ascii nocase
        $request = "$_REQUEST" ascii
    condition:
        $php and 2 of ($eval, $decode, $request)
}
