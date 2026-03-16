rule detect_login {
    meta:
        author = "sec"
        severity = "high"
    events:
        $e.metadata.event_type = "USER_LOGIN"
    match:
        $e over 5m
    condition:
        #e > 5
    outcome:
        $risk_score = 80
}
