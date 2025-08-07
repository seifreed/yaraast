// YARA-L 2.0 Example Rules for Google Chronicle
// These examples demonstrate various YARA-L features supported by yaraast

// Basic single-event rule
rule suspicious_login_attempts {
    meta:
        author = "Security Team"
        description = "Detect multiple failed login attempts"
        severity = "Medium"

    events:
        $e.metadata.event_type = "USER_LOGIN"
        $e.security_result.action = "BLOCK"
        $e.principal.user.userid = $userid

    match:
        $userid over 5m

    condition:
        #e > 5
}

// Multi-event correlation rule
rule lateral_movement_detection {
    meta:
        author = "SOC Team"
        description = "Detect potential lateral movement"
        severity = "High"

    events:
        // Initial authentication
        $auth.metadata.event_type = "USER_LOGIN"
        $auth.security_result.action = "ALLOW"
        $auth.principal.user.userid = $user

        // Process launch after auth
        $proc.metadata.event_type = "PROCESS_LAUNCH"
        $proc.principal.user.userid = $user
        $proc.target.process.file.full_path = /.*\\(psexec|wmic|powershell)\.exe/ nocase

        // Network connection
        $net.metadata.event_type = "NETWORK_CONNECTION"
        $net.principal.user.userid = $user
        $net.target.port in [445, 135, 139]

    match:
        $user over 10m

    condition:
        $auth and $proc and $net
}

// Rule with aggregation functions
rule data_exfiltration_detection {
    meta:
        author = "Threat Intel Team"
        severity = "Critical"
        mitre_attack = "T1048"

    events:
        $e.metadata.event_type = "NETWORK_CONNECTION"
        $e.principal.hostname = $hostname
        $e.network.sent_bytes > 0
        $e.target.ip not in %internal_ip_ranges%

    match:
        $hostname over 1h

    outcome:
        $total_bytes = sum($e.network.sent_bytes)
        $unique_destinations = count_distinct($e.target.ip)
        $max_transfer = max($e.network.sent_bytes)
        $all_ports = array_distinct($e.target.port)

    condition:
        $total_bytes > 1000000000 and  // 1GB
        $unique_destinations > 5
}

// Rule with reference lists and CIDR
rule command_and_control_detection {
    meta:
        author = "CTI Team"
        description = "Detect C2 communication patterns"

    events:
        $dns.metadata.event_type = "NETWORK_DNS"
        $dns.network.dns.questions.name in %known_c2_domains%

        $http.metadata.event_type = "NETWORK_HTTP"
        $http.network.http.user_agent in %suspicious_user_agents%
        not cidr($http.target.ip, "10.0.0.0/8")
        not cidr($http.target.ip, "192.168.0.0/16")

    match:
        $hostname over 24h

    condition:
        ($dns or $http) and #dns > 10
}

// Advanced rule with conditional outcomes
rule privilege_escalation_detection {
    meta:
        author = "Detection Engineering"
        description = "Detect privilege escalation attempts"

    events:
        $e1.metadata.event_type = "PROCESS_LAUNCH"
        $e1.target.process.file.full_path = /.*\\(net|net1)\.exe/ nocase
        $e1.target.process.command_line = /.*localgroup\s+administrators/ nocase

        $e2.metadata.event_type = "USER_UNCATEGORIZED"
        $e2.security_result.summary = /privilege.*escalat/ nocase

    match:
        $hostname over 15m

    outcome:
        $risk_score = if(#e1 > 10, 90, if(#e1 > 5, 70, 50))
        $severity = if($risk_score >= 90, "CRITICAL",
                      if($risk_score >= 70, "HIGH", "MEDIUM"))
        $unique_users = count_distinct($e1.principal.user.userid)

    condition:
        ($e1 or $e2) and $risk_score >= 70
}

// Rule with time-based correlation
rule ransomware_behavior_detection {
    meta:
        author = "IR Team"
        description = "Detect ransomware-like file modification patterns"
        severity = "Critical"

    events:
        // File modification events
        $modify.metadata.event_type = "FILE_MODIFICATION"
        $modify.target.file.full_path = /.*\.(doc|xls|pdf|jpg|png)/ nocase
        $modify.principal.process.pid = $pid

        // File creation events (encrypted files)
        $create.metadata.event_type = "FILE_CREATION"
        $create.target.file.full_path = /.*\.(locked|enc|encrypted|crypto)/ nocase
        $create.principal.process.pid = $pid

        // File deletion events
        $delete.metadata.event_type = "FILE_DELETION"
        $delete.principal.process.pid = $pid

    match:
        $pid over 5m

    outcome:
        $files_modified = count($modify.target.file.full_path)
        $files_created = count($create.target.file.full_path)
        $files_deleted = count($delete.target.file.full_path)
        $first_activity = earliest($modify.metadata.event_timestamp)
        $last_activity = latest($create.metadata.event_timestamp)

    condition:
        $files_modified > 100 and
        $files_created > 100 and
        ($files_deleted > 50 or $files_modified > 500)
}

// Rule with regex and string matching
rule webshell_detection {
    meta:
        author = "Web Security Team"
        description = "Detect potential webshell activity"

    events:
        $web.metadata.event_type = "NETWORK_HTTP"
        $web.network.http.method = "POST"
        $web.network.http.request_body = /(<\?php|eval\(|base64_decode|system\(|exec\(|shell_exec)/ nocase
        $web.target.file.full_path = /.*\.(php|asp|aspx|jsp)$/ nocase

        $proc.metadata.event_type = "PROCESS_LAUNCH"
        $proc.principal.process.file.full_path = /.*\/(apache|nginx|iis|httpd)/ nocase
        $proc.target.process.file.full_path = /.*\/(cmd|powershell|bash|sh)/ nocase

    match:
        $hostname over 10m

    condition:
        $web and $proc
}

// Rule with UDM additional fields
rule kubernetes_suspicious_activity {
    meta:
        author = "Cloud Security Team"
        description = "Detect suspicious Kubernetes activity"

    events:
        $e.metadata.product_name = "GKE"
        $e.metadata.event_type = "STATUS_UPDATE"
        $e.udm.additional.fields["pod_name"] in ["kube-system", "kube-public"]
        $e.udm.additional.fields["container_image"] = /.*:(latest|dev)$/ nocase
        $e.security_result.action = "FAIL"

    match:
        $namespace over 30m

    outcome:
        $failed_attempts = count($e.metadata.id)
        $unique_pods = count_distinct($e.udm.additional.fields["pod_name"])

    condition:
        $failed_attempts > 10 or $unique_pods > 5
}

// Complex rule with sliding windows
rule brute_force_with_success {
    meta:
        author = "Security Analytics"
        description = "Detect brute force followed by successful login"

    events:
        // Failed login attempts
        $fail.metadata.event_type = "USER_LOGIN"
        $fail.security_result.action = "BLOCK"
        $fail.target.user.userid = $target_user
        $fail.principal.ip = $source_ip

        // Successful login
        $success.metadata.event_type = "USER_LOGIN"
        $success.security_result.action = "ALLOW"
        $success.target.user.userid = $target_user
        $success.principal.ip = $source_ip

    match:
        $target_user over 30m
        $source_ip over 30m

    outcome:
        $failed_count = count($fail.metadata.id)
        $success_count = count($success.metadata.id)
        $first_fail = earliest($fail.metadata.event_timestamp)
        $first_success = earliest($success.metadata.event_timestamp)
        $time_to_success = $first_success.seconds - $first_fail.seconds

    condition:
        $failed_count > 5 and
        $success_count >= 1 and
        $time_to_success < 1800  // Success within 30 minutes of first failure
}
