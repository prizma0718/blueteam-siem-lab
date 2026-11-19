### Scenario 1: Encoded PowerShell Execution (T1059.001, WinClient)
- **Rule File:** [`t1059-001-encoded-powershell-execution.ndjson`](t1059-001-encoded-powershell-execution.ndjson)
- **Full Investigation:** [IR-001: Encoded PowerShell Execution on WinClient](../incident-reports/IR-001.md)

### Scenario 2: SSH Brute Force (T1110, LinClient)
- **Rule File:** [`t1110-ssh-brute-force.ndjson`](t1110-ssh-brute-force.ndjson)
- **Full Investigation:** [IR-002: SSH Brute Force on LinClient](../incident-reports/IR-002.md)

### Scenario 3: Linux Network Port Scanning: Cardinality Detection (T1046, LinClient)
- **Rule File:** [`t1046-linux-port-scan-cardinality.ndjson`](t1046-linux-port-scan-cardinality.ndjson)
- **What Ran:** `sudo nmap -sS -p- -T4 172.16.60.130` executed from Kali (172.16.60.134).
- **What Happened:** The SIEM rule (Network Port Scanning Detected, T1046) grouped by `source.ip` and triggered after breaching the threshold of 20 unique `destination.port` connections (`cardinality >= 20`) within a 2-minute window.

### Scenario 4: Privilege Escalation via Sudo (T1548.003, LinClient)
- **Rule File:** [`t1548-003-sudo-privilege-escalation.ndjson`](t1548-003-sudo-privilege-escalation.ndjson)
- **What Ran:** Standard user `badguy` executed `sudo su` and `sudo -l` resulting in "NOT in sudoers" logs, while authorized admin `linclient` executed `sudo -i` to spawn a root shell.
- **What Happened:** The high-severity custom KQL rule (Privilege Escalation and Sudo Anomaly, T1548.003) scanning `system.auth` and `system.syslog` triggered for the unauthorized user and correctly allowed the administrator via the `and not message: "*linclient*"` filtering.

### Scenario 5: Scheduled Task Persistence (T1053.005, WinClient)
- **Rule File:** [`t1053-005-scheduled-task-persistence.ndjson`](t1053-005-scheduled-task-persistence.ndjson)
- **What Ran:** `schtasks /create /tn "Updater" /tr "cmd.exe /c echo 'beacon'" /sc minute /mo 5` executed on WinClient (172.16.60.132).
- **What Happened:** The SIEM rule (Scheduled Task Creation for Persistence, T1053.005) successfully filtered in Sysmon Event ID 1 (`schtasks.exe` with `*create*`) and Windows Security Event ID 4698 while filtering out updates based on these specific filters: (`*GoogleUpdate*`, `*Mozilla*`, `*OneDrive*`).

### Scenario 6: Cross-Platform Aggressive Network Port Scan (T1046, WinClient & LinClient)
- **Rule File:** [`t1046-aggressive-port-scan-cross-platform.ndjson`](t1046-aggressive-port-scan-cross-platform.ndjson)
- **What Ran:** High-volume TCP SYN reconnaissance (`nmap -sS -T4`) executed from Kali (172.16.60.134) across both WinClient (172.16.60.132) and LinClient (172.16.60.130).
- **What Happened:** The cross-platform threshold rule (Aggressive Network Port Scan Detected, T1046) aggregated Sysmon Event ID 3 (`NetworkConnect`) telemetry on Windows alongside Linux `NMAP_SYN_SCAN` syslog events, triggering when a single `source.ip` generated `>= 100` connection events within a 5-minutes window.