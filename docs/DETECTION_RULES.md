# ThreatLens Detection Rule Catalogue

ThreatLens implements 11 deterministic detection rules aligned with the MITRE ATT&CK framework. Each rule operates across configurable sliding time windows with transparent evaluation logic.

---

### RULE-001: Repeated Failed Logins / Brute-Force Pattern
- **MITRE Tactic**: Credential Access
- **Technique ID**: T1110 (Brute Force)
- **Default Window**: 300 seconds (5 minutes)
- **Default Threshold**: 5 failed events
- **Severity**: High
- **Logic**: Aggregates failed authentication events (`action in ['failure', 'deny', 'failed']`) sharing the same `username` or `source_ip`.
- **Limitations**: In network configurations where NAT is applied without X-Forwarded-For headers, multiple benign users behind a single proxy IP could trigger false positives if threshold is set too low.

---

### RULE-002: Successful Login Following a Burst of Failures
- **MITRE Tactic**: Credential Access
- **Technique ID**: T1110.001 (Password Guessing)
- **Default Window**: 600 seconds (10 minutes)
- **Default Threshold**: 3 preceding failed attempts
- **Severity**: Critical
- **Logic**: Evaluates a successful authentication event preceded by 3 or more failed authentication attempts from the same `username` or `source_ip` within the evaluation window.
- **Limitations**: Legitimate users who mistype their password multiple times before remembering the correct credentials can trigger this rule. Corroborate with geolocation anomalies.

---

### RULE-003: Suspicious Privileged Account or Group Change
- **MITRE Tactic**: Privilege Escalation / Persistence
- **Technique ID**: T1098 (Account Manipulation) / T1078 (Valid Accounts)
- **Severity**: High
- **Logic**: Detects addition of user accounts into sensitive administrative groups (e.g. Windows Event 4728/4732 targeting `Domain Admins`, `Administrators`, Linux `wheel`, or modifying `/etc/sudoers`).
- **Limitations**: Authorized sysadmin onboarding and routine maintenance may trigger this rule; verify against scheduled change tickets.

---

### RULE-004: New or Unusual Service/Process Execution
- **MITRE Tactic**: Persistence / Execution
- **Technique ID**: T1543.003 (Windows Service) / T1059
- **Severity**: High
- **Logic**: Identifies installation of new system services (Windows System Event 7045) or invocation of high-risk tools (`psexec`, `mimikatz`, `certutil -urlcache`, `vssadmin`, `procdump`, `netcat`).
- **Limitations**: PsExec or Certutil may be used by legitimate IT automation scripts. Exclude authorized orchestrator service accounts.

---

### RULE-005: Suspicious PowerShell or Command-Line Indicators
- **MITRE Tactic**: Execution / Defense Evasion
- **Technique ID**: T1059.001 (PowerShell)
- **Severity**: High
- **Logic**: Detects obfuscated command lines or script blocks matching `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `-EncodedCommand` / `-enc`, `DownloadString`, `Invoke-Expression` (IEX), or `Invoke-Mimikatz`.
- **Limitations**: Complex enterprise software deployment tools (e.g. SCCM, Intune) occasionally use encoded commands for script execution.

---

### RULE-006: Possible Lateral Movement via Remote Logon / Admin Share
- **MITRE Tactic**: Lateral Movement
- **Technique ID**: T1021 (Remote Services)
- **Severity**: High
- **Logic**: Detects network logons establishing access to administrative network shares (`ADMIN$`, `C$`, `IPC$`) or an identical user authenticating across multiple disparate endpoints within a 10-minute window.
- **Limitations**: Automated scanning by vulnerability management scanners (e.g. Tenable/Qualys) will trigger lateral movement indicators. Whitelist scanner service accounts.

---

### RULE-007: Unusual Outbound Connection to High-Risk Destination
- **MITRE Tactic**: Command and Control
- **Technique ID**: T1071 (Application Layer Protocol)
- **Severity**: Medium
- **Logic**: Heuristic detection of outbound network egress connecting to high-risk non-standard ports typically associated with reverse shells and RATs (`4444`, `1337`, `6667`, `8888`, `9001`, `31337`, `5555`).
- **Limitations**: Custom internal development services or non-standard corporate proxies may utilize these ports.

---

### RULE-008: DNS Query to Known Malicious Domain
- **MITRE Tactic**: Command and Control
- **Technique ID**: T1071.004 (DNS)
- **Severity**: Critical
- **Logic**: Matches DNS resolution requests and HTTP Host headers against active domains stored in the ThreatLens IOC intelligence store.
- **Limitations**: Requires up-to-date threat intelligence feeds; newly registered domains (DGA/zero-day) might not exist in IOC databases.

---

### RULE-009: Malware File Hash Indicator Match
- **MITRE Tactic**: Execution
- **Technique ID**: T1204 (User Execution) / T1059
- **Severity**: Critical
- **Logic**: Evaluates SHA-256, SHA-1, or MD5 checksums extracted from file creation or execution telemetry against active malware indicators in the threat intelligence store.
- **Limitations**: Hash-based detection is brittle against polymorphic malware; should be paired with behavioral detection.

---

### RULE-010: Cloud Audit Suspicious Privilege or Policy Change
- **MITRE Tactic**: Privilege Escalation / Persistence
- **Technique ID**: T1098.001 (Cloud Role/Policy Modification)
- **Severity**: High
- **Logic**: Inspects AWS CloudTrail (`AttachRolePolicy`, `PutUserPolicy`, `CreatePolicyVersion`) and Azure Resource Manager (`roleAssignments/write`) for privileged permission assignments.
- **Limitations**: Terraform, Pulumi, or CI/CD pipelines deploying infrastructure can generate these events. Whitelist approved CI/CD service principals.

---

### RULE-011: Web-Server Path Traversal or Exploit Probing
- **MITRE Tactic**: Initial Access / Discovery
- **Technique ID**: T1190 (Exploit Public-Facing Application)
- **Severity**: High
- **Logic**: Inspects HTTP requests in Apache and Nginx access logs for directory traversal signatures (`../`, `..\`), sensitive system file reads (`/etc/passwd`, `win.ini`), SQL injection (`union select`), script injection (`<script>`), or env probes (`/.env`).
- **Limitations**: Defensive detection only; does not confirm whether the underlying web application was vulnerable or if the probe succeeded. Correlate with HTTP response status codes.

