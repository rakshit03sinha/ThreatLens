# ThreatLens Supported Log Formats (12 Parsers)

ThreatLens provides native, robust parsers for 12 industry-standard telemetry formats. Missing fields are preserved as null rather than fabricated.

| # | Format Identifier | Source Description | Primary Extracted Fields |
|---|-------------------|--------------------|--------------------------|
| 1 | `windows` | Windows Event Logs (JSON / XML Export) | EventID, TimeCreated, Computer, TargetUserName, IpAddress, IpPort, Status, LogonType |
| 2 | `linux` | Linux System & Auth (`/var/log/auth.log`, `secure`) | Timestamp, Hostname, Program, PID, Username, Source IP, Port, Action |
| 3 | `syslog` | Generic Syslog (RFC 3164 / RFC 5424) | PRI, Facility, Severity, Timestamp, Hostname, AppName, ProcessID, Message |
| 4 | `cisco` | Cisco ASA / IOS Network Security Logs | Facility, Severity, Mnemonic, Source Zone/IP/Port, Destination Zone/IP/Port, Action |
| 5 | `paloalto` | Palo Alto Networks PAN-OS Firewall (CSV) | Log Type, Subtype, Generated Time, Source IP, Dest IP, Source Port, Dest Port, Rule, Action |
| 6 | `aws_cloudtrail` | AWS CloudTrail Audit Events (JSON) | eventTime, eventSource, eventName, userIdentity, sourceIPAddress, awsRegion, requestParameters |
| 7 | `azure_activity` | Azure Activity & Audit Logs (JSON) | time, resourceId, operationName, resultType, caller, callerIpAddress, properties |
| 8 | `ndjson` | JSON Lines / Standard Telemetry (NDJSON) | timestamp, src_ip, dst_ip, src_port, dst_port, user, host, action, severity, event |
| 9 | `cef` | Common Event Format (ArcSight / Syslog) | Vendor, Product, Version, EventClassID, Name, Severity, Extension key-values |
| 10 | `leef` | Log Event Extended Format (IBM QRadar) | LEEF Version, Vendor, Product, Version, EventID, delimiter-separated key-values |
| 11 | `apache` | Apache HTTP Server Access Logs (Combined/Common) | Client IP, Ident, Auth User, Date, Method, URI, Protocol, Status, Bytes, Referer, User-Agent |
| 12 | `nginx` | Nginx HTTP Server Access Logs | Remote Addr, Remote User, Time Local, Request, Status, Body Bytes Sent, Referer, User Agent |

## Ingestion Sanitization & Redaction
All raw logs passed through the ingestion pipeline undergo redaction before database persistence:
- Password patterns: `password=...`, `pwd=...`, `secret=...`
- Authorization tokens: `Bearer [token]`, `Basic [base64]`
- Credit card numbers: `\b(?:\d{4}[-\s]?){3}\d{4}\b`
- Private cryptographic keys: `-----BEGIN ... PRIVATE KEY-----`

