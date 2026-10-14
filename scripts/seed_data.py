"""ThreatLens Synthetic Demo Dataset & Scenario Seeding Script.

Generates realistic telemetry across all 12 supported log formats simulating
a multi-stage enterprise attack campaign:
1. External reconnaissance & web probing (Apache, Nginx, Palo Alto)
2. Brute-force credential access (Linux SSH, Windows Security 4625)
3. Successful credential compromise (Windows Security 4624)
4. Privilege escalation & Account manipulation (Windows 4728, Linux sudo)
5. Lateral movement (Windows remote logon / Admin shares, Cisco ASA)
6. Persistence via new service creation (Windows 7045)
7. Command & Control DNS beaconing (CEF, LEEF)
8. Cloud audit unauthorized policy manipulation (AWS CloudTrail, Azure Activity)
"""

import asyncio
import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")

from app.db.session import async_session_factory, init_db
from app.services.ingestion import ingestion_service
from app.services.ioc import ioc_service
from app.main import seed_initial_metadata

DEMO_IOCS = [
    {
        "value": "198.51.100.5",
        "type": "ipv4",
        "severity": "critical",
        "confidence": 95,
        "source": "ThreatLens CyberIntel Feed",
        "desc": "Active C2 server linked to Advanced Adversary Group Alpha",
        "tags": ["c2", "adversary-alpha", "botnet"],
    },
    {
        "value": "203.0.113.15",
        "type": "ipv4",
        "severity": "high",
        "confidence": 90,
        "source": "ThreatLens CyberIntel Feed",
        "desc": "Known brute-force scanner IP",
        "tags": ["scanner", "brute-force"],
    },
    {
        "value": "malicious-c2.example.com",
        "type": "domain",
        "severity": "critical",
        "confidence": 98,
        "source": "ThreatLens ThreatIntel DNS",
        "desc": "Dynamic DNS Command & Control domain",
        "tags": ["c2", "dns-tunnel"],
    },
    {
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "sha256",
        "severity": "critical",
        "confidence": 100,
        "source": "ThreatLens MalwareVault",
        "desc": "Trojan.Dropper payload binary hash",
        "tags": ["trojan", "dropper"],
    },
]

DEMO_TELEMETRY = [
    # Stage 1: Web Exploit Probing (Apache & Nginx)
    (
        '198.51.100.5 - - [14/Oct/2026:21:00:01 +0000] "GET /admin/../../etc/passwd HTTP/1.1" 404 153 "-" "curl/7.68.0"',
        "apache",
    ),
    (
        '198.51.100.5 - - [14/Oct/2026:21:00:03 +0000] "GET /phpmyadmin/scripts/setup.php HTTP/1.1" 404 162 "-" "curl/7.68.0"',
        "nginx",
    ),
    # Stage 2: Palo Alto Firewall Drop
    (
        "1,2026/10/14 21:00:05,001801000001,TRAFFIC,drop,1,2026/10/14 21:00:05,198.51.100.5,10.0.0.5,198.51.100.5,10.0.0.5,rule_block_malicious,admin,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,1,123456,1,54321,4444,54321,4444,0x0,tcp,deny,100,0,100,1,2026/10/14 21:00:05,0,any,0,1234,0x0,192.168.0.0,US,0,1,0",
        "paloalto",
    ),
    # Stage 3: Linux SSH Brute-Force (Linux Auth)
    (
        "Oct 14 21:00:10 srv-bastion sshd[12345]: Failed password for invalid user admin from 198.51.100.5 port 54321 ssh2",
        "linux",
    ),
    (
        "Oct 14 21:00:12 srv-bastion sshd[12346]: Failed password for invalid user admin from 198.51.100.5 port 54322 ssh2",
        "linux",
    ),
    (
        "Oct 14 21:00:14 srv-bastion sshd[12347]: Failed password for invalid user admin from 198.51.100.5 port 54323 ssh2",
        "linux",
    ),
    (
        "Oct 14 21:00:16 srv-bastion sshd[12348]: Failed password for invalid user admin from 198.51.100.5 port 54324 ssh2",
        "linux",
    ),
    (
        "Oct 14 21:00:18 srv-bastion sshd[12349]: Failed password for invalid user admin from 198.51.100.5 port 54325 ssh2",
        "linux",
    ),
    # Stage 4: Windows Brute-Force and Subsequent Compromise (Windows Event 4625 & 4624)
    (
        '{"Event":{"System":{"EventID":4625,"TimeCreated":{"SystemTime":"2026-10-14T21:00:20Z"},"Computer":"DC01.corp.internal"},"EventData":{"TargetUserName":"victim_admin","IpAddress":"198.51.100.5","IpPort":"54321","Status":"0xC000006D"}}}',
        "windows",
    ),
    (
        '{"Event":{"System":{"EventID":4625,"TimeCreated":{"SystemTime":"2026-10-14T21:00:22Z"},"Computer":"DC01.corp.internal"},"EventData":{"TargetUserName":"victim_admin","IpAddress":"198.51.100.5","IpPort":"54322","Status":"0xC000006D"}}}',
        "windows",
    ),
    (
        '{"Event":{"System":{"EventID":4625,"TimeCreated":{"SystemTime":"2026-10-14T21:00:24Z"},"Computer":"DC01.corp.internal"},"EventData":{"TargetUserName":"victim_admin","IpAddress":"198.51.100.5","IpPort":"54323","Status":"0xC000006D"}}}',
        "windows",
    ),
    (
        '{"Event":{"System":{"EventID":4624,"TimeCreated":{"SystemTime":"2026-10-14T21:00:28Z"},"Computer":"DC01.corp.internal"},"EventData":{"TargetUserName":"victim_admin","IpAddress":"198.51.100.5","IpPort":"54324","LogonType":"10"}}}',
        "windows",
    ),
    # Stage 5: Privilege Escalation & Persistence (Windows 4728 & 7045)
    (
        '{"Event":{"System":{"EventID":4728,"TimeCreated":{"SystemTime":"2026-10-14T21:00:35Z"},"Computer":"DC01.corp.internal"},"EventData":{"TargetUserName":"Administrators","SubjectUserName":"victim_admin"}}}',
        "windows",
    ),
    (
        '{"Event":{"System":{"EventID":7045,"TimeCreated":{"SystemTime":"2026-10-14T21:00:40Z"},"Computer":"DC01.corp.internal"},"EventData":{"ServiceName":"psexesvc","ImagePath":"C:\\\\Windows\\\\System32\\\\psexesvc.exe"}}}',
        "windows",
    ),
    # Stage 6: Suspicious PowerShell Cradle (NDJSON)
    (
        '{"timestamp":"2026-10-14T21:00:45Z","src_ip":"10.0.0.15","dst_ip":"198.51.100.5","user":"victim_admin","host":"DC01.corp.internal","action":"execute","severity":"high","event":"Process Execution","command_line":"powershell.exe -ExecutionPolicy Bypass -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."}',
        "ndjson",
    ),
    # Stage 7: Cisco Network Outbound Reverse Shell Connection
    (
        "%ASA-6-302013: Built outbound TCP connection 98765 for outside:198.51.100.5/4444 (198.51.100.5/4444) to inside:10.0.0.15/54321 (10.0.0.15/54321)",
        "cisco",
    ),
    # Stage 8: DNS C2 Query & Indicator Match (CEF & LEEF)
    (
        "CEF:0|SecurityCorp|ThreatSensor|1.0|100|Malicious Domain Query|9|src=10.0.0.15 dst=1.1.1.1 spt=54321 dpt=53 dhost=malicious-c2.example.com suser=victim_admin act=blocked",
        "cef",
    ),
    (
        "LEEF:1.0|IBM|QRadar|7.3.0|MaliciousHashDetected|devTime=2026-10-14T21:00:55Z\tsrc=10.0.0.15\tdst=198.51.100.5\tusrName=victim_admin\thash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "leef",
    ),
    # Stage 9: Generic Syslog Event
    (
        "<165>1 2026-10-14T21:01:00.000Z DC01.corp.internal sec-agent 4321 ID99 [threatlens@32473 action=\"alert\"] Lateral movement administrative share access ADMIN$ by victim_admin",
        "syslog",
    ),
    # Stage 10: Cloud IAM Privilege Manipulation (AWS CloudTrail & Azure)
    (
        '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"cloud_attacker"},"eventTime":"2026-10-14T21:01:10Z","eventSource":"iam.amazonaws.com","eventName":"AttachRolePolicy","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.5","requestParameters":{"roleName":"SecurityAdmin"}}',
        "aws_cloudtrail",
    ),
    (
        '{"time":"2026-10-14T21:01:15Z","resourceId":"/subscriptions/sub1/resourceGroups/rg1","operationName":{"value":"Microsoft.Authorization/roleAssignments/write"},"category":{"value":"Administrative"},"resultType":"Success","caller":"cloud_attacker@cloud.internal","callerIpAddress":"198.51.100.5"}',
        "azure_activity",
    ),
]


async def run_seed():
    print("[*] Initializing database tables and metadata...")
    await init_db()
    await seed_initial_metadata()

    async with async_session_factory() as session:
        print("[*] Seeding Threat Intelligence IOC indicators...")
        for ioc in DEMO_IOCS:
            await ioc_service.add_or_update_ioc(
                session=session,
                indicator_value=ioc["value"],
                indicator_type=ioc["type"],
                severity=ioc["severity"],
                confidence=ioc["confidence"],
                source=ioc["source"],
                description=ioc["desc"],
                tags=ioc["tags"],
            )
        await session.commit()
        print(f"    [+] Seeded {len(DEMO_IOCS)} threat intelligence indicators.")

        print("[*] Ingesting multi-stage synthetic attack telemetry across 12 formats...")
        raw_events = [item[0] for item in DEMO_TELEMETRY]
        job = await ingestion_service.process_batch(session=session, raw_events=raw_events)
        await session.commit()
        print(f"    [+] Processed {job.total_records} events: {job.accepted_count} accepted, {job.rejected_count} rejected.")

    print("[+] ThreatLens synthetic demonstration dataset successfully seeded!")


if __name__ == "__main__":
    asyncio.run(run_seed())

