"""
SecureAI Guardian - Threat Detection Agent
Analyzes security logs and identifies potential threats using pattern matching + ML heuristics.
"""

import re
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging

from app.schemas import SecurityLog, ThreatDetection, ThreatCategory, SeverityLevel, ThreatIndicator

logger = logging.getLogger(__name__)


class ThreatAgent:
    """
    AI Agent for automated threat detection.
    Analyzes patterns, frequencies, and anomalies in security logs.
    """

    # ── Threat Signature Patterns ────────────────────────────────────────────

    SQL_INJECTION_PATTERNS = [
        r"(\bOR\b|\bAND\b)\s+\d+=\d+",
        r"UNION\s+SELECT",
        r"DROP\s+TABLE",
        r"INSERT\s+INTO.*SELECT",
        r";\s*--",
        r"'.*OR.*'.*'",
        r"xp_cmdshell",
        r"EXEC\s*\(",
        r"WAITFOR\s+DELAY",
        r"1\s*=\s*1",
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"document\.cookie",
        r"eval\(",
        r"alert\(",
        r"<img[^>]+onerror",
        r"svg.*onload",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e",
        r"%252e",
        r"/etc/passwd",
        r"/etc/shadow",
        r"win\.ini",
        r"boot\.ini",
    ]

    MALWARE_KEYWORDS = [
        "trojan", "ransomware", "backdoor", "rootkit", "keylogger",
        "botnet", "c2", "command.and.control", "payload", "exploit",
        "shellcode", "dropper", "rat ", "remote.access.tool",
    ]

    DDOS_KEYWORDS = [
        "ddos", "flood", "syn flood", "udp flood", "amplification",
        "reflection attack", "volumetric", "botnet", "requests/min",
        "requests/sec", "rate limit exceeded",
    ]

    def __init__(self):
        self.name = "ThreatAgent"
        self.version = "1.0.0"

    async def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main analysis pipeline for a batch of logs.
        Returns detected threats and analysis metadata.
        """
        logger.info(f"[{self.name}] Analyzing {len(logs)} logs")

        detected_threats = []
        analysis_metadata = {
            "agent": self.name,
            "analyzed_logs": len(logs),
            "analysis_time": datetime.utcnow().isoformat(),
            "patterns_checked": 0,
        }

        # Group logs by source IP for correlation
        ip_groups = defaultdict(list)
        for log in logs:
            ip_groups[log.get("source_ip", "unknown")].append(log)

        # ── Detection Modules ────────────────────────────────────────────────

        # 1. Brute Force Detection
        brute_force = self._detect_brute_force(ip_groups)
        detected_threats.extend(brute_force)

        # 2. SQL Injection Detection
        sqli = self._detect_sql_injection(logs)
        detected_threats.extend(sqli)

        # 3. XSS Detection
        xss = self._detect_xss(logs)
        detected_threats.extend(xss)

        # 4. DDoS Detection
        ddos = self._detect_ddos(ip_groups)
        detected_threats.extend(ddos)

        # 5. Malware Detection
        malware = self._detect_malware(logs)
        detected_threats.extend(malware)

        # 6. Path Traversal Detection
        traversal = self._detect_path_traversal(logs)
        detected_threats.extend(traversal)

        # 7. Data Exfiltration Detection
        exfil = self._detect_data_exfiltration(logs)
        detected_threats.extend(exfil)

        # 8. Privilege Escalation Detection
        privesc = self._detect_privilege_escalation(logs)
        detected_threats.extend(privesc)

        analysis_metadata["threats_detected"] = len(detected_threats)
        analysis_metadata["threat_categories"] = list(set(t["threat_category"] for t in detected_threats))

        return {
            "threats": detected_threats,
            "metadata": analysis_metadata,
        }

    def _detect_brute_force(self, ip_groups: Dict[str, List]) -> List[Dict]:
        """Detect brute force attacks based on failed login frequency."""
        threats = []
        THRESHOLD = 5

        for ip, logs in ip_groups.items():
            failed_logins = [
                l for l in logs
                if l.get("event_type") in ("failed_login", "auth_failure", "login_failed")
                or (l.get("status_code") == 401)
                or "failed" in str(l.get("message", "")).lower()
                   and "login" in str(l.get("message", "")).lower()
            ]

            if len(failed_logins) >= THRESHOLD:
                severity = SeverityLevel.CRITICAL if len(failed_logins) > 50 else (
                    SeverityLevel.HIGH if len(failed_logins) > 20 else SeverityLevel.MEDIUM
                )
                threats.append({
                    "threat_category": ThreatCategory.BRUTE_FORCE,
                    "severity": severity,
                    "source_ips": [ip],
                    "log_count": len(failed_logins),
                    "description": f"Brute force attack detected: {len(failed_logins)} failed authentication attempts from {ip}",
                    "indicators": [
                        {"indicator_type": "ip", "value": ip, "confidence": 0.9,
                         "description": f"Source of {len(failed_logins)} failed login attempts"}
                    ],
                    "confidence": min(0.95, 0.5 + (len(failed_logins) / 100)),
                })

        return threats

    def _detect_sql_injection(self, logs: List[Dict]) -> List[Dict]:
        """Detect SQL injection attempts in log messages."""
        threats = []
        affected_ips = []

        for log in logs:
            message = str(log.get("message", "")) + str(log.get("raw_log", ""))
            for pattern in self.SQL_INJECTION_PATTERNS:
                if re.search(pattern, message, re.IGNORECASE):
                    ip = log.get("source_ip", "unknown")
                    if ip not in affected_ips:
                        affected_ips.append(ip)

        if affected_ips:
            threats.append({
                "threat_category": ThreatCategory.SQL_INJECTION,
                "severity": SeverityLevel.CRITICAL,
                "source_ips": affected_ips,
                "log_count": len(affected_ips),
                "description": f"SQL injection attack detected from {len(affected_ips)} source(s). Payload signatures matched in request data.",
                "indicators": [
                    {"indicator_type": "pattern", "value": "SQL_INJECTION_PAYLOAD",
                     "confidence": 0.97, "description": "SQL injection pattern detected in HTTP request"}
                ],
                "confidence": 0.97,
            })

        return threats

    def _detect_xss(self, logs: List[Dict]) -> List[Dict]:
        """Detect Cross-Site Scripting attempts."""
        threats = []
        affected_ips = []

        for log in logs:
            message = str(log.get("message", "")) + str(log.get("raw_log", ""))
            for pattern in self.XSS_PATTERNS:
                if re.search(pattern, message, re.IGNORECASE):
                    ip = log.get("source_ip", "unknown")
                    if ip not in affected_ips:
                        affected_ips.append(ip)
                    break

        if affected_ips:
            threats.append({
                "threat_category": ThreatCategory.XSS,
                "severity": SeverityLevel.HIGH,
                "source_ips": affected_ips,
                "log_count": len(affected_ips),
                "description": f"Cross-Site Scripting (XSS) attack detected from {len(affected_ips)} source(s).",
                "indicators": [
                    {"indicator_type": "pattern", "value": "XSS_PAYLOAD",
                     "confidence": 0.93, "description": "XSS payload detected in user input"}
                ],
                "confidence": 0.93,
            })

        return threats

    def _detect_ddos(self, ip_groups: Dict[str, List]) -> List[Dict]:
        """Detect DDoS attack patterns."""
        threats = []

        all_ips_with_high_volume = []
        ddos_keywords_found = []

        for ip, logs in ip_groups.items():
            if len(logs) > 100:
                all_ips_with_high_volume.append(ip)

            for log in logs:
                message = str(log.get("message", "")).lower()
                for kw in self.DDOS_KEYWORDS:
                    if kw in message:
                        ddos_keywords_found.append(ip)
                        break

        target_ips = list(set(all_ips_with_high_volume + ddos_keywords_found))

        if target_ips:
            threats.append({
                "threat_category": ThreatCategory.DDoS,
                "severity": SeverityLevel.CRITICAL,
                "source_ips": target_ips[:10],
                "log_count": sum(len(ip_groups[ip]) for ip in target_ips if ip in ip_groups),
                "description": f"DDoS attack pattern detected. {len(target_ips)} attacking IPs identified with high request volumes.",
                "indicators": [
                    {"indicator_type": "ip", "value": ip, "confidence": 0.88,
                     "description": "High-volume request source in DDoS pattern"}
                    for ip in target_ips[:3]
                ],
                "confidence": 0.88,
            })

        return threats

    def _detect_malware(self, logs: List[Dict]) -> List[Dict]:
        """Detect malware signatures in logs."""
        threats = []
        affected_ips = []

        for log in logs:
            message = str(log.get("message", "")).lower()
            if any(kw in message for kw in self.MALWARE_KEYWORDS):
                ip = log.get("source_ip", "unknown")
                if ip not in affected_ips:
                    affected_ips.append(ip)

        if affected_ips:
            threats.append({
                "threat_category": ThreatCategory.MALWARE,
                "severity": SeverityLevel.CRITICAL,
                "source_ips": affected_ips,
                "log_count": len(affected_ips),
                "description": f"Malware signatures detected on {len(affected_ips)} host(s). Immediate investigation required.",
                "indicators": [
                    {"indicator_type": "signature", "value": "MALWARE_SIGNATURE",
                     "confidence": 0.96, "description": "Known malware signature matched"}
                ],
                "confidence": 0.96,
            })

        return threats

    def _detect_path_traversal(self, logs: List[Dict]) -> List[Dict]:
        """Detect directory/path traversal attacks."""
        threats = []
        affected_ips = []

        for log in logs:
            message = str(log.get("message", "")) + str(log.get("raw_log", ""))
            for pattern in self.PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, message, re.IGNORECASE):
                    ip = log.get("source_ip", "unknown")
                    if ip not in affected_ips:
                        affected_ips.append(ip)
                    break

        if affected_ips:
            threats.append({
                "threat_category": ThreatCategory.PRIVILEGE_ESCALATION,
                "severity": SeverityLevel.HIGH,
                "source_ips": affected_ips,
                "log_count": len(affected_ips),
                "description": f"Path traversal attack detected from {len(affected_ips)} source(s). Attempted access to restricted filesystem paths.",
                "indicators": [
                    {"indicator_type": "pattern", "value": "PATH_TRAVERSAL",
                     "confidence": 0.91, "description": "Directory traversal sequence detected"}
                ],
                "confidence": 0.91,
            })

        return threats

    def _detect_data_exfiltration(self, logs: List[Dict]) -> List[Dict]:
        """Detect potential data exfiltration based on transfer volumes."""
        threats = []
        HIGH_BYTES_THRESHOLD = 100_000_000  # 100MB

        large_transfers = [
            log for log in logs
            if log.get("bytes_transferred") and log["bytes_transferred"] > HIGH_BYTES_THRESHOLD
        ]

        if large_transfers:
            source_ips = list(set(l.get("source_ip", "unknown") for l in large_transfers))
            total_bytes = sum(l.get("bytes_transferred", 0) for l in large_transfers)

            threats.append({
                "threat_category": ThreatCategory.DATA_EXFILTRATION,
                "severity": SeverityLevel.CRITICAL,
                "source_ips": source_ips,
                "log_count": len(large_transfers),
                "description": f"Potential data exfiltration: {total_bytes / 1_000_000:.1f}MB transferred in suspicious patterns.",
                "indicators": [
                    {"indicator_type": "behavior", "value": f"{total_bytes / 1_000_000:.1f}MB_OUTBOUND",
                     "confidence": 0.85, "description": "Anomalously large outbound data transfer"}
                ],
                "confidence": 0.85,
            })

        return threats

    def _detect_privilege_escalation(self, logs: List[Dict]) -> List[Dict]:
        """Detect privilege escalation attempts."""
        PRIVESC_KEYWORDS = [
            "privilege escalation", "sudo", "su -", "chmod 777", "setuid",
            "/etc/shadow", "passwd file", "sudoers", "unauthorized access",
            "access denied", "permission denied", "403"
        ]
        threats = []
        affected_ips = []

        for log in logs:
            message = str(log.get("message", "")).lower()
            if any(kw in message for kw in PRIVESC_KEYWORDS):
                ip = log.get("source_ip", "unknown")
                if ip not in affected_ips:
                    affected_ips.append(ip)

        if affected_ips:
            threats.append({
                "threat_category": ThreatCategory.PRIVILEGE_ESCALATION,
                "severity": SeverityLevel.HIGH,
                "source_ips": affected_ips,
                "log_count": len(affected_ips),
                "description": f"Privilege escalation attempts detected from {len(affected_ips)} source(s).",
                "indicators": [
                    {"indicator_type": "behavior", "value": "PRIV_ESC_ATTEMPT",
                     "confidence": 0.82, "description": "Unauthorized privilege escalation behavior"}
                ],
                "confidence": 0.82,
            })

        return threats