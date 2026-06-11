"""
SecureAI Guardian - Recommendation Agent
Generates prioritized, actionable remediation recommendations for detected threats.
"""

from typing import List, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class RecommendationAgent:
    """
    AI Agent for generating actionable security recommendations.
    Maps threat types to specific remediation playbooks.
    """

    name = "RecommendationAgent"
    version = "1.0.0"

    # ── Remediation Playbooks ─────────────────────────────────────────────────

    PLAYBOOKS = {
        "brute_force": [
            {
                "priority": 1,
                "action": "Block Source IPs",
                "category": "Network Defense",
                "description": "Immediately block all identified attacking IP addresses at the firewall/WAF level.",
                "implementation_steps": [
                    "Add source IPs to firewall deny list",
                    "Update WAF rules to block the IP range/ASN",
                    "Enable geo-blocking if attacks originate from unexpected regions",
                    "Configure rate limiting: max 5 failed attempts per IP per minute",
                ],
                "estimated_effort": "15 minutes",
                "automated": True,
            },
            {
                "priority": 2,
                "action": "Enable Account Lockout Policy",
                "category": "Identity & Access",
                "description": "Enforce progressive account lockout after failed authentication attempts.",
                "implementation_steps": [
                    "Set account lockout threshold: 5 failed attempts",
                    "Set lockout duration: 30 minutes with admin unlock option",
                    "Enable CAPTCHA after 3 consecutive failures",
                    "Send email alert to account owner on lockout",
                ],
                "estimated_effort": "1 hour",
                "automated": False,
            },
            {
                "priority": 3,
                "action": "Enforce Multi-Factor Authentication",
                "category": "Identity & Access",
                "description": "Require MFA for all user accounts, especially privileged users.",
                "implementation_steps": [
                    "Enable MFA for all admin accounts immediately",
                    "Roll out MFA to all users within 48 hours",
                    "Disable password-only authentication",
                    "Consider hardware security keys for privileged accounts",
                ],
                "estimated_effort": "2-4 hours",
                "automated": False,
            },
        ],
        "sql_injection": [
            {
                "priority": 1,
                "action": "Enable Web Application Firewall (WAF) SQL Rules",
                "category": "Application Security",
                "description": "Activate WAF rules to block SQL injection patterns in all HTTP requests.",
                "implementation_steps": [
                    "Enable OWASP CRS SQL injection rules in WAF",
                    "Set WAF to block mode (not just detect)",
                    "Add custom rules for your application's specific patterns",
                    "Test WAF rules in staging before applying to production",
                ],
                "estimated_effort": "30 minutes",
                "automated": True,
            },
            {
                "priority": 2,
                "action": "Audit and Fix Vulnerable Code",
                "category": "Application Security",
                "description": "Review and remediate all database queries to use parameterized statements.",
                "implementation_steps": [
                    "Run static code analysis (SAST) on all database interaction code",
                    "Replace string concatenation with parameterized queries/prepared statements",
                    "Implement input validation and sanitization at all entry points",
                    "Conduct code review with security-focused checklist",
                ],
                "estimated_effort": "4-16 hours",
                "automated": False,
            },
            {
                "priority": 3,
                "action": "Implement Database Activity Monitoring",
                "category": "Monitoring",
                "description": "Deploy real-time database activity monitoring to detect and alert on suspicious queries.",
                "implementation_steps": [
                    "Deploy DAM solution (AWS RDS Enhanced Monitoring or equivalent)",
                    "Set alerts for: bulk data reads, schema queries, admin operations",
                    "Enable query logging for forensic analysis",
                    "Restrict database user privileges to minimum necessary",
                ],
                "estimated_effort": "2-4 hours",
                "automated": True,
            },
        ],
        "malware": [
            {
                "priority": 1,
                "action": "Isolate Infected Systems",
                "category": "Incident Response",
                "description": "Immediately isolate all systems with detected malware to prevent lateral spread.",
                "implementation_steps": [
                    "Disconnect infected hosts from network (VLAN isolation or physical)",
                    "Preserve memory dumps and disk images for forensics before remediation",
                    "Document all network connections made by infected systems in last 24h",
                    "Notify incident response team and management",
                ],
                "estimated_effort": "Immediate - 30 minutes",
                "automated": True,
            },
            {
                "priority": 2,
                "action": "Malware Eradication & System Recovery",
                "category": "Incident Response",
                "description": "Remove malware and restore systems from clean backups.",
                "implementation_steps": [
                    "Run full antimalware scan with updated signatures",
                    "If persistent: reimage system from known-good baseline",
                    "Restore from backup made before infection if needed",
                    "Verify system integrity before reconnecting to network",
                ],
                "estimated_effort": "2-8 hours per system",
                "automated": False,
            },
            {
                "priority": 3,
                "action": "Hunt for Lateral Movement",
                "category": "Threat Hunting",
                "description": "Investigate whether malware has spread to other systems.",
                "implementation_steps": [
                    "Review all lateral movement indicators (SMB, RDP, WMI activity)",
                    "Check for new user accounts or modified credentials",
                    "Scan all endpoints for the same malware signature",
                    "Review DNS and network logs for C2 communication patterns",
                ],
                "estimated_effort": "4-24 hours",
                "automated": False,
            },
        ],
        "ddos": [
            {
                "priority": 1,
                "action": "Activate DDoS Protection / CDN Scrubbing",
                "category": "Network Defense",
                "description": "Enable DDoS mitigation services to absorb and filter attack traffic.",
                "implementation_steps": [
                    "Enable AWS Shield Advanced or CloudFlare Under Attack Mode",
                    "Route traffic through scrubbing center",
                    "Implement Anycast routing if available",
                    "Contact upstream ISP for null-routing attack sources",
                ],
                "estimated_effort": "15-60 minutes",
                "automated": True,
            },
            {
                "priority": 2,
                "action": "Implement Rate Limiting and Traffic Shaping",
                "category": "Network Defense",
                "description": "Apply aggressive rate limits to mitigate ongoing attack while maintaining service for legitimate users.",
                "implementation_steps": [
                    "Set per-IP rate limit: 100 requests/min on load balancer",
                    "Implement connection-level rate limiting on web servers",
                    "Use CAPTCHA challenges for suspicious traffic patterns",
                    "Block attacking ASNs/countries at edge if applicable",
                ],
                "estimated_effort": "30 minutes",
                "automated": True,
            },
        ],
        "data_exfiltration": [
            {
                "priority": 1,
                "action": "Block Suspicious Outbound Connections",
                "category": "Data Loss Prevention",
                "description": "Immediately block unauthorized outbound data transfers.",
                "implementation_steps": [
                    "Block identified destination IPs/domains at firewall",
                    "Implement egress filtering: whitelist authorized external destinations",
                    "Enable DLP rules to flag large outbound transfers",
                    "Review and revoke any compromised API keys or credentials",
                ],
                "estimated_effort": "30 minutes",
                "automated": True,
            },
            {
                "priority": 2,
                "action": "Assess Data Breach Scope",
                "category": "Incident Response",
                "description": "Determine what data was exfiltrated and assess regulatory obligations.",
                "implementation_steps": [
                    "Review data transferred: identify sensitive data categories",
                    "Check if PII, financial, or health data was involved",
                    "Assess GDPR/CCPA/PCI-DSS notification requirements",
                    "Engage legal counsel and DPO if required by regulations",
                ],
                "estimated_effort": "4-24 hours",
                "automated": False,
            },
        ],
        "privilege_escalation": [
            {
                "priority": 1,
                "action": "Revoke Elevated Privileges",
                "category": "Identity & Access",
                "description": "Immediately revoke unauthorized privilege grants and reset affected accounts.",
                "implementation_steps": [
                    "Reset passwords for all accounts showing escalation attempts",
                    "Review and revoke unauthorized sudo/admin rights",
                    "Audit all privileged account activity in last 24 hours",
                    "Enable privileged access management (PAM) session recording",
                ],
                "estimated_effort": "1 hour",
                "automated": True,
            },
            {
                "priority": 2,
                "action": "Patch Privilege Escalation Vulnerabilities",
                "category": "Vulnerability Management",
                "description": "Identify and patch OS/application vulnerabilities exploited for privilege escalation.",
                "implementation_steps": [
                    "Run vulnerability scan on affected systems",
                    "Apply OS security patches (focus on kernel and SUID binaries)",
                    "Review cron jobs, startup scripts, and service configurations",
                    "Implement least-privilege principle for all service accounts",
                ],
                "estimated_effort": "4-8 hours",
                "automated": False,
            },
        ],
        "xss": [
            {
                "priority": 1,
                "action": "Enable Content Security Policy (CSP)",
                "category": "Application Security",
                "description": "Implement strict CSP headers to mitigate XSS impact.",
                "implementation_steps": [
                    "Add Content-Security-Policy header: default-src 'self'",
                    "Disable inline scripts and eval() in CSP",
                    "Enable X-XSS-Protection header",
                    "Set X-Content-Type-Options: nosniff",
                ],
                "estimated_effort": "1-2 hours",
                "automated": True,
            },
            {
                "priority": 2,
                "action": "Implement Output Encoding",
                "category": "Application Security",
                "description": "Ensure all dynamic content is properly encoded before rendering.",
                "implementation_steps": [
                    "Audit all user-controlled data rendered in HTML/JS",
                    "Implement HTML encoding for all dynamic content",
                    "Use template engines with auto-escaping enabled",
                    "Conduct security-focused code review of frontend code",
                ],
                "estimated_effort": "4-16 hours",
                "automated": False,
            },
        ],
        "default": [
            {
                "priority": 1,
                "action": "Investigate and Contain Threat",
                "category": "Incident Response",
                "description": "Perform immediate investigation and containment of the detected threat.",
                "implementation_steps": [
                    "Collect and preserve all relevant logs",
                    "Block suspicious source IPs at network perimeter",
                    "Isolate affected systems if breach is confirmed",
                    "Notify security team and initiate incident response process",
                ],
                "estimated_effort": "1-4 hours",
                "automated": False,
            },
            {
                "priority": 2,
                "action": "Review Security Monitoring Coverage",
                "category": "Security Operations",
                "description": "Assess and improve detection capabilities to prevent future incidents.",
                "implementation_steps": [
                    "Review SIEM alert rules and detection logic",
                    "Add new detection signatures based on observed IOCs",
                    "Conduct threat hunting for related activity",
                    "Update incident response playbooks",
                ],
                "estimated_effort": "4-8 hours",
                "automated": False,
            },
        ],
    }

    async def recommend(self, threats: List[Dict], investigations: List[Dict]) -> Dict[str, Any]:
        """
        Generate prioritized recommendations for all detected threats.
        """
        logger.info(f"[{self.name}] Generating recommendations for {len(threats)} threats")

        all_recommendations = []
        seen_actions = set()

        for threat in threats:
            category = str(threat.get("threat_category", "default")).lower()
            playbook = self.PLAYBOOKS.get(category, self.PLAYBOOKS["default"])

            for rec in playbook:
                action_key = rec["action"]
                if action_key not in seen_actions:
                    seen_actions.add(action_key)
                    enhanced = {
                        **rec,
                        "threat_category": category,
                        "threat_severity": threat.get("severity", "medium"),
                        "risk_score": threat.get("risk_score", 50.0),
                        "source_ips": threat.get("source_ips", []),
                    }
                    all_recommendations.append(enhanced)

        # Always add general security hygiene recommendations
        general_recs = self._general_recommendations()
        for rec in general_recs:
            if rec["action"] not in seen_actions:
                all_recommendations.append(rec)

        # Sort by priority
        all_recommendations.sort(key=lambda x: (x["priority"], -x.get("risk_score", 0)))

        return {
            "agent": self.name,
            "total_recommendations": len(all_recommendations),
            "automated_actions": sum(1 for r in all_recommendations if r.get("automated")),
            "manual_actions": sum(1 for r in all_recommendations if not r.get("automated")),
            "recommendations": all_recommendations,
            "immediate_actions": [r for r in all_recommendations if r["priority"] == 1],
            "estimated_total_effort": self._estimate_total_effort(all_recommendations),
        }

    def _general_recommendations(self) -> List[Dict]:
        """General security hygiene recommendations always applicable."""
        return [
            {
                "priority": 4,
                "action": "Update Security Monitoring Rules",
                "category": "Security Operations",
                "description": "Add detection rules based on newly identified IOCs from this incident.",
                "implementation_steps": [
                    "Add blocking rules for identified malicious IPs/domains",
                    "Create SIEM correlation rules for detected attack patterns",
                    "Update threat intelligence feeds with new IOCs",
                    "Test new detection rules in staging environment",
                ],
                "estimated_effort": "2-4 hours",
                "automated": True,
                "threat_category": "general",
                "threat_severity": "medium",
                "risk_score": 0,
            },
            {
                "priority": 5,
                "action": "Conduct Security Awareness Training",
                "category": "People & Process",
                "description": "Brief security team and relevant staff on the attack patterns observed.",
                "implementation_steps": [
                    "Send security advisory to all relevant staff",
                    "Conduct 30-minute threat briefing for security team",
                    "Update security runbooks with lessons learned",
                    "Schedule post-incident review meeting",
                ],
                "estimated_effort": "2-4 hours",
                "automated": False,
                "threat_category": "general",
                "threat_severity": "low",
                "risk_score": 0,
            },
        ]

    def _estimate_total_effort(self, recommendations: List[Dict]) -> str:
        immediate = sum(1 for r in recommendations if r["priority"] == 1)
        total = len(recommendations)
        if immediate > 3:
            return "Significant effort required — 8-24 hours for critical remediations"
        elif immediate > 1:
            return "Moderate effort required — 4-8 hours for critical remediations"
        else:
            return "Manageable effort — 1-4 hours for initial remediations"