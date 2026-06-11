"""
SecureAI Guardian - LLM Investigation Agent
Uses Large Language Models to perform deep threat investigation and analysis.
"""

import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
import httpx

from app.config import settings

logger = logging.getLogger(__name__)


INVESTIGATION_SYSTEM_PROMPT = """You are SecureAI Guardian's expert threat investigation AI. 
You analyze cybersecurity threats with the precision of a senior SOC analyst with 10+ years of experience.

When analyzing threats, you:
1. Identify the attack vector, techniques, and tactics (MITRE ATT&CK framework)
2. Assess the blast radius and affected systems
3. Identify Indicators of Compromise (IOCs)
4. Explain the attacker's likely goals and methodology
5. Provide clear, actionable findings

Always respond in valid JSON format matching the exact schema requested.
Be concise, technical, and accurate. Avoid speculation without evidence."""


class LLMAgent:
    """
    AI Agent for LLM-powered threat investigation.
    Integrates with OpenAI GPT-4 for deep analysis.
    Falls back to rule-based analysis when API key is not configured.
    """

    name = "LLMAgent"
    version = "1.0.0"

    def __init__(self):
        self.api_key = settings.OPENAI_API_KEY
        self.model = settings.LLM_MODEL
        self.use_llm = bool(self.api_key)
        if not self.use_llm:
            logger.info(f"[{self.name}] OpenAI API key not set — using rule-based fallback analysis")

    async def investigate(self, threats: List[Dict], logs: List[Dict]) -> Dict[str, Any]:
        """
        Perform deep investigation of threats using LLM or fallback analysis.
        """
        logger.info(f"[{self.name}] Investigating {len(threats)} threats")

        investigations = []
        for threat in threats[:5]:  # Limit to top 5 threats to control API costs
            if self.use_llm:
                result = await self._llm_investigate(threat, logs)
            else:
                result = self._rule_based_investigate(threat, logs)
            investigations.append(result)

        # Generate overall summary
        summary = self._generate_summary(threats, investigations)

        return {
            "agent": self.name,
            "investigations": investigations,
            "overall_summary": summary,
            "analysis_method": "llm" if self.use_llm else "rule_based",
            "analyzed_at": datetime.utcnow().isoformat(),
        }

    async def _llm_investigate(self, threat: Dict, logs: List[Dict]) -> Dict:
        """Call OpenAI API for threat investigation."""
        # Prepare context (limit log sample to control token usage)
        relevant_logs = [
            l for l in logs
            if l.get("source_ip") in threat.get("source_ips", [])
        ][:10]

        prompt = f"""Analyze this security threat and provide a detailed investigation report.

THREAT DETAILS:
{json.dumps(threat, indent=2, default=str)}

RELEVANT LOG SAMPLES ({len(relevant_logs)} entries):
{json.dumps(relevant_logs[:5], indent=2, default=str)}

Respond ONLY with a JSON object in this exact format:
{{
  "threat_id": "{threat.get('threat_category', 'unknown')}",
  "attack_vector": "Describe the specific attack vector and method",
  "attack_stage": "Initial Access / Execution / Persistence / Privilege Escalation / etc.",
  "affected_systems": ["list", "of", "affected", "system", "types"],
  "iocs": ["ip:x.x.x.x", "pattern:xxx", "hash:xxx"],
  "mitre_techniques": ["T1110.001", "T1190"],
  "mitre_tactics": ["Initial Access", "Credential Access"],
  "attacker_objective": "What the attacker is trying to achieve",
  "blast_radius": "low/medium/high/critical - and brief explanation",
  "analysis": "2-3 sentence technical analysis of the threat",
  "confidence_explanation": "Why this threat was classified with this confidence level",
  "urgency": "immediate/high/medium/low"
}}"""

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": INVESTIGATION_SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        "max_tokens": settings.LLM_MAX_TOKENS,
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"},
                    },
                )
                response.raise_for_status()
                data = response.json()
                result = json.loads(data["choices"][0]["message"]["content"])
                result["analysis_method"] = "gpt-4"
                return result

        except Exception as e:
            logger.error(f"[{self.name}] LLM API error: {e}")
            return self._rule_based_investigate(threat, logs)

    def _rule_based_investigate(self, threat: Dict, logs: List[Dict]) -> Dict:
        """
        Deterministic rule-based fallback investigation.
        Provides structured analysis without requiring an LLM API.
        """
        category_raw = threat.get("threat_category", "unknown")
        severity_raw = threat.get("severity", "medium")
        source_ips = threat.get("source_ips", [])
        confidence = threat.get("confidence", 0.7)
        category = str(category_raw).strip().lower()
        severity = str(severity_raw).strip().lower()

        # Category-specific analysis templates
        analysis_templates = {
            "brute_force": {
                "attack_vector": "Network-based credential stuffing/brute force via authentication endpoints",
                "attack_stage": "Credential Access",
                "mitre_techniques": ["T1110.001", "T1110.003"],
                "mitre_tactics": ["Credential Access"],
                "attacker_objective": "Gain unauthorized access to accounts by guessing or brute-forcing credentials",
                "blast_radius": "high - successful breach could compromise user accounts and pivot to internal systems",
            },
            "sql_injection": {
                "attack_vector": "HTTP request manipulation with malicious SQL payloads targeting database layer",
                "attack_stage": "Initial Access / Exploitation",
                "mitre_techniques": ["T1190", "T1505.001"],
                "mitre_tactics": ["Initial Access", "Collection"],
                "attacker_objective": "Extract sensitive data, bypass authentication, or gain remote code execution via database",
                "blast_radius": "critical - potential full database compromise and data exfiltration",
            },
            "ddos": {
                "attack_vector": "Volumetric/application-layer DDoS using botnet infrastructure",
                "attack_stage": "Impact",
                "mitre_techniques": ["T1498", "T1499"],
                "mitre_tactics": ["Impact"],
                "attacker_objective": "Disrupt service availability, extort target, or serve as distraction for secondary attack",
                "blast_radius": "high - service disruption affecting all users, potential revenue loss",
            },
            "malware": {
                "attack_vector": "Malware delivery via file upload, phishing, or drive-by download",
                "attack_stage": "Execution / Persistence",
                "mitre_techniques": ["T1059", "T1547", "T1055"],
                "mitre_tactics": ["Execution", "Persistence", "Defense Evasion"],
                "attacker_objective": "Establish persistent access, conduct espionage, deploy ransomware, or join botnet",
                "blast_radius": "critical - active malware can spread laterally and compromise entire network",
            },
            "data_exfiltration": {
                "attack_vector": "Unauthorized large-volume data transfer to external endpoints",
                "attack_stage": "Exfiltration",
                "mitre_techniques": ["T1041", "T1567", "T1048"],
                "mitre_tactics": ["Exfiltration"],
                "attacker_objective": "Steal sensitive data for financial gain, espionage, or competitive advantage",
                "blast_radius": "critical - potential regulatory violations (GDPR, PCI-DSS) and business impact",
            },
            "privilege_escalation": {
                "attack_vector": "Exploitation of system misconfigurations or vulnerabilities to gain elevated privileges",
                "attack_stage": "Privilege Escalation",
                "mitre_techniques": ["T1068", "T1078", "T1548"],
                "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
                "attacker_objective": "Obtain administrator/root access to gain full system control",
                "blast_radius": "high - elevated privileges enable lateral movement and system takeover",
            },
            "xss": {
                "attack_vector": "Cross-Site Scripting payload injection into web application inputs",
                "attack_stage": "Initial Access / Collection",
                "mitre_techniques": ["T1059.007", "T1185"],
                "mitre_tactics": ["Initial Access", "Collection"],
                "attacker_objective": "Session hijacking, credential theft, or malicious redirects targeting users",
                "blast_radius": "medium - affects end users; can escalate if admin sessions are compromised",
            },
        }

        template = analysis_templates.get(
            category,
            {
                "attack_vector": f"Unclassified threat vector from {len(source_ips)} source IP(s)",
                "attack_stage": "Unknown",
                "mitre_techniques": ["T1078"],
                "mitre_tactics": ["Initial Access"],
                "attacker_objective": "Unknown — further investigation required",
                "blast_radius": "medium - impact scope undetermined",
            }
        )

        iocs = [f"ip:{ip}" for ip in source_ips[:5]]
        iocs.append(f"pattern:{str(category).upper()}_SIGNATURE")

        return {
            "threat_id": str(category),
            "attack_vector": template["attack_vector"],
            "attack_stage": template["attack_stage"],
            "affected_systems": self._identify_affected_systems(threat, logs),
            "iocs": iocs,
            "mitre_techniques": template["mitre_techniques"],
            "mitre_tactics": template["mitre_tactics"],
            "attacker_objective": template["attacker_objective"],
            "blast_radius": template["blast_radius"],
            "analysis": (
                f"Detected {category} threat with {confidence:.0%} confidence from {len(source_ips)} source IP(s). "
                f"Severity classified as {severity}. "
                f"{threat.get('description', 'Automated detection triggered by pattern matching.')}"
            ),
            "confidence_explanation": (
                f"Confidence of {confidence:.0%} based on pattern matching against known attack signatures "
                f"and behavioral analysis of {threat.get('log_count', 0)} log events."
            ),
            "urgency": "immediate" if severity == "critical" else (
                "high" if severity == "high" else "medium"

            ),
            "analysis_method": "rule_based",
        }

    def _identify_affected_systems(self, threat: Dict, logs: List[Dict]) -> List[str]:
        """Identify likely affected system types based on threat context."""
        systems = set()
        source_ips = threat.get("source_ips", [])

        for log in logs:
            if log.get("source_ip") in source_ips:
                event_type = log.get("event_type", "")
                if "ssh" in event_type or "login" in event_type:
                    systems.add("SSH Server")
                if "sql" in str(log.get("message", "")).lower():
                    systems.add("Database Server")
                if "web" in event_type or log.get("status_code"):
                    systems.add("Web Application")
                if "file" in event_type:
                    systems.add("File Server")

        if not systems:
            systems = {"Web Application", "Network Infrastructure"}

        return list(systems)

    def _generate_summary(self, threats: List[Dict], investigations: List[Dict]) -> str:
        """Generate an executive summary of the investigation."""
        if not threats:
            return "No threats detected in the analyzed log set."

        critical_count = sum(1 for t in threats if str(t.get("severity", "")).lower() in ("critical", "high"))
        categories = list(set(str(t.get("threat_category", "unknown")) for t in threats))

        mitre_techniques = []
        for inv in investigations:
            mitre_techniques.extend(inv.get("mitre_techniques", []))
        unique_techniques = list(set(mitre_techniques))

        return (
            f"Security analysis identified {len(threats)} threat(s) across {len(categories)} categories: "
            f"{', '.join(categories)}. "
            f"{critical_count} threat(s) are classified as critical or high severity requiring immediate action. "
            f"MITRE ATT&CK techniques identified: {', '.join(unique_techniques[:5])}. "
            f"Immediate remediation is {'strongly ' if critical_count > 0 else ''}recommended."
        )