"""
SecureAI Guardian - Risk Score Agent
Calculates comprehensive risk scores for detected threats using weighted heuristics.
"""

from typing import List, Dict, Any
from datetime import datetime
import logging

from app.schemas import SeverityLevel, ThreatCategory

logger = logging.getLogger(__name__)


class RiskAgent:
    """
    AI Agent for Risk Scoring and Prioritization.
    
    Scoring factors:
    - Base severity score
    - Threat category risk multiplier
    - Number of affected source IPs
    - Confidence level
    - Asset criticality
    - Attack velocity (frequency)
    - Historical context
    """

    name = "RiskAgent"
    version = "1.0.0"

    # ── Risk Weights ──────────────────────────────────────────────────────────

    SEVERITY_BASE_SCORES = {
        SeverityLevel.CRITICAL: 80.0,
        SeverityLevel.HIGH: 60.0,
        SeverityLevel.MEDIUM: 40.0,
        SeverityLevel.LOW: 20.0,
        
    }

    CATEGORY_MULTIPLIERS = {
        ThreatCategory.MALWARE: 1.3,
        ThreatCategory.DATA_EXFILTRATION: 1.25,
        ThreatCategory.SQL_INJECTION: 1.2,
        ThreatCategory.PRIVILEGE_ESCALATION: 1.2,
        ThreatCategory.DDoS: 1.15,
        ThreatCategory.BRUTE_FORCE: 1.1,
        ThreatCategory.XSS: 1.1,
        ThreatCategory.PHISHING: 1.1,
        ThreatCategory.ANOMALY: 1.0,
        ThreatCategory.UNKNOWN: 1.0,
        # # String variants
        # "malware": 1.3,
        # "data_exfiltration": 1.25,
        # "sql_injection": 1.2,
        # "privilege_escalation": 1.2,
        # "ddos": 1.15,
        # "brute_force": 1.1,
        # "xss": 1.1,
        # "phishing": 1.1,
        # "anomaly": 1.0,
        # "unknown": 1.0,
    }

    async def assess(self, threats: List[Dict[str, Any]], logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess risk for a list of detected threats.
        Returns scored threats sorted by risk score (highest first).
        """
        logger.info(f"[{self.name}] Assessing risk for {len(threats)} threats")

        scored_threats = []
        total_risk = 0.0

        for threat in threats:
            risk_score = self._calculate_risk_score(threat, logs)
            threat["risk_score"] = risk_score
            threat["risk_level"] = self._score_to_level(risk_score)
            threat["risk_factors"] = self._explain_risk(threat, risk_score)
            scored_threats.append(threat)
            total_risk += risk_score

        # Sort by risk score descending
        scored_threats.sort(key=lambda x: x["risk_score"], reverse=True)

        avg_risk = total_risk / len(scored_threats) if scored_threats else 0.0

        return {
            "agent": self.name,
            "scored_threats": scored_threats,
            "summary": {
                "total_threats": len(scored_threats),
                "average_risk_score": round(avg_risk, 2),
                "max_risk_score": round(max((t["risk_score"] for t in scored_threats), default=0), 2),
                "critical_count": sum(1 for t in scored_threats if t["risk_score"] >= 85),
                "high_count": sum(1 for t in scored_threats if 65 <= t["risk_score"] < 85),
                "medium_count": sum(1 for t in scored_threats if 40 <= t["risk_score"] < 65),
                "low_count": sum(1 for t in scored_threats if t["risk_score"] < 40),
            }
        }

    def _calculate_risk_score(self, threat: Dict, logs: List[Dict]) -> float:
        """Calculate weighted risk score (0-100)."""
        severity_raw = threat.get("severity", "medium")
        severity = SeverityLevel(severity_raw)
        category = threat.get("threat_category", "unknown")
        confidence = float(threat.get("confidence", 0.7))
        source_ips = threat.get("source_ips", [])
        log_count = threat.get("log_count", 1)

        # Base score from severity
        base_score = self.SEVERITY_BASE_SCORES.get(severity, 40.0)

        # Category multiplier
        multiplier = self.CATEGORY_MULTIPLIERS.get(category, 1.0)

        # Confidence adjustment (confidence scales score by up to ±15%)
        confidence_factor = 0.85 + (confidence * 0.3)

        # Spread factor: more attacking IPs = higher risk
        spread_bonus = min(10.0, len(source_ips) * 2.0)

        # Volume factor: more log events = higher risk
        volume_bonus = min(8.0, (log_count / 10) * 2.0)

        # Final calculation
        raw_score = (base_score * multiplier * confidence_factor) + spread_bonus + volume_bonus

        # Clamp to 0-100
        return round(min(100.0, max(0.0, raw_score)), 2)

    def _score_to_level(self, score: float) -> str:
        if score >= 85:
            return "critical"
        elif score >= 65:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"

    def _explain_risk(self, threat: Dict, score: float) -> List[str]:
        """Generate human-readable risk factor explanations."""
        factors = []

        severity = SeverityLevel(threat.get("severity", "medium"))
        if severity == SeverityLevel.CRITICAL:
            factors.append("Critical severity event type detected")
        elif severity == SeverityLevel.HIGH:
            factors.append("High severity threat indicator present")

        category = ThreatCategory(threat.get("threat_category", "unknown"))
        if category == ThreatCategory.MALWARE:
            factors.append("Malware presence indicates active compromise")
        elif category == ThreatCategory.DATA_EXFILTRATION:
            factors.append("Data exfiltration threatens confidentiality")
        elif category == ThreatCategory.SQL_INJECTION:
            factors.append("SQL injection can expose entire database")

        confidence = float(threat.get("confidence", 0.7))
        if confidence > 0.9:
            factors.append(f"High confidence detection ({confidence:.0%})")
        elif confidence < 0.6:
            factors.append(f"Lower confidence — manual review recommended ({confidence:.0%})")

        source_ips = threat.get("source_ips", [])
        if len(source_ips) > 3:
            factors.append(f"Coordinated attack from {len(source_ips)} source IPs")

        log_count = threat.get("log_count", 1)
        if log_count > 50:
            factors.append(f"High event volume: {log_count} related log entries")

        if score >= 85:
            factors.append("⚠️  Immediate response required")
        elif score >= 65:
            factors.append("🔶 High priority — investigate within 1 hour")

        return factors