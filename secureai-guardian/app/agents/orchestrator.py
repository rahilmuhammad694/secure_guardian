"""
SecureAI Guardian - Agent Orchestrator
Coordinates multi-agent pipeline execution for comprehensive threat analysis.
"""

import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
import asyncio

from app.agents.threat_agent import ThreatAgent
from app.agents.risk_agent import RiskAgent
from app.agents.llm_agent import LLMAgent
from app.agents.recommendation_agent import RecommendationAgent

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Orchestrates the multi-agent security analysis pipeline.
    
    Pipeline:
    1. ThreatAgent    → Detect threats from raw logs
    2. RiskAgent      → Score and prioritize threats
    3. LLMAgent       → Deep investigation with AI
    4. RecommendationAgent → Generate remediation plan
    """

    def __init__(self):
        self.threat_agent = ThreatAgent()
        self.risk_agent = RiskAgent()
        self.llm_agent = LLMAgent()
        self.recommendation_agent = RecommendationAgent()

    async def run_pipeline(
        self,
        logs: List[Dict[str, Any]],
        pipeline: Optional[List[str]] = None,
        pipeline_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute the full multi-agent analysis pipeline.
        
        Args:
            logs: List of security log records
            pipeline: Which agents to run (default: all)
            pipeline_id: Unique ID for this pipeline run
        
        Returns:
            Comprehensive analysis result
        """
        if pipeline_id is None:
            pipeline_id = str(uuid.uuid4())

        if pipeline is None:
            pipeline = ["threat", "risk", "llm", "recommendation"]

        logger.info(f"[Orchestrator] Starting pipeline {pipeline_id} with {len(logs)} logs")
        start_time = datetime.utcnow()

        result = {
            "pipeline_id": pipeline_id,
            "status": "running",
            "started_at": start_time.isoformat(),
            "log_count": len(logs),
            "pipeline_stages": pipeline,
        }

        try:
            # ── Stage 1: Threat Detection ──────────────────────────────────
            if "threat" in pipeline:
                logger.info(f"[Orchestrator] Stage 1: Threat Detection")
                threat_result = await self.threat_agent.analyze(logs)
                result["threat_detection"] = threat_result
                threats = threat_result.get("threats", [])
                logger.info(f"[Orchestrator] Stage 1 complete: {len(threats)} threats detected")
            else:
                threats = []
                result["threat_detection"] = {"threats": [], "metadata": {"skipped": True}}

            # ── Stage 2: Risk Assessment ───────────────────────────────────
            if "risk" in pipeline and threats:
                logger.info(f"[Orchestrator] Stage 2: Risk Assessment")
                risk_result = await self.risk_agent.assess(threats, logs)
                result["risk_assessment"] = risk_result
                threats = risk_result.get("scored_threats", threats)
                logger.info(f"[Orchestrator] Stage 2 complete: avg risk {risk_result['summary']['average_risk_score']}")
            else:
                result["risk_assessment"] = {"summary": {"skipped": True}}

            # ── Stage 3: LLM Investigation ─────────────────────────────────
            if "llm" in pipeline and threats:
                logger.info(f"[Orchestrator] Stage 3: LLM Investigation")
                llm_result = await self.llm_agent.investigate(threats, logs)
                result["llm_investigation"] = llm_result
                investigations = llm_result.get("investigations", [])
                logger.info(f"[Orchestrator] Stage 3 complete: {len(investigations)} investigations")
            else:
                investigations = []
                result["llm_investigation"] = {"investigations": [], "skipped": True}

            # ── Stage 4: Recommendations ───────────────────────────────────
            if "recommendation" in pipeline and threats:
                logger.info(f"[Orchestrator] Stage 4: Recommendations")
                rec_result = await self.recommendation_agent.recommend(threats, investigations)
                result["recommendations"] = rec_result
                logger.info(f"[Orchestrator] Stage 4 complete: {rec_result['total_recommendations']} recommendations")
            else:
                result["recommendations"] = {"recommendations": [], "skipped": True}

            # ── Pipeline Summary ───────────────────────────────────────────
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            result.update({
                "status": "completed",
                "completed_at": end_time.isoformat(),
                "duration_seconds": duration,
                "summary": self._generate_pipeline_summary(result, threats, duration),
            })

            logger.info(f"[Orchestrator] Pipeline {pipeline_id} completed in {duration:.2f}s")

        except Exception as e:
            logger.error(f"[Orchestrator] Pipeline {pipeline_id} failed: {e}")
            result["status"] = "failed"
            result["error"] = str(e)

        return result

    def _generate_pipeline_summary(self, result: Dict, threats: List[Dict], duration: float) -> Dict:
        """Generate executive summary of pipeline results."""
        threat_detection = result.get("threat_detection", {})
        risk_assessment = result.get("risk_assessment", {})
        recommendations = result.get("recommendations", {})

        risk_summary = risk_assessment.get("summary", {})
        total_threats = len(threats)
        critical = risk_summary.get("critical_count", 0)
        high = risk_summary.get("high_count", 0)
        avg_risk = risk_summary.get("average_risk_score", 0)

        total_recs = recommendations.get("total_recommendations", 0)
        immediate_actions = len(recommendations.get("immediate_actions", []))

        overall_status = (
            "CRITICAL" if critical > 0 else
            "HIGH RISK" if high > 0 else
            "MEDIUM RISK" if total_threats > 0 else
            "CLEAN"
        )

        return {
            "overall_status": overall_status,
            "total_threats": total_threats,
            "critical_threats": critical,
            "high_threats": high,
            "average_risk_score": avg_risk,
            "total_recommendations": total_recs,
            "immediate_actions_required": immediate_actions,
            "analysis_duration_seconds": duration,
            "llm_method": result.get("llm_investigation", {}).get("analysis_method", "none"),
        }