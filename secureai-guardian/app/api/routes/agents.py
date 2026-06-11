"""
SecureAI Guardian - AI Agents API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List, Optional
import uuid
from datetime import datetime

from app.schemas import AgentPipelineRequest
from app.security import get_current_user
from app.storage import memory_store
from app.agents.orchestrator import AgentOrchestrator

router = APIRouter()
orchestrator = AgentOrchestrator()

# In-memory pipeline status store
pipeline_results = {}


@router.post("/pipeline/run")
async def run_agent_pipeline(
    request: AgentPipelineRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Run the multi-agent security analysis pipeline.
    Executes: ThreatAgent → RiskAgent → LLMAgent → RecommendationAgent
    """
    pipeline_id = str(uuid.uuid4())

    # Fetch logs
    logs = []
    for log_id in request.log_ids:
        log = memory_store.find_one("logs", {"_id": log_id})
        if log:
            logs.append(log)

    if not logs:
        # Use recent logs if specific IDs not found
        logs = memory_store.find("logs", {}, limit=100)

    if not logs:
        raise HTTPException(status_code=400, detail="No logs found to analyze")

    # Initialize pipeline status
    pipeline_results[pipeline_id] = {
        "pipeline_id": pipeline_id,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat(),
        "log_count": len(logs),
        "pipeline_stages": request.pipeline,
        "created_by": current_user["username"],
    }

    # Run pipeline in background
    background_tasks.add_task(
        _run_pipeline_async,
        pipeline_id=pipeline_id,
        logs=logs,
        pipeline=request.pipeline,
    )

    return {
        "pipeline_id": pipeline_id,
        "status": "queued",
        "log_count": len(logs),
        "message": f"Pipeline queued with {len(logs)} logs. Check /api/agents/pipeline/{pipeline_id} for results.",
    }


async def _run_pipeline_async(pipeline_id: str, logs: list, pipeline: list):
    """Background task to run the agent pipeline."""
    pipeline_results[pipeline_id]["status"] = "running"

    result = await orchestrator.run_pipeline(
        logs=logs,
        pipeline=pipeline,
        pipeline_id=pipeline_id,
    )

    # Save threats from pipeline
    threats = result.get("risk_assessment", {}).get("scored_threats", [])
    for threat in threats:
        threat_id = str(uuid.uuid4())
        memory_store.insert_one("threats", {
            "_id": threat_id,
            "detected_at": datetime.utcnow().isoformat(),
            "status": "open",
            "pipeline_id": pipeline_id,
            **threat,
        })

    pipeline_results[pipeline_id].update(result)


@router.get("/pipeline/{pipeline_id}")
async def get_pipeline_result(
    pipeline_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get the results of a pipeline run."""
    result = pipeline_results.get(pipeline_id)
    if not result:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    return result


@router.get("/pipeline")
async def list_pipelines(current_user: dict = Depends(get_current_user)):
    """List all pipeline runs."""
    pipelines = [
        {
            "pipeline_id": pid,
            "status": p.get("status"),
            "created_at": p.get("created_at"),
            "log_count": p.get("log_count"),
        }
        for pid, p in pipeline_results.items()
    ]
    pipelines.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"pipelines": pipelines, "total": len(pipelines)}


@router.post("/analyze/quick")
async def quick_analyze(
    current_user: dict = Depends(get_current_user)
):
    """
    Quick full analysis of all recent logs through the complete pipeline.
    Returns results synchronously (suitable for small log sets).
    """
    logs = memory_store.find("logs", {}, limit=200)

    if not logs:
        return {"message": "No logs available for analysis", "threats": []}

    result = await orchestrator.run_pipeline(logs=logs)

    # Save detected threats
    threats = result.get("risk_assessment", {}).get("scored_threats", [])
    saved_count = 0
    for threat in threats:
        # Check if similar threat already exists (avoid duplicates)
        existing = memory_store.find_one("threats", {
            "threat_category": threat.get("threat_category"),
            "status": "open",
        })
        if not existing:
            threat_id = str(uuid.uuid4())
            memory_store.insert_one("threats", {
                "_id": threat_id,
                "detected_at": datetime.utcnow().isoformat(),
                "status": "open",
                **threat,
            })
            saved_count += 1

    return {
        "analysis_complete": True,
        "logs_analyzed": len(logs),
        "new_threats_saved": saved_count,
        "result": result,
    }


@router.get("/status")
async def get_agents_status(current_user: dict = Depends(get_current_user)):
    """Get the status and capabilities of all AI agents."""
    return {
        "agents": [
            {
                "name": "ThreatAgent",
                "version": "1.0.0",
                "status": "active",
                "capabilities": [
                    "Brute Force Detection",
                    "SQL Injection Detection",
                    "XSS Detection",
                    "DDoS Detection",
                    "Malware Detection",
                    "Path Traversal Detection",
                    "Data Exfiltration Detection",
                    "Privilege Escalation Detection",
                ],
                "detection_methods": "Pattern matching + Behavioral analysis",
            },
            {
                "name": "RiskAgent",
                "version": "1.0.0",
                "status": "active",
                "capabilities": [
                    "Risk Score Calculation (0-100)",
                    "Severity Classification",
                    "Threat Prioritization",
                    "Risk Factor Explanation",
                ],
                "scoring_model": "Weighted multi-factor heuristics",
            },
            {
                "name": "LLMAgent",
                "version": "1.0.0",
                "status": "active" if orchestrator.llm_agent.use_llm else "rule-based",
                "capabilities": [
                    "MITRE ATT&CK Mapping",
                    "IOC Identification",
                    "Attack Vector Analysis",
                    "Blast Radius Assessment",
                    "Executive Summary Generation",
                ],
                "model": orchestrator.llm_agent.model if orchestrator.llm_agent.use_llm else "Rule-based fallback",
            },
            {
                "name": "RecommendationAgent",
                "version": "1.0.0",
                "status": "active",
                "capabilities": [
                    "Remediation Playbooks",
                    "Priority-based Action Planning",
                    "Automated Remediation Flags",
                    "Effort Estimation",
                ],
                "playbooks_available": 7,
            },
        ],
        "pipeline_runs": len(pipeline_results),
        "orchestrator_version": "1.0.0",
    }