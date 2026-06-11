"""
SecureAI Guardian - Threat Detection API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Optional, List
import uuid
from datetime import datetime

from app.schemas import ThreatAnalysisRequest, SeverityLevel
from app.security import get_current_user
from app.storage import memory_store
from app.agents.threat_agent import ThreatAgent
from app.agents.risk_agent import RiskAgent

router = APIRouter()

threat_agent = ThreatAgent()
risk_agent = RiskAgent()


@router.post("/analyze")
async def analyze_threats(
    request: ThreatAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Run threat detection analysis on specified logs or recent logs.
    Uses the ThreatAgent + RiskAgent pipeline.
    """
    # Fetch logs to analyze
    if request.log_ids:
        logs = [
            memory_store.find_one("logs", {"_id": lid})
            for lid in request.log_ids
        ]
        logs = [l for l in logs if l]
    else:
        logs = memory_store.find("logs", {}, limit=500)

    if not logs:
        return {"message": "No logs found for analysis", "threats": []}

    # Run threat detection
    threat_result = await threat_agent.analyze(logs)
    threats = threat_result.get("threats", [])

    # Run risk scoring
    if threats:
        risk_result = await risk_agent.assess(threats, logs)
        threats = risk_result.get("scored_threats", threats)

    # Persist threats to storage
    saved_ids = []
    for threat in threats:
        threat_id = str(uuid.uuid4())
        memory_store.insert_one("threats", {
            "_id": threat_id,
            "detected_at": datetime.utcnow().isoformat(),
            "status": "open",
            "detected_by": current_user["username"],
            **threat,
        })
        saved_ids.append(threat_id)

    return {
        "analyzed_logs": len(logs),
        "threats_detected": len(threats),
        "threat_ids": saved_ids,
        "threats": threats,
        "metadata": threat_result.get("metadata", {}),
    }


@router.get("/")
async def list_threats(
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """List all detected threats with filtering."""
    query = {}
    if severity:
        query["severity"] = severity
    if status:
        query["status"] = status
    if category:
        query["threat_category"] = category

    threats = memory_store.find("threats", query, limit=limit, skip=skip)
    total = memory_store.count("threats", query)

    return {
        "total": total,
        "limit": limit,
        "skip": skip,
        "threats": threats,
    }


@router.get("/{threat_id}")
async def get_threat(
    threat_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific threat by ID."""
    threat = memory_store.find_one("threats", {"_id": threat_id})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@router.patch("/{threat_id}/status")
async def update_threat_status(
    threat_id: str,
    status: str,
    current_user: dict = Depends(get_current_user)
):
    """Update the status of a threat (open/investigating/mitigated/resolved)."""
    valid_statuses = {"open", "investigating", "mitigated", "resolved", "false_positive"}
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Valid: {valid_statuses}"
        )

    threat = memory_store.find_one("threats", {"_id": threat_id})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    memory_store.update_one(
        "threats",
        {"_id": threat_id},
        {"$set": {
            "status": status,
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": current_user["username"],
        }}
    )

    return {"message": f"Threat status updated to '{status}'", "threat_id": threat_id}


@router.patch("/{threat_id}/assign")
async def assign_threat(
    threat_id: str,
    assignee: str,
    current_user: dict = Depends(get_current_user)
):
    """Assign a threat to a user for investigation."""
    threat = memory_store.find_one("threats", {"_id": threat_id})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    memory_store.update_one(
        "threats",
        {"_id": threat_id},
        {"$set": {
            "assigned_to": assignee,
            "assigned_at": datetime.utcnow().isoformat(),
            "assigned_by": current_user["username"],
        }}
    )
    return {"message": f"Threat assigned to {assignee}", "threat_id": threat_id}


@router.get("/stats/summary")
async def get_threat_stats(current_user: dict = Depends(get_current_user)):
    """Get aggregated threat statistics."""
    all_threats = memory_store.find("threats", {}, limit=10000)

    stats = {
        "total": len(all_threats),
        "by_severity": {},
        "by_category": {},
        "by_status": {},
        "avg_risk_score": 0,
    }

    total_risk = 0
    for t in all_threats:
        sev = t.get("severity", "unknown")
        stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

        cat = t.get("threat_category", "unknown")
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

        st = t.get("status", "unknown")
        stats["by_status"][st] = stats["by_status"].get(st, 0) + 1

        total_risk += float(t.get("risk_score", 0))

    if all_threats:
        stats["avg_risk_score"] = round(total_risk / len(all_threats), 2)

    return stats