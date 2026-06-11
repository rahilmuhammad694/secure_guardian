"""
SecureAI Guardian - Dashboard API Routes
"""

from fastapi import APIRouter, Depends
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List

from app.security import get_current_user
from app.storage import memory_store

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get all KPI statistics for the main dashboard."""
    all_logs = memory_store.find("logs", {}, limit=100000)
    all_threats = memory_store.find("threats", {}, limit=100000)

    now = datetime.utcnow()
    cutoff_24h = (now - timedelta(hours=24)).isoformat()

    # Filter last 24h
    logs_24h = [l for l in all_logs if l.get("timestamp", "") >= cutoff_24h]
    threats_24h = [t for t in all_threats if t.get("detected_at", "") >= cutoff_24h]

    # Severity distribution
    severity_dist = defaultdict(int)
    for t in all_threats:
        sev = t.get("severity", "unknown")
        severity_dist[sev] += 1

    # Status distribution
    status_dist = defaultdict(int)
    for t in all_threats:
        status_dist[t.get("status", "unknown")] += 1

    # Category distribution
    category_dist = defaultdict(int)
    for t in all_threats:
        category_dist[t.get("threat_category", "unknown")] += 1

    top_categories = sorted(
        [{"category": k, "count": v} for k, v in category_dist.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:6]

    # Average risk score
    risk_scores = [float(t.get("risk_score", 0)) for t in all_threats if t.get("risk_score")]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    # Recent threats (last 10)
    recent_threats = sorted(
        all_threats,
        key=lambda x: x.get("detected_at", ""),
        reverse=True
    )[:10]

    return {
        # KPI Cards
        "total_logs": len(all_logs),
        "total_threats": len(all_threats),
        "critical_threats": severity_dist.get("critical", 0),
        "high_threats": severity_dist.get("high", 0),
        "open_incidents": status_dist.get("open", 0) + status_dist.get("investigating", 0),
        "resolved_incidents": status_dist.get("resolved", 0) + status_dist.get("mitigated", 0),
        "avg_risk_score": avg_risk,
        "threats_last_24h": len(threats_24h),
        "logs_last_24h": len(logs_24h),

        # Chart data
        "top_threat_categories": top_categories,
        "severity_distribution": dict(severity_dist),
        "status_distribution": dict(status_dist),

        # Table data
        "recent_threats": recent_threats,
    }


@router.get("/timeline")
async def get_threat_timeline(
    hours: int = 24,
    current_user: dict = Depends(get_current_user)
):
    """Get threat detection timeline for charts."""
    all_threats = memory_store.find("threats", {}, limit=100000)
    now = datetime.utcnow()

    # Build hourly buckets
    buckets = {}
    for i in range(hours):
        hour_key = (now - timedelta(hours=hours - i - 1)).strftime("%H:00")
        buckets[hour_key] = {"hour": hour_key, "threats": 0, "critical": 0, "high": 0}

    for threat in all_threats:
        detected_at = threat.get("detected_at", "")
        try:
            dt = datetime.fromisoformat(detected_at.replace("Z", "+00:00").replace("+00:00", ""))
            if (now - dt).total_seconds() < hours * 3600:
                hour_key = dt.strftime("%H:00")
                if hour_key in buckets:
                    buckets[hour_key]["threats"] += 1
                    sev = threat.get("severity", "")
                    if sev == "critical":
                        buckets[hour_key]["critical"] += 1
                    elif sev == "high":
                        buckets[hour_key]["high"] += 1
        except Exception:
            pass

    return {"timeline": list(buckets.values()), "period_hours": hours}


@router.get("/top-ips")
async def get_top_attacker_ips(
    limit: int = 10,
    current_user: dict = Depends(get_current_user)
):
    """Get top attacking IP addresses."""
    all_threats = memory_store.find("threats", {}, limit=100000)

    ip_counts = defaultdict(lambda: {"count": 0, "max_severity": "low", "categories": set()})
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for threat in all_threats:
        for ip in threat.get("source_ips", []):
            ip_counts[ip]["count"] += 1
            sev = threat.get("severity", "low")
            current_max = ip_counts[ip]["max_severity"]
            if severity_order.get(sev, 0) > severity_order.get(current_max, 0):
                ip_counts[ip]["max_severity"] = sev
            ip_counts[ip]["categories"].add(str(threat.get("threat_category", "unknown")))

    top_ips = sorted(
        [
            {
                "ip": ip,
                "threat_count": data["count"],
                "max_severity": data["max_severity"],
                "categories": list(data["categories"]),
            }
            for ip, data in ip_counts.items()
        ],
        key=lambda x: x["threat_count"],
        reverse=True
    )[:limit]

    return {"top_attacker_ips": top_ips}


@router.get("/risk-trend")
async def get_risk_trend(current_user: dict = Depends(get_current_user)):
    """Get risk score trend over time."""
    all_threats = memory_store.find("threats", {}, limit=10000)

    trend = sorted(
        [
            {
                "timestamp": t.get("detected_at", ""),
                "risk_score": float(t.get("risk_score", 0)),
                "severity": t.get("severity", "low"),
                "category": t.get("threat_category", "unknown"),
            }
            for t in all_threats if t.get("risk_score")
        ],
        key=lambda x: x["timestamp"]
    )[-50:]  # Last 50 data points

    return {"risk_trend": trend}