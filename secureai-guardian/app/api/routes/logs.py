"""
SecureAI Guardian - Security Logs API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Query
from typing import List, Optional
import uuid
import json
import csv
import io
from datetime import datetime

from app.schemas import SecurityLog, LogUploadRequest, LogUploadResponse, SeverityLevel
from app.security import get_current_user
from app.storage import memory_store

router = APIRouter()


@router.post("/upload", response_model=LogUploadResponse)
async def upload_logs(
    request: LogUploadRequest,
    current_user: dict = Depends(get_current_user)
):
    """Upload security logs for analysis."""
    uploaded_ids = []
    failed = 0

    for log in request.logs:
        try:
            log_id = str(uuid.uuid4())
            log_doc = {
                "_id": log_id,
                "timestamp": log.timestamp.isoformat(),
                "source_ip": log.source_ip,
                "destination_ip": log.destination_ip,
                "event_type": log.event_type,
                "message": log.message,
                "severity": log.severity.value if hasattr(log.severity, 'value') else log.severity,
                "user_agent": log.user_agent,
                "status_code": log.status_code,
                "bytes_transferred": log.bytes_transferred,
                "raw_log": log.raw_log,
                "source": request.source,
                "uploaded_by": current_user["username"],
                "uploaded_at": datetime.utcnow().isoformat(),
            }
            memory_store.insert_one("logs", log_doc)
            uploaded_ids.append(log_id)
        except Exception as e:
            failed += 1

    return LogUploadResponse(
        uploaded=len(uploaded_ids),
        failed=failed,
        log_ids=uploaded_ids,
        message=f"Successfully uploaded {len(uploaded_ids)} logs. {failed} failed."
    )


@router.post("/upload/file")
async def upload_log_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Upload logs from a file (JSON or CSV format)."""
    if not file.filename.endswith(('.json', '.csv', '.log', '.txt')):
        raise HTTPException(status_code=400, detail="Unsupported file type. Use .json, .csv, or .log")

    content = await file.read()
    logs_data = []

    try:
        if file.filename.endswith('.json'):
            data = json.loads(content)
            logs_data = data if isinstance(data, list) else [data]
        elif file.filename.endswith('.csv'):
            reader = csv.DictReader(io.StringIO(content.decode('utf-8')))
            logs_data = list(reader)
        else:
            # Plain text log format: one line per entry
            lines = content.decode('utf-8').strip().split('\n')
            for line in lines:
                if line.strip():
                    logs_data.append({
                        "source_ip": "0.0.0.0",
                        "event_type": "raw_log",
                        "message": line.strip(),
                        "severity": "low",
                        "timestamp": datetime.utcnow().isoformat(),
                    })
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse file: {str(e)}")

    uploaded_ids = []
    for log_data in logs_data[:1000]:  # Max 1000 per upload
        log_id = str(uuid.uuid4())
        memory_store.insert_one("logs", {
            "_id": log_id,
            "timestamp": log_data.get("timestamp", datetime.utcnow().isoformat()),
            "source_ip": log_data.get("source_ip", "unknown"),
            "event_type": log_data.get("event_type", "unknown"),
            "message": log_data.get("message", ""),
            "severity": log_data.get("severity", "low"),
            "uploaded_by": current_user["username"],
            "file_source": file.filename,
        })
        uploaded_ids.append(log_id)

    return {
        "uploaded": len(uploaded_ids),
        "log_ids": uploaded_ids,
        "filename": file.filename,
        "message": f"Processed {len(uploaded_ids)} log entries from {file.filename}"
    }


@router.get("/")
async def list_logs(
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """List security logs with optional filtering."""
    query = {}
    if severity:
        query["severity"] = severity
    if event_type:
        query["event_type"] = event_type
    if source_ip:
        query["source_ip"] = source_ip

    logs = memory_store.find("logs", query, limit=limit, skip=skip)
    total = memory_store.count("logs", query)

    return {
        "total": total,
        "limit": limit,
        "skip": skip,
        "logs": logs,
    }


@router.get("/{log_id}")
async def get_log(
    log_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific log entry by ID."""
    log = memory_store.find_one("logs", {"_id": log_id})
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log


@router.delete("/{log_id}")
async def delete_log(
    log_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a log entry."""
    if current_user["role"] not in ("admin",):
        raise HTTPException(status_code=403, detail="Admin access required")

    deleted = memory_store.delete_one("logs", {"_id": log_id})
    if not deleted:
        raise HTTPException(status_code=404, detail="Log not found")

    return {"message": "Log deleted successfully"}


@router.post("/generate/sample")
async def generate_sample_logs(
    count: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """Generate sample security logs for testing/demo."""
    import random
    from datetime import timedelta

    sample_events = [
        {"event_type": "failed_login", "severity": "high", "status_code": 401,
         "message": "Authentication failure: invalid credentials for user admin"},
        {"event_type": "sql_injection", "severity": "critical", "status_code": 400,
         "message": "SQL injection detected: ' OR 1=1; DROP TABLE users; --"},
        {"event_type": "port_scan", "severity": "medium", "status_code": None,
         "message": "Nmap port scan detected: SYN scan on ports 1-65535"},
        {"event_type": "xss_attempt", "severity": "high", "status_code": 400,
         "message": "XSS payload in input: <script>document.cookie</script>"},
        {"event_type": "normal_traffic", "severity": "low", "status_code": 200,
         "message": "Normal HTTP GET request to /api/v1/products"},
        {"event_type": "ddos", "severity": "critical", "status_code": None,
         "message": "DDoS flood: 75,000 SYN packets/sec from distributed sources"},
        {"event_type": "malware_detected", "severity": "critical", "status_code": 200,
         "message": "Malware detected: Ransomware.WannaCry signature in upload"},
        {"event_type": "data_transfer", "severity": "high", "bytes_transferred": 500000000,
         "message": "Large outbound transfer: 500MB to external IP 203.0.113.100"},
    ]

    source_ips = [
        "192.168.1.100", "10.0.0.50", "172.16.0.200",
        "203.0.113.45", "198.51.100.20", "192.168.2.15"
    ]

    uploaded_ids = []
    for i in range(count):
        event = random.choice(sample_events)
        log_id = str(uuid.uuid4())
        ts = datetime.utcnow() - timedelta(minutes=random.randint(0, 360))

        memory_store.insert_one("logs", {
            "_id": log_id,
            "timestamp": ts.isoformat(),
            "source_ip": random.choice(source_ips),
            "destination_ip": "10.0.0.1",
            "event_type": event["event_type"],
            "message": event["message"],
            "severity": event["severity"],
            "status_code": event.get("status_code"),
            "bytes_transferred": event.get("bytes_transferred"),
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "uploaded_by": current_user["username"],
            "generated": True,
        })
        uploaded_ids.append(log_id)

    return {
        "generated": len(uploaded_ids),
        "log_ids": uploaded_ids,
        "message": f"Generated {len(uploaded_ids)} sample logs"
    }