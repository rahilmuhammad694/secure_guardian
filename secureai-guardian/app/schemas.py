"""
SecureAI Guardian - Data Models
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DDoS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"


# ─── User Models ────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    password: str
    email: str
    role: str = "analyst"


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    username: str
    email: str
    role: str
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str


# ─── Security Log Models ─────────────────────────────────────────────────────

class SecurityLog(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str
    message: str
    severity: SeverityLevel = SeverityLevel.LOW
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    bytes_transferred: Optional[int] = None
    geo_location: Optional[Dict[str, str]] = None
    raw_log: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class LogUploadRequest(BaseModel):
    logs: List[SecurityLog]
    source: str = "manual"


class LogUploadResponse(BaseModel):
    uploaded: int
    failed: int
    log_ids: List[str]
    message: str


# ─── Threat Models ───────────────────────────────────────────────────────────

class ThreatIndicator(BaseModel):
    indicator_type: str
    value: str
    confidence: float
    description: str


class ThreatDetection(BaseModel):
    id: Optional[str] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    log_ids: List[str] = []
    threat_category: ThreatCategory
    severity: SeverityLevel
    risk_score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    source_ips: List[str] = []
    indicators: List[ThreatIndicator] = []
    description: str
    status: str = "open"
    assigned_to: Optional[str] = None


class ThreatAnalysisRequest(BaseModel):
    log_ids: Optional[List[str]] = None
    time_window_minutes: int = 60
    auto_remediate: bool = False


# ─── Agent Models ────────────────────────────────────────────────────────────

class AgentTask(BaseModel):
    task_id: str
    agent_name: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    input_data: Dict[str, Any] = {}
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class AgentPipelineRequest(BaseModel):
    log_ids: List[str]
    pipeline: List[str] = ["threat", "risk", "llm", "recommendation"]
    priority: str = "normal"


class AgentPipelineResponse(BaseModel):
    pipeline_id: str
    status: str
    tasks: List[AgentTask]
    threat_detection: Optional[Dict] = None
    risk_assessment: Optional[Dict] = None
    llm_investigation: Optional[Dict] = None
    recommendations: Optional[List[Dict]] = None
    summary: Optional[str] = None


# ─── Investigation Models ─────────────────────────────────────────────────────

class LLMInvestigationResult(BaseModel):
    threat_id: str
    analysis: str
    attack_vector: str
    affected_systems: List[str]
    iocs: List[str]  # Indicators of Compromise
    mitre_techniques: List[str]
    confidence_explanation: str


class RemediationRecommendation(BaseModel):
    priority: int
    action: str
    category: str
    description: str
    implementation_steps: List[str]
    estimated_effort: str
    automated: bool = False


# ─── Dashboard Models ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_logs: int
    total_threats: int
    critical_threats: int
    high_threats: int
    open_incidents: int
    resolved_incidents: int
    avg_risk_score: float
    threats_last_24h: int
    logs_last_24h: int
    top_threat_categories: List[Dict[str, Any]]
    severity_distribution: Dict[str, int]
    recent_threats: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]