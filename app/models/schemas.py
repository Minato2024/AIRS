from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    MALWARE = "malware"
    BRUTE_FORCE = "brute_force"
    UNKNOWN = "unknown"


class ResponseStatus(str, Enum):
    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"
    REVERTED = "reverted"

class HoneypotLog(BaseModel):
    """Incoming honeypot log schema"""
    timestamp: datetime
    honeypot_type: str = Field(..., description="Type: cowrie, dionaea, tpot, etc.")
    session_id: str
    source_ip: str
    source_port: int
    dest_port: int
    protocol: str = "tcp"
    event_type: str  # login_attempt, command_execution, file_upload, etc.
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    payload: Optional[str] = None
    meta_data: Dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    """Output from detection engine"""
    threat_detected: bool
    threat_level: str  # low, medium, high, critical
    attack_type: Optional[str] = None
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    detection_method: str  # signature, anomaly, hybrid
    signature_match: Optional[str] = None
    anomaly_score: Optional[float] = None
    mitre_mapping: Optional[Dict[str, str]] = None
    mitre_mappings: List[Dict[str, str]] = Field(default_factory=list)
    features: Dict[str, Any] = Field(default_factory=dict)
    recommendation: Optional[str] = None

class DetectionRequest(BaseModel):
    """Request to manually analyze data"""
    log_data: HoneypotLog
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)

class ResponseDecision(BaseModel):
    """Automated response decision"""
    action_required: bool
    action_type: Optional[str] = None  # block_ip, throttle, isolate, alert
    target: Optional[str] = None
    priority: int = Field(..., ge=1, le=5)
    reasoning: str
    estimated_impact: Optional[str] = None
    requires_approval: bool = False

class ResponseActionCreate(BaseModel):
    """Create a response action"""
    threat_event_id: int
    action_type: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    automated: bool = True


class ResponseActionResult(BaseModel):
    """Result of executed response"""
    id: int
    threat_event_id: int
    timestamp: datetime
    action_type: str
    target: str
    status: ResponseStatus
    result: Optional[Dict[str, Any]] = None
    automated: bool
    executed_by: Optional[str] = None

class ThreatAlert(BaseModel):
    """Real-time alert schema for WebSocket"""
    id: int
    timestamp: datetime
    source_ip: str
    threat_level: str
    attack_type: str
    confidence: float
    status: str
    details: Dict[str, Any]

class TimeSeriesData(BaseModel):
    """For charts/graphs"""
    timestamp: datetime
    value: int
    category: Optional[str] = None

class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_sessions_24h: int
    active_threats: int
    blocked_ips: int
    detection_accuracy_7d: float
    avg_response_time_ms: float
    threats_by_level: Dict[str, int]
    threats_by_type: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    recent_alerts: List[ThreatAlert]
