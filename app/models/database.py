from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean, Text, Enum, ForeignKey, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import enum

from app.config import settings

Base = declarative_base()

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True
)

# Create session factory
async_session = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


# ============== ENUMS ==============

class ThreatLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, enum.Enum):
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    MALWARE = "malware"
    BRUTE_FORCE = "brute_force"
    UNKNOWN = "unknown"


class ResponseStatus(str, enum.Enum):
    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"
    REVERTED = "reverted"


# ============== DATABASE MODELS ==============

class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), unique=True, index=True, nullable=False)
    honeypot_type = Column(String(50), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10), default="tcp")
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    commands = Column(JSON, default=list)
    payload = Column(Text, nullable=True)
    meta_data = Column(JSON, default=dict)
    
    # Relationships - simplified, no back_populates initially
    # threat_events = relationship("ThreatEvent", back_populates="session")
    
    def __repr__(self):
        return f"<HoneypotSession(id={self.id}, ip={self.source_ip})>"


class ThreatEvent(Base):
    __tablename__ = "threat_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    session_id = Column(String(100), ForeignKey("honeypot_sessions.session_id"), index=True)
    source_ip = Column(String(45), index=True, nullable=False)
    
    # Detection results
    threat_level = Column(Enum(ThreatLevel), nullable=False)
    attack_type = Column(Enum(AttackType), default=AttackType.UNKNOWN)
    confidence_score = Column(Float, nullable=False)
    detection_method = Column(String(20), default="unknown")
    
    # Detailed detection info
    signature_match = Column(String(100), nullable=True)
    anomaly_score = Column(Float, nullable=True)
    features = Column(JSON, default=dict)
    raw_data = Column(Text, nullable=True)
    
    # MITRE ATT&CK mapping
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(20), nullable=True)
    
    # Status tracking
    status = Column(String(20), default="detected")
    assigned_to = Column(String(100), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships - simplified
    # session = relationship("HoneypotSession", back_populates="threat_events")
    # response_actions = relationship("ResponseAction", back_populates="threat_event")
    
    def __repr__(self):
        return f"<ThreatEvent(id={self.id}, level={self.threat_level})>"


class ResponseAction(Base):
    __tablename__ = "response_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_event_id = Column(Integer, ForeignKey("threat_events.id"), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Action details
    action_type = Column(String(50), nullable=False)
    target = Column(String(100), nullable=False)
    parameters = Column(JSON, default=dict)
    status = Column(Enum(ResponseStatus), default=ResponseStatus.PENDING)
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Execution tracking
    automated = Column(Boolean, default=True)
    approved_by = Column(String(100), nullable=True)
    executed_at = Column(DateTime, nullable=True)
    reverted_at = Column(DateTime, nullable=True)
    reverted_by = Column(String(100), nullable=True)
    
    # Relationships - simplified
    # threat_event = relationship("ThreatEvent", back_populates="response_actions")
    
    def __repr__(self):
        return f"<ResponseAction(id={self.id}, type={self.action_type})>"


class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    first_blocked_at = Column(DateTime, default=datetime.utcnow)
    last_blocked_at = Column(DateTime, default=datetime.utcnow)
    block_count = Column(Integer, default=1)
    reason = Column(String(255), nullable=True)
    threat_event_id = Column(Integer, ForeignKey("threat_events.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    unblocked_at = Column(DateTime, nullable=True)
    unblocked_by = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<BlockedIP(ip={self.ip_address})>"


class MLModel(Base):
    __tablename__ = "ml_models"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    model_type = Column(String(50), nullable=False)
    version = Column(String(20), default="1.0.0")
    file_path = Column(String(255), nullable=False)
    training_date = Column(DateTime, default=datetime.utcnow)
    training_data_size = Column(Integer, nullable=True)
    accuracy = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    is_active = Column(Boolean, default=True)
    hyperparameters = Column(JSON, default=dict)
    description = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<MLModel(name={self.name})>"


class SystemLog(Base):
    __tablename__ = "system_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    level = Column(String(20), default="INFO")
    component = Column(String(50), nullable=False)
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    source_ip = Column(String(45), nullable=True)
    session_id = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<SystemLog(level={self.level})>"


# ============== DATABASE UTILITIES ==============

def _ensure_sqlite_column(sync_conn, table_name: str, column_name: str, column_type: str):
    """Ensure a column exists in SQLite table; add it if missing."""
    result = sync_conn.execute(text(f"PRAGMA table_info({table_name})"))
    existing_columns = [row[1] for row in result.fetchall()]
    if column_name not in existing_columns:
        sync_conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


async def init_db():
    """Initialize database tables and perform lightweight migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Light migrations for SQLite development.
        # This handles schema drift when fields are added after tables existed.
        if conn.dialect.name == "sqlite":
            await conn.run_sync(lambda sync_conn: _ensure_sqlite_column(sync_conn, "threat_events", "detection_method", "VARCHAR(20) DEFAULT 'unknown'"))
            await conn.run_sync(lambda sync_conn: _ensure_sqlite_column(sync_conn, "threat_events", "assigned_to", "VARCHAR(100) DEFAULT NULL"))
            await conn.run_sync(lambda sync_conn: _ensure_sqlite_column(sync_conn, "threat_events", "resolution_notes", "TEXT DEFAULT NULL"))
            await conn.run_sync(lambda sync_conn: _ensure_sqlite_column(sync_conn, "threat_events", "resolved_at", "DATETIME DEFAULT NULL"))


async def get_db() -> AsyncSession:
    """Dependency for database sessions"""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def close_db():
    """Close database connections"""
    await engine.dispose()