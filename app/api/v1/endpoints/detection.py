from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime, timedelta

from app.models.database import get_db
from app.models.schemas import DetectionResult, DetectionRequest, ThreatLevel, AttackType
from app.services.detection_engine import DetectionEngine
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger("airs.api.detection")


@router.post("/analyze", response_model=DetectionResult)
async def analyze_log(
    request: DetectionRequest
):
    """
    Manually analyze a honeypot log for threats.
    This endpoint allows testing the detection engine without ingesting data.
    """
    # Get detection engine from app state
    from app.main import app
    detection_engine = app.state.detection_engine
    
    logger.info(
        "Manual analysis requested",
        source_ip=request.log_data.source_ip,
        event_type=request.log_data.event_type
    )
    
    result = await detection_engine.analyze(request.log_data)
    
    return result


@router.get("/stats")
async def get_detection_stats(
    hours: int = Query(default=24, ge=1, le=168, description="Time window in hours"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detection statistics for the specified time window.
    """
    from sqlalchemy import func, select
    from app.models.database import ThreatEvent
    
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Query statistics
    stmt = select(
        func.count(ThreatEvent.id).label("total"),
        func.avg(ThreatEvent.confidence_score).label("avg_confidence")
    ).where(ThreatEvent.timestamp >= since)
    
    result = await db.execute(stmt)
    stats = result.one()
    
    # Count by threat level
    level_stmt = select(
        ThreatEvent.threat_level,
        func.count(ThreatEvent.id)
    ).where(
        ThreatEvent.timestamp >= since
    ).group_by(ThreatEvent.threat_level)
    
    level_result = await db.execute(level_stmt)
    by_level = {level.value: count for level, count in level_result.all()}
    
    # Count by attack type
    type_stmt = select(
        ThreatEvent.attack_type,
        func.count(ThreatEvent.id)
    ).where(
        ThreatEvent.timestamp >= since
    ).group_by(ThreatEvent.attack_type)
    
    type_result = await db.execute(type_stmt)
    by_type = {attack_type.value: count for attack_type, count in type_result.all()}
    
    return {
        "time_window_hours": hours,
        "total_detections": stats.total or 0,
        "average_confidence": round(stats.avg_confidence or 0, 4),
        "by_threat_level": by_level,
        "by_attack_type": by_type
    }


@router.get("/threats")
async def list_threats(
    threat_level: Optional[ThreatLevel] = None,
    attack_type: Optional[AttackType] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    List detected threats with optional filtering.
    """
    from sqlalchemy import select
    from app.models.database import ThreatEvent
    
    # Build query
    stmt = select(ThreatEvent).order_by(ThreatEvent.timestamp.desc())
    
    if threat_level:
        stmt = stmt.where(ThreatEvent.threat_level == threat_level)
    if attack_type:
        stmt = stmt.where(ThreatEvent.attack_type == attack_type)
    if status:
        stmt = stmt.where(ThreatEvent.status == status)
    if source_ip:
        stmt = stmt.where(ThreatEvent.source_ip == source_ip)
    
    # Apply pagination
    stmt = stmt.offset(offset).limit(limit)
    
    result = await db.execute(stmt)
    threats = result.scalars().all()
    
    return {
        "total": len(threats),
        "limit": limit,
        "offset": offset,
        "threats": [
            {
                "id": t.id,
                "timestamp": t.timestamp,
                "source_ip": t.source_ip,
                "threat_level": t.threat_level.value,
                "attack_type": t.attack_type.value,
                "confidence_score": t.confidence_score,
                "detection_method": t.detection_method,
                "status": t.status
            }
            for t in threats
        ]
    }


@router.get("/threats/{threat_id}")
async def get_threat_details(
    threat_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific threat.
    """
    from sqlalchemy import select
    from app.models.database import ThreatEvent
    
    stmt = select(ThreatEvent).where(ThreatEvent.id == threat_id)
    result = await db.execute(stmt)
    threat = result.scalar_one_or_none()
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return {
        "id": threat.id,
        "timestamp": threat.timestamp,
        "session_id": threat.session_id,
        "source_ip": threat.source_ip,
        "threat_level": threat.threat_level.value,
        "attack_type": threat.attack_type.value,
        "confidence_score": threat.confidence_score,
        "detection_method": threat.detection_method,
        "signature_match": threat.signature_match,
        "anomaly_score": threat.anomaly_score,
        "features": threat.features,
        "mitre_tactic": threat.mitre_tactic,
        "mitre_technique": threat.mitre_technique,
        "status": threat.status,
        "assigned_to": threat.assigned_to,
        "resolution_notes": threat.resolution_notes,
        "resolved_at": threat.resolved_at
    }


@router.patch("/threats/{threat_id}/status")
async def update_threat_status(
    threat_id: int,
    status: str,
    notes: Optional[str] = None,
    assigned_to: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Update the status of a threat (for manual investigation workflow).
    """
    from sqlalchemy import select
    from app.models.database import ThreatEvent
    
    stmt = select(ThreatEvent).where(ThreatEvent.id == threat_id)
    result = await db.execute(stmt)
    threat = result.scalar_one_or_none()
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Update fields
    threat.status = status
    if notes:
        threat.resolution_notes = notes
    if assigned_to:
        threat.assigned_to = assigned_to
    
    if status in ["resolved", "false_positive"]:
        threat.resolved_at = datetime.utcnow()
    
    await db.commit()
    
    logger.info(
        "Threat status updated",
        threat_id=threat_id,
        new_status=status,
        assigned_to=assigned_to
    )
    from app.api.v1.endpoints.dashboard import broadcast_stats_update, broadcast_system_event
    await broadcast_stats_update()
    await broadcast_system_event(
        "threat_status_changed",
        {
            "threat_id": threat_id,
            "status": status,
            "assigned_to": assigned_to,
        },
    )
    
    return {"message": "Threat status updated", "threat_id": threat_id, "status": status}
