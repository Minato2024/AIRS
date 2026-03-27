from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from datetime import datetime, timedelta

from app.models.database import get_db
from app.models.schemas import DashboardStats, ThreatAlert, TimeSeriesData
from app.core.logging import get_logger
from app.services.mitre_attack import (
    ENTERPRISE_TACTICS,
    TACTIC_BY_NAME,
    TOTAL_ENTERPRISE_TACTICS,
    TOTAL_ENTERPRISE_TECHNIQUES,
)

router = APIRouter()
logger = get_logger("airs.api.dashboard")


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db)
):
    """
    Get comprehensive dashboard statistics.
    This is the main endpoint for the dashboard UI.
    """
    from sqlalchemy import func, select, desc
    from app.models.database import (
        HoneypotSession, ThreatEvent, ResponseAction, ThreatLevel, AttackType
    )
    
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    
    # Total sessions in last 24h
    sessions_stmt = select(func.count(HoneypotSession.id)).where(
        HoneypotSession.start_time >= last_24h
    )
    sessions_result = await db.execute(sessions_stmt)
    total_sessions_24h = sessions_result.scalar() or 0
    
    # Active threats (not resolved)
    active_threats_stmt = select(func.count(ThreatEvent.id)).where(
        ThreatEvent.status.in_(["detected", "investigating"])
    )
    active_threats_result = await db.execute(active_threats_stmt)
    active_threats = active_threats_result.scalar() or 0
    
    # Blocked IPs count
    try:
        from app.models.database import BlockedIP
        blocked_stmt = select(func.count(BlockedIP.id)).where(BlockedIP.is_active == True)
        blocked_result = await db.execute(blocked_stmt)
        blocked_ips = blocked_result.scalar() or 0
    except:
        blocked_ips = 0  # Fallback if table doesn't exist
    
    # Detection accuracy (last 7 days) - threats with high confidence
    accuracy_stmt = select(func.avg(ThreatEvent.confidence_score)).where(
        ThreatEvent.timestamp >= last_7d,
        ThreatEvent.status != "false_positive"
    )
    accuracy_result = await db.execute(accuracy_stmt)
    detection_accuracy_7d = round(accuracy_result.scalar() or 0.0, 4)
    
    # Average response time (last 7 days)
    response_time_stmt = select(
        func.count(ResponseAction.id)
    ).where(
        ResponseAction.timestamp >= last_7d,
        ResponseAction.status == "executed"
    )
    
    avg_response_time_ms = 0.0
    
    # Threats by level (last 24h)
    level_stmt = select(
        ThreatEvent.threat_level,
        func.count(ThreatEvent.id)
    ).where(
        ThreatEvent.timestamp >= last_24h
    ).group_by(ThreatEvent.threat_level)
    
    level_result = await db.execute(level_stmt)
    threats_by_level = {level.value: count for level, count in level_result.all()}
    
    # Threats by type (last 24h)
    type_stmt = select(
        ThreatEvent.attack_type,
        func.count(ThreatEvent.id)
    ).where(
        ThreatEvent.timestamp >= last_24h
    ).group_by(ThreatEvent.attack_type)
    
    type_result = await db.execute(type_stmt)
    threats_by_type = {attack_type.value: count for attack_type, count in type_result.all()}
    
    # Top source IPs (last 24h)
    top_ips_stmt = select(
        ThreatEvent.source_ip,
        func.count(ThreatEvent.id).label("count")
    ).where(
        ThreatEvent.timestamp >= last_24h
    ).group_by(ThreatEvent.source_ip).order_by(desc("count")).limit(10)
    
    top_ips_result = await db.execute(top_ips_stmt)
    top_source_ips = [
        {"ip": ip, "count": count, "country": "Unknown"}  # Add geo lookup in production
        for ip, count in top_ips_result.all()
    ]
    
    # Recent alerts (last 10)
    recent_stmt = select(ThreatEvent).order_by(
        desc(ThreatEvent.timestamp)
    ).limit(10)
    
    recent_result = await db.execute(recent_stmt)
    recent_threats = recent_result.scalars().all()
    
    recent_alerts = [
        ThreatAlert(
            id=t.id,
            timestamp=t.timestamp,
            source_ip=t.source_ip,
            threat_level=t.threat_level,
            attack_type=t.attack_type,
            confidence=t.confidence_score,
            status=t.status,
            detection_method=t.detection_method,
            details={
                "mitre_tactic": t.mitre_tactic,
                "mitre_technique": t.mitre_technique,
                "mitre_mappings": t.mitre_mappings or [],
                "signature_match": t.signature_match
            }
        )
        for t in recent_threats
    ]
    
    return DashboardStats(
        total_sessions_24h=total_sessions_24h,
        active_threats=active_threats,
        blocked_ips=blocked_ips,
        detection_accuracy_7d=detection_accuracy_7d,
        avg_response_time_ms=avg_response_time_ms,
        threats_by_level=threats_by_level,
        threats_by_type=threats_by_type,
        top_source_ips=top_source_ips,
        recent_alerts=recent_alerts
    )


@router.get("/timeline")
async def get_threat_timeline(
    hours: int = 24,
    interval: str = "hour",  # hour, day
    db: AsyncSession = Depends(get_db)
):
    """
    Get time-series data for threat timeline charts.
    """
    from sqlalchemy import func, select
    from app.models.database import ThreatEvent
    
    since = datetime.utcnow() - timedelta(hours=hours)
    
    if interval == "hour":
        # Group by hour
        stmt = select(
            func.strftime('%Y-%m-%d %H:00', ThreatEvent.timestamp).label("hour"),
            func.count(ThreatEvent.id)
        ).where(
            ThreatEvent.timestamp >= since
        ).group_by("hour").order_by("hour")
    else:
        # Group by day
        stmt = select(
            func.strftime('%Y-%m-%d', ThreatEvent.timestamp).label("day"),
            func.count(ThreatEvent.id)
        ).where(
            ThreatEvent.timestamp >= since
        ).group_by("day").order_by("day")
    
    result = await db.execute(stmt)
    data = result.all()
    
    return [
        TimeSeriesData(
            timestamp=datetime.strptime(time_str, "%Y-%m-%d %H:00" if interval == "hour" else "%Y-%m-%d"),
            value=count,
            category="threats"
        )
        for time_str, count in data
    ]


@router.get("/mitre-coverage")
async def get_mitre_coverage(
    db: AsyncSession = Depends(get_db)
):
    """
    Get MITRE ATT&CK coverage statistics.
    Shows which tactics and techniques have been observed.
    """
    from sqlalchemy import func, select
    from app.models.database import ThreatEvent
    
    events_result = await db.execute(
        select(
            ThreatEvent.mitre_tactic,
            ThreatEvent.mitre_technique,
            ThreatEvent.mitre_mappings,
        ).where(
            (ThreatEvent.mitre_tactic.isnot(None)) |
            (ThreatEvent.mitre_technique.isnot(None)) |
            (ThreatEvent.mitre_mappings.isnot(None))
        )
    )
    tactic_counts = {}
    technique_counts = {}
    for tactic_name, technique_id, mappings in events_result.all():
        if mappings:
            for mapping in mappings:
                mapped_tactic = mapping.get("tactic")
                mapped_technique = mapping.get("technique_id")
                if mapped_tactic and mapped_tactic != "Unknown":
                    tactic_counts[mapped_tactic] = tactic_counts.get(mapped_tactic, 0) + 1
                if mapped_technique and mapped_technique.startswith("T"):
                    technique_counts[mapped_technique] = technique_counts.get(mapped_technique, 0) + 1
        else:
            if tactic_name and tactic_name != "Unknown":
                tactic_counts[tactic_name] = tactic_counts.get(tactic_name, 0) + 1
            if technique_id and technique_id.startswith("T"):
                technique_counts[technique_id] = technique_counts.get(technique_id, 0) + 1
    
    observed_tactic_ids = set()
    tactic_breakdown = []
    for tactic_name, observed_count in tactic_counts.items():
        tactic_meta = TACTIC_BY_NAME.get(tactic_name)
        if tactic_meta:
            observed_tactic_ids.add(tactic_meta["id"])
            tactic_breakdown.append({
                "id": tactic_meta["id"],
                "name": tactic_meta["name"],
                "url": tactic_meta["url"],
                "technique_count": tactic_meta["technique_count"],
                "observed_count": observed_count,
            })

    technique_breakdown = [
        {
            "id": technique_id,
            "url": f"https://attack.mitre.org/techniques/{technique_id}/",
            "observed_count": count,
        }
        for technique_id, count in technique_counts.items()
        if technique_id and technique_id.startswith("T")
    ]

    tactic_coverage_percentage = round(
        len(observed_tactic_ids) / TOTAL_ENTERPRISE_TACTICS * 100, 2
    ) if observed_tactic_ids else 0
    technique_coverage_percentage = round(
        len(technique_breakdown) / TOTAL_ENTERPRISE_TECHNIQUES * 100, 2
    ) if technique_breakdown else 0

    return {
        "framework": "MITRE ATT&CK Enterprise",
        "framework_url": "https://attack.mitre.org/matrices/enterprise/",
        "matrix_version_note": "Coverage is calculated against the Enterprise ATT&CK matrix tactic catalog bundled with AIRS.",
        "total_tactics": TOTAL_ENTERPRISE_TACTICS,
        "total_techniques": TOTAL_ENTERPRISE_TECHNIQUES,
        "tactics_observed": len(observed_tactic_ids),
        "techniques_observed": len(technique_breakdown),
        "tactic_coverage_percentage": tactic_coverage_percentage,
        "technique_coverage_percentage": technique_coverage_percentage,
        "coverage_percentage": tactic_coverage_percentage,
        "tactic_breakdown": tactic_breakdown,
        "technique_breakdown": technique_breakdown,
        "matrix_tactics": ENTERPRISE_TACTICS,
    }


@router.get("/system-health")
async def get_system_health():
    """
    Get system health status.
    """
    from app.main import app
    
    components = {
        "api": "ok",
        "database": "ok",  # Would check actual connection in production
        "detection_engine": "loaded" if hasattr(app.state, 'detection_engine') else "error",
        "response_orchestrator": "loaded" if hasattr(app.state, 'response_orchestrator') else "error"
    }
    
    # Determine overall status
    if all(v in ["ok", "loaded"] for v in components.values()):
        status = "healthy"
    elif any(v == "error" for v in components.values()):
        status = "unhealthy"
    else:
        status = "degraded"
    
    return {
        "status": status,
        "version": "1.0.0",
        "timestamp": datetime.utcnow(),
        "components": components
    }


# ============== WEBSOCKET FOR REAL-TIME UPDATES ==============

class ConnectionManager:
    """Manage WebSocket connections for real-time dashboard updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


@router.websocket("/ws")
async def dashboard_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time dashboard updates.
    Clients receive notifications when new threats are detected.
    """
    await manager.connect(websocket)
    
    try:
        while True:
            # Wait for client messages (ping/keepalive)
            data = await websocket.receive_text()
            
            # Echo back or handle commands
            if data == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
            elif data == "subscribe":
                await websocket.send_json({"type": "subscribed", "channels": ["threats", "stats"]})
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


async def broadcast_threat_alert(alert: ThreatAlert):
    """Helper function to broadcast new threat to all connected clients"""
    await manager.broadcast({
        "type": "new_threat",
        "data": alert.dict()
    })


async def broadcast_stats_update():
    """Broadcast stats update to all clients"""
    await manager.broadcast({
        "type": "stats_update",
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_system_event(event_type: str, payload: dict | None = None):
    """Broadcast a generic backend event to connected dashboard clients."""
    await manager.broadcast({
        "type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "data": payload or {}
    })
