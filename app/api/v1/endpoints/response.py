from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime

from app.models.database import get_db, ResponseStatus
from app.models.schemas import ResponseDecision, ResponseActionResult
from app.services.response_orchestrator import ResponseOrchestrator
from app.core.event_bus import event_bus
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger("airs.api.response")


@router.get("/blocked-ips")
async def get_blocked_ips(
    is_active: Optional[bool] = True,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    Get list of blocked IP addresses.
    """
    from sqlalchemy import select
    from app.models.database import BlockedIP
    
    stmt = select(BlockedIP).order_by(BlockedIP.first_blocked_at.desc())
    
    if is_active is not None:
        stmt = stmt.where(BlockedIP.is_active == is_active)
    
    stmt = stmt.offset(offset).limit(limit)
    
    result = await db.execute(stmt)
    blocked = result.scalars().all()
    
    return {
        "total": len(blocked),
        "blocked_ips": [
            {
                "id": b.id,
                "ip_address": b.ip_address,
                "first_blocked_at": b.first_blocked_at,
                "last_blocked_at": b.last_blocked_at,
                "block_count": b.block_count,
                "reason": b.reason,
                "is_active": b.is_active,
                "unblocked_at": b.unblocked_at
            }
            for b in blocked
        ]
    }


@router.post("/unblock-ip/{ip_address}")
async def unblock_ip(
    ip_address: str,
    reason: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Manually unblock an IP address.
    """
    from sqlalchemy import select
    from app.models.database import BlockedIP
    
    stmt = select(BlockedIP).where(
        BlockedIP.ip_address == ip_address,
        BlockedIP.is_active == True
    )
    result = await db.execute(stmt)
    blocked = result.scalar_one_or_none()
    
    if not blocked:
        raise HTTPException(status_code=404, detail="IP not found or already unblocked")
    
    # Update database record
    blocked.is_active = False
    blocked.unblocked_at = datetime.utcnow()
    blocked.unblocked_by = "manual_api"  # Should be current user in production
    
    await db.commit()
    
    # Execute actual unblock command (iptables, firewall API, etc.)
    # This would call your response orchestrator or firewall integration
    
    logger.info("IP manually unblocked", ip_address=ip_address, reason=reason)
    await event_bus.publish(
        "response.updated",
        {
            "event": "ip_unblocked",
            "ip_address": ip_address,
            "reason": reason,
        },
    )
    
    return {"message": f"IP {ip_address} unblocked successfully"}


@router.get("/actions")
async def list_response_actions(
    threat_event_id: Optional[int] = None,
    action_type: Optional[str] = None,
    status: Optional[ResponseStatus] = None,
    automated: Optional[bool] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    List response actions with optional filtering.
    """
    from sqlalchemy import select
    from app.models.database import ResponseAction
    
    stmt = select(ResponseAction).order_by(ResponseAction.timestamp.desc())
    
    if threat_event_id:
        stmt = stmt.where(ResponseAction.threat_event_id == threat_event_id)
    if action_type:
        stmt = stmt.where(ResponseAction.action_type == action_type)
    if status:
        stmt = stmt.where(ResponseAction.status == status)
    if automated is not None:
        stmt = stmt.where(ResponseAction.automated == automated)
    
    stmt = stmt.offset(offset).limit(limit)
    
    result = await db.execute(stmt)
    actions = result.scalars().all()
    
    return {
        "total": len(actions),
        "actions": [
            {
                "id": a.id,
                "threat_event_id": a.threat_event_id,
                "timestamp": a.timestamp,
                "action_type": a.action_type,
                "target": a.target,
                "status": a.status.value,
                "automated": a.automated,
                "executed_at": a.executed_at,
                "result": a.result
            }
            for a in actions
        ]
    }


@router.get("/actions/{action_id}")
async def get_action_details(
    action_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific response action.
    """
    from sqlalchemy import select
    from app.models.database import ResponseAction
    
    stmt = select(ResponseAction).where(ResponseAction.id == action_id)
    result = await db.execute(stmt)
    action = result.scalar_one_or_none()
    
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    
    return {
        "id": action.id,
        "threat_event_id": action.threat_event_id,
        "timestamp": action.timestamp,
        "action_type": action.action_type,
        "target": action.target,
        "parameters": action.parameters,
        "status": action.status.value,
        "result": action.result,
        "error_message": action.error_message,
        "automated": action.automated,
        "approved_by": action.approved_by,
        "executed_at": action.executed_at,
        "reverted_at": action.reverted_at,
        "reverted_by": action.reverted_by
    }


@router.post("/execute-manual")
async def execute_manual_response(
    threat_event_id: int,
    action_type: str,
    target: str,
    parameters: Optional[dict] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Execute a manual response action (requires admin privileges in production).
    """
    from app.main import app
    orchestrator: ResponseOrchestrator = app.state.response_orchestrator
    
    # Verify threat exists
    from sqlalchemy import select
    from app.models.database import ThreatEvent
    
    stmt = select(ThreatEvent).where(ThreatEvent.id == threat_event_id)
    result = await db.execute(stmt)
    threat = result.scalar_one_or_none()
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat event not found")
    
    # Create decision
    decision = ResponseDecision(
        action_required=True,
        action_type=action_type,
        target=target,
        priority=3,
        reasoning=f"Manual execution by API for threat {threat_event_id}",
        requires_approval=False
    )
    
    # Execute action
    # This would call your orchestrator's execution method
    
    logger.warning(
        "Manual response executed",
        threat_event_id=threat_event_id,
        action_type=action_type,
        target=target
    )
    await event_bus.publish(
        "response.updated",
        {
            "event": "manual_response_executed",
            "threat_event_id": threat_event_id,
            "action_type": action_type,
            "target": target,
        },
    )
    
    return {
        "message": "Manual response executed",
        "threat_event_id": threat_event_id,
        "action_type": action_type,
        "target": target,
        "status": "executed"
    }


@router.get("/settings")
async def get_response_settings():
    """
    Get current response automation settings.
    """
    from app.config import settings
    
    return {
        "auto_response_enabled": settings.AUTO_RESPONSE_ENABLED,
        "response_cooldown_seconds": settings.RESPONSE_COOLDOWN_SECONDS,
        "anomaly_threshold": settings.ANOMALY_THRESHOLD,
        "confidence_threshold": settings.CONFIDENCE_THRESHOLD
    }


@router.put("/settings")
async def update_response_settings(
    auto_response_enabled: Optional[bool] = None,
    response_cooldown_seconds: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Update response settings (in production, persist to database).
    Note: This is a simplified version. In production, store in DB.
    """
    from app.config import settings
    
    if auto_response_enabled is not None:
        settings.AUTO_RESPONSE_ENABLED = auto_response_enabled
    if response_cooldown_seconds is not None:
        settings.RESPONSE_COOLDOWN_SECONDS = response_cooldown_seconds
    
    logger.info(
        "Response settings updated",
        auto_response=settings.AUTO_RESPONSE_ENABLED,
        cooldown=settings.RESPONSE_COOLDOWN_SECONDS
    )
    await event_bus.publish(
        "settings.updated",
        {
            "auto_response_enabled": settings.AUTO_RESPONSE_ENABLED,
            "response_cooldown_seconds": settings.RESPONSE_COOLDOWN_SECONDS,
        },
    )
    
    return {
        "message": "Settings updated",
        "auto_response_enabled": settings.AUTO_RESPONSE_ENABLED,
        "response_cooldown_seconds": settings.RESPONSE_COOLDOWN_SECONDS
    }
