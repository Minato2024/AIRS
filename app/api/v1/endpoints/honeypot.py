from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime, timedelta

from app.models.database import async_session, get_db
from app.models.schemas import HoneypotLog, DetectionResult, ThreatAlert
from app.services.detection_engine import DetectionEngine
from app.services.response_orchestrator import ResponseOrchestrator
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger("airs.api.honeypot")

# Global references - will be set in main.py
detection_engine: DetectionEngine = None
response_orchestrator: ResponseOrchestrator = None

def set_services(de: DetectionEngine, ro: ResponseOrchestrator):
    """Set global service references"""
    global detection_engine, response_orchestrator
    detection_engine = de
    response_orchestrator = ro


@router.get("/sessions")
async def list_honeypot_sessions(
    hours: int = Query(default=24, ge=1, le=168),
    honeypot_type: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    List recent honeypot sessions for frontend inspection.
    """
    from sqlalchemy import select
    from app.models.database import HoneypotSession

    since = datetime.utcnow() - timedelta(hours=hours)

    stmt = select(HoneypotSession).where(
        HoneypotSession.start_time >= since
    ).order_by(HoneypotSession.start_time.desc())

    if honeypot_type:
        stmt = stmt.where(HoneypotSession.honeypot_type == honeypot_type)

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    sessions = result.scalars().all()

    return {
        "total": len(sessions),
        "time_window_hours": hours,
        "sessions": [
            {
                "id": session.id,
                "session_id": session.session_id,
                "honeypot_type": session.honeypot_type,
                "source_ip": session.source_ip,
                "source_port": session.source_port,
                "destination_port": session.destination_port,
                "protocol": session.protocol,
                "start_time": session.start_time,
                "end_time": session.end_time,
                "username": session.username,
                "commands": session.commands or [],
                "payload": session.payload,
                "meta_data": session.meta_data or {}
            }
            for session in sessions
        ]
    }


@router.post("/ingest", response_model=DetectionResult)
async def ingest_honeypot_log(
    log: HoneypotLog,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Ingest honeypot log data, analyze for threats, and trigger automated response.
    """
    logger.info(
        "Honeypot log received",
        honeypot_type=log.honeypot_type,
        source_ip=log.source_ip,
        event_type=log.event_type
    )
    await store_system_log(
        db,
        level="INFO",
        component="honeypot_ingest",
        message="Honeypot log received",
        source_ip=log.source_ip,
        session_id=log.session_id,
        details={
            "honeypot_type": log.honeypot_type,
            "event_type": log.event_type,
            "protocol": log.protocol,
        },
    )
    
    # Step 1: Store raw log
    await store_honeypot_session(db, log)
    
    # Step 2: Analyze for threats
    result = await detection_engine.analyze(log)
    await store_system_log(
        db,
        level="INFO",
        component="detection_pipeline",
        message="Detection pipeline completed",
        source_ip=log.source_ip,
        session_id=log.session_id,
        details={
            "threat_detected": result.threat_detected,
            "detection_method": result.detection_method,
            "attack_type": result.attack_type,
            "confidence_score": result.confidence_score,
            "threat_level": result.threat_level,
        },
    )
    
    # Step 3: If threat detected, trigger response in background
    if result.threat_detected:
        logger.warning(
            "Threat detected",
            threat_level=result.threat_level,
            attack_type=result.attack_type,
            confidence=result.confidence_score
        )
        
        # Store threat event
        threat_event = await store_threat_event(db, log, result)
        await broadcast_realtime_alert(threat_event, result)
        background_tasks.add_task(
            handle_threat_response,
            threat_event.id,
            result,
            log
        )
    
    return result


@router.post("/ingest/batch")
async def ingest_batch(
    logs: List[HoneypotLog],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Batch ingest for high-volume honeypot data"""
    results = []
    for log in logs:
        result = await ingest_honeypot_log(log, background_tasks, db)
        results.append(result)
    return {
        "processed": len(results),
        "threats_detected": sum(1 for r in results if r.threat_detected)
    }


async def handle_threat_response(threat_event_id: int, detection: DetectionResult, log: HoneypotLog):
    """Background task for threat response"""
    if response_orchestrator is None:
        logger.error("Response orchestrator not initialized")
        return

    async with async_session() as db:
        from app.api.v1.endpoints.dashboard import broadcast_stats_update, broadcast_system_event

        context = {
            "source_ip": log.source_ip,
            "honeypot_type": log.honeypot_type,
            "timestamp": log.timestamp,
            "session_id": log.session_id,
            "threat_event_id": threat_event_id,
        }

        decision = await response_orchestrator.decide_response(detection, context)
        await store_system_log(
            db,
            level="INFO",
            component="response_orchestrator",
            message="Response decision generated",
            source_ip=log.source_ip,
            session_id=log.session_id,
            details={
                "threat_event_id": threat_event_id,
                "action_required": decision.action_required,
                "action_type": decision.action_type,
                "priority": decision.priority,
                "requires_approval": decision.requires_approval,
                "reasoning": decision.reasoning,
            },
        )

        execution_result = await response_orchestrator.execute_response(decision, detection, context)
        await persist_response_action(db, threat_event_id, decision, execution_result)
        await sync_blocked_ip_state(db, threat_event_id, decision, execution_result, detection)
        await store_system_log(
            db,
            level="INFO" if execution_result.get("status") != "failed" else "ERROR",
            component="response_execution",
            message="Response execution completed",
            source_ip=log.source_ip,
            session_id=log.session_id,
            details={
                "threat_event_id": threat_event_id,
                "action_type": decision.action_type,
                "status": execution_result.get("status"),
                "target": execution_result.get("target"),
                "result": execution_result,
            },
        )
        await broadcast_stats_update()
        await broadcast_system_event(
            "pipeline_event",
            {
                "event": "response_executed",
                "threat_event_id": threat_event_id,
                "action_type": decision.action_type,
                "status": execution_result.get("status"),
                "target": execution_result.get("target"),
            },
        )


async def store_honeypot_session(db: AsyncSession, log: HoneypotLog):
    """Store honeypot session in database."""
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError
    from app.models.database import HoneypotSession

    stmt = select(HoneypotSession).where(HoneypotSession.session_id == log.session_id)
    result = await db.execute(stmt)
    existing_session = result.scalar_one_or_none()

    if existing_session:
        # Update existing session with latest fields
        existing_session.honeypot_type = log.honeypot_type
        existing_session.source_ip = log.source_ip
        existing_session.source_port = log.source_port
        existing_session.destination_port = log.dest_port
        existing_session.protocol = log.protocol
        existing_session.username = log.username
        existing_session.password = log.password
        existing_session.payload = log.payload
        existing_session.meta_data = log.meta_data if hasattr(log, "meta_data") else existing_session.meta_data or {}
        existing_session.end_time = log.timestamp

        commands = existing_session.commands or []
        if log.command:
            if isinstance(log.command, list):
                commands.extend(log.command)
            else:
                commands.append(log.command)
        existing_session.commands = commands
    else:
        existing_session = HoneypotSession(
            session_id=log.session_id,
            honeypot_type=log.honeypot_type,
            source_ip=log.source_ip,
            source_port=log.source_port,
            destination_port=log.dest_port,
            protocol=log.protocol,
            username=log.username,
            password=log.password,
            commands=[log.command] if log.command else [],
            payload=log.payload,
            meta_data=log.meta_data if hasattr(log, "meta_data") else {}
        )
        db.add(existing_session)

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        # If a concurrent insert happened, fallback to update existing row
        result = await db.execute(stmt)
        existing_session = result.scalar_one_or_none()
        if existing_session:
            existing_session.end_time = log.timestamp
            if log.command:
                commands = existing_session.commands or []
                if isinstance(log.command, list):
                    commands.extend(log.command)
                else:
                    commands.append(log.command)
                existing_session.commands = commands
            db.add(existing_session)
            await db.commit()
        else:
            raise


async def store_threat_event(db: AsyncSession, log: HoneypotLog, detection: DetectionResult):
    """Store detected threat in database"""
    from app.models.database import ThreatEvent, ThreatLevel, AttackType
    
    # Map string to enum
    threat_level = ThreatLevel(detection.threat_level.value if hasattr(detection.threat_level, 'value') else str(detection.threat_level).lower())
    attack_type = AttackType(detection.attack_type.value if hasattr(detection.attack_type, 'value') else str(detection.attack_type).lower())
    
    event = ThreatEvent(
        session_id=log.session_id,
        source_ip=log.source_ip,
        threat_level=threat_level,
        attack_type=attack_type,
        confidence_score=detection.confidence_score,
        detection_method=detection.detection_method,
        signature_match=detection.signature_match,
        anomaly_score=detection.anomaly_score,
        features=detection.features,
        raw_data=log.json() if hasattr(log, 'json') else str(log),
        mitre_tactic=detection.mitre_mapping.get("tactic") if detection.mitre_mapping else None,
        mitre_technique=detection.mitre_mapping.get("technique_id") if detection.mitre_mapping else None,
        mitre_mappings=make_json_safe(detection.mitre_mappings),
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


async def persist_response_action(
    db: AsyncSession,
    threat_event_id: int,
    decision,
    execution_result: dict,
):
    from app.models.database import ResponseAction, ResponseStatus

    status_map = {
        "executed": ResponseStatus.EXECUTED,
        "failed": ResponseStatus.FAILED,
        "pending": ResponseStatus.PENDING,
        "skipped": ResponseStatus.PENDING,
    }
    status = status_map.get(execution_result.get("status"), ResponseStatus.PENDING)

    action = ResponseAction(
        threat_event_id=threat_event_id,
        action_type=decision.action_type or execution_result.get("action_type") or "log_alert",
        target=decision.target or execution_result.get("target") or "unknown",
        parameters=make_json_safe({
            "reasoning": decision.reasoning,
            "estimated_impact": decision.estimated_impact,
            "priority": decision.priority,
        }),
        status=status,
        result=make_json_safe(execution_result),
        error_message=execution_result.get("error_message"),
        automated=not decision.requires_approval,
        executed_at=datetime.utcnow() if status == ResponseStatus.EXECUTED else None,
    )
    db.add(action)
    await db.commit()
    return action


async def sync_blocked_ip_state(
    db: AsyncSession,
    threat_event_id: int,
    decision,
    execution_result: dict,
    detection: DetectionResult,
):
    from sqlalchemy import select
    from app.models.database import BlockedIP

    if decision.action_type != "block_ip" or execution_result.get("status") != "executed":
        return

    target_ip = execution_result.get("target")
    stmt = select(BlockedIP).where(BlockedIP.ip_address == target_ip)
    result = await db.execute(stmt)
    blocked = result.scalar_one_or_none()

    if blocked:
        blocked.last_blocked_at = datetime.utcnow()
        blocked.block_count += 1
        blocked.reason = detection.attack_type
        blocked.threat_event_id = threat_event_id
        blocked.is_active = True
        blocked.unblocked_at = None
        blocked.unblocked_by = None
    else:
        blocked = BlockedIP(
            ip_address=target_ip,
            reason=detection.attack_type,
            threat_event_id=threat_event_id,
            is_active=True,
        )
        db.add(blocked)

    await db.commit()


async def store_system_log(
    db: AsyncSession,
    level: str,
    component: str,
    message: str,
    details: Optional[dict] = None,
    source_ip: Optional[str] = None,
    session_id: Optional[str] = None,
):
    from app.models.database import SystemLog

    entry = SystemLog(
        level=level,
        component=component,
        message=message,
        details=make_json_safe(details or {}),
        source_ip=source_ip,
        session_id=session_id,
    )
    db.add(entry)
    await db.commit()
    return entry


async def broadcast_realtime_alert(threat_event, detection: DetectionResult):
    from app.api.v1.endpoints.dashboard import broadcast_stats_update, broadcast_system_event, broadcast_threat_alert

    alert = ThreatAlert(
        id=threat_event.id,
        timestamp=threat_event.timestamp,
        source_ip=threat_event.source_ip,
        threat_level=threat_event.threat_level.value if hasattr(threat_event.threat_level, "value") else str(threat_event.threat_level),
        attack_type=threat_event.attack_type.value if hasattr(threat_event.attack_type, "value") else str(threat_event.attack_type),
        confidence=detection.confidence_score,
        status=threat_event.status,
        details={
            "detection_method": detection.detection_method,
            "signature_match": detection.signature_match,
            "mitre_tactic": threat_event.mitre_tactic,
            "mitre_technique": threat_event.mitre_technique,
            "mitre_mappings": threat_event.mitre_mappings or detection.mitre_mappings,
        },
    )
    await broadcast_threat_alert(alert)
    await broadcast_stats_update()
    await broadcast_system_event(
        "pipeline_event",
        {
            "event": "threat_detected",
            "threat_event_id": threat_event.id,
            "source_ip": threat_event.source_ip,
            "detection_method": detection.detection_method,
        },
    )


def make_json_safe(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: make_json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [make_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [make_json_safe(item) for item in value]
    return value
