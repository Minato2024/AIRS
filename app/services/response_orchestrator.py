import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import structlog
import ipaddress

from app.models.schemas import DetectionResult, ResponseDecision
from app.config import settings

logger = structlog.get_logger()


class ResponseOrchestrator:
    """
    Automated Response Orchestrator using:
    1. Rule-based response selection
    2. Reinforcement Learning for optimization
    3. Integration with firewall/iptables
    """
    
    def __init__(self):
        self.action_history = []
        self.blocked_ips = set()
        self.response_cooldown = {}
        
    async def decide_response(self, detection: DetectionResult, context: Dict) -> ResponseDecision:
        """
        Decide appropriate response based on:
        - Threat level and confidence
        - Target criticality
        - Historical effectiveness
        - Business context
        """
        
        # Check cooldown to prevent response loops
        target_ip = context.get("source_ip")
        if target_ip and self._is_in_cooldown(target_ip):
            return ResponseDecision(
                action_required=False,
                reasoning="Target in response cooldown period"
            )
        
        # Decision logic based on threat level
        if detection.threat_level == "critical" and detection.confidence_score > 0.9:
            return await self._critical_response(detection, context)
        elif detection.threat_level == "high":
            return await self._high_response(detection, context)
        elif detection.threat_level == "medium":
            return await self._medium_response(detection, context)
        else:
            return ResponseDecision(
                action_required=True,
                action_type="log_alert",
                target=target_ip,
                priority=1,
                reasoning="Low threat level, logging only"
            )
    
    async def _critical_response(self, detection: DetectionResult, context: Dict) -> ResponseDecision:
        """Immediate blocking for critical threats"""
        target = context.get("source_ip")
        
        decision = ResponseDecision(
            action_required=True,
            action_type="block_ip",
            target=target,
            priority=5,
            reasoning=f"Critical {detection.attack_type} detected with {detection.confidence_score:.2%} confidence",
            estimated_impact="High - may block legitimate traffic if IP is shared",
            requires_approval=False  # Auto-execute for critical
        )
        
        if settings.AUTO_RESPONSE_ENABLED:
            await self._execute_block_ip(target, detection)
            self._set_cooldown(target)
        
        return decision
    
    async def _high_response(self, detection: DetectionResult, context: Dict) -> ResponseDecision:
        """Throttling or quarantine for high threats"""
        target = context.get("source_ip")
        
        return ResponseDecision(
            action_required=True,
            action_type="throttle_connection",
            target=target,
            priority=4,
            reasoning=f"High risk {detection.attack_type} detected",
            estimated_impact="Medium - reduced bandwidth for target",
            requires_approval=not settings.AUTO_RESPONSE_ENABLED
        )
    
    async def _medium_response(self, detection: DetectionResult, context: Dict) -> ResponseDecision:
        """Increased monitoring for medium threats"""
        target = context.get("source_ip")
        
        return ResponseDecision(
            action_required=True,
            action_type="increase_monitoring",
            target=target,
            priority=2,
            reasoning=f"Suspicious activity: {detection.attack_type}",
            requires_approval=False
        )
    
    async def _execute_block_ip(self, ip: str, detection: DetectionResult):
        """Execute IP blocking via iptables or API call to firewall"""
        logger.warning("Executing IP block", ip=ip, reason=detection.attack_type)
        
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error("Invalid IP address", ip=ip)
            return
        
        # Execute iptables command (Linux) or API call
        # In production, use a more secure method (e.g., nftables, cloud API)
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        
        # Placeholder: Actually execute or queue for execution
        self.blocked_ips.add(ip)
        
        # Log action
        self.action_history.append({
            "timestamp": datetime.utcnow(),
            "action": "block_ip",
            "target": ip,
            "trigger": detection.attack_type,
            "automated": True
        })
    
    def _is_in_cooldown(self, target: str) -> bool:
        """Check if target is in cooldown period"""
        if target in self.response_cooldown:
            if datetime.utcnow() < self.response_cooldown[target]:
                return True
            else:
                del self.response_cooldown[target]
        return False
    
    def _set_cooldown(self, target: str):
        """Set cooldown for target"""
        self.response_cooldown[target] = datetime.utcnow() + timedelta(
            seconds=settings.RESPONSE_COOLDOWN_SECONDS
        )
    
    async def get_active_blocks(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        return [
            {"ip": ip, "blocked_since": datetime.utcnow().isoformat()}
            for ip in self.blocked_ips
        ]
    
    async def unblock_ip(self, ip: str) -> bool:
        """Remove IP from blocklist"""
        if ip in self.blocked_ips:
            # Execute iptables -D INPUT -s {ip} -j DROP
            self.blocked_ips.discard(ip)
            logger.info("IP unblocked", ip=ip)
            return True
        return False