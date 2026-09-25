from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from ..utils.logger import logger
from ..database import FirewallRule, Alert, SessionLocal
from ..config import settings

class RuleManager:
    def __init__(self, firewall_backend):
        self.firewall = firewall_backend
        # Removed self.db_session = SessionLocal() to prevent session leaks


    def create_adaptive_rule(self, source_ip: str, threat_info: Dict[str, Any]):
        score = threat_info["score"]
        severity = threat_info["severity"]
        reasons = ", ".join(threat_info["reasons"])

        # Determine action based on severity
        action_map = settings.firewall_config.get("actions", {
            "low": "allow",
            "moderate": "monitor",
            "high": "temporary_block",
            "critical": "block"
        })
        action = action_map.get(severity.lower(), "allow")

        duration = None
        if action == "temporary_block":
            duration = settings.firewall_config.get("temporary_block", {}).get("default_duration_seconds", 300)

        expires_at = None
        if duration:
            expires_at = datetime.utcnow() + timedelta(seconds=duration)

        # Prevent duplicate active rules for the same source
        from ..database import SessionLocal, FirewallRule
        db = SessionLocal()
        existing = db.query(FirewallRule).filter(
            FirewallRule.source == source_ip,
            FirewallRule.status == "ACTIVE"
        ).first()

        if existing:
            rule_id_existing = existing.id
            if score > existing.threat_score:
                existing.threat_score = score
                existing.reason = reasons
                existing.expires_at = expires_at
                db.commit()
            db.close()
            return rule_id_existing

        # Create rule in backend
        rule_data = {
            "source": source_ip,
            "action": action.upper(),
            "reason": reasons,
            "threat_score": score,
            "expires_at": expires_at,
            "status": "ACTIVE"
        }

        rule_id = self.firewall.add_rule(rule_data)

        # Persist to DB
        db_rule = FirewallRule(
            source=source_ip,
            action=rule_data["action"],
            reason=reasons,
            threat_score=score,
            expires_at=expires_at,
            status="ACTIVE"
        )
        db.add(db_rule)
        db.commit()
        rule_id_val = db_rule.id
        db.close()

        logger.info(f"Adaptive rule created for {source_ip}: {action} (Score: {score:.1f})")
        return rule_id_val

    def cleanup_expired_rules(self):
        from ..database import SessionLocal, FirewallRule
        db = SessionLocal()
        now = datetime.utcnow()
        rules = db.query(FirewallRule).filter(
            FirewallRule.expires_at < now,
            FirewallRule.status == "ACTIVE"
        ).all()

        for rule in rules:
            rule.status = "EXPIRED"
            # In a real system, we'd call firewall.remove_rule(rule.id)
            db.commit()
            logger.info(f"Rule {rule.id} for {rule.source} has expired.")
        db.close()

    def remove_rule(self, rule_id: int):
        from ..database import SessionLocal, FirewallRule
        db = SessionLocal()
        rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
        if rule:
            rule.status = "REMOVED"
            db.commit()
            self.firewall.remove_rule(rule_id)
            logger.info(f"Rule {rule_id} manually removed.")
        db.close()
