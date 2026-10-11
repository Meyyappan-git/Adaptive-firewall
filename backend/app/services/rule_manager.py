from typing import Dict, Any, Optional, Set
from datetime import datetime, timedelta
from ..utils.logger import logger
from ..database import FirewallRule, Alert, SessionLocal
from ..config import settings


class RuleManager:
    def __init__(self, firewall_backend):
        self.firewall = firewall_backend
        self._blocked_ips_cache: Set[str] = set()
        self._rule_id_map: Dict[int, int] = {}  # db_rule_id -> os_rule_id
        self._sync_active_cache()

    def set_firewall_backend(self, new_backend):
        """Allows dynamically switching between simulation and live host firewall."""
        self.firewall = new_backend
        logger.info(f"RuleManager firewall backend updated to: {new_backend.__class__.__name__}")
        # Re-enforce any currently active rules into the new backend
        self._reapply_active_rules()

    def _sync_active_cache(self):
        """Pre-populate in-memory blocked IPs cache from DB."""
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            active_rules = db.query(FirewallRule).filter(
                FirewallRule.status == "ACTIVE"
            ).all()
            self._blocked_ips_cache = {
                r.source for r in active_rules
                if r.action in ["BLOCK", "TEMPORARY_BLOCK"] and (r.expires_at is None or r.expires_at > now)
            }
        except Exception as e:
            logger.error(f"Error syncing active firewall cache: {e}")
        finally:
            db.close()

    def _reapply_active_rules(self):
        """Re-applies active database rules into the active backend."""
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            active_rules = db.query(FirewallRule).filter(
                FirewallRule.status == "ACTIVE"
            ).all()
            for r in active_rules:
                if r.expires_at and r.expires_at <= now:
                    continue
                rule_data = {
                    "id": r.id,
                    "source": r.source,
                    "action": r.action,
                    "reason": r.reason,
                    "threat_score": r.threat_score,
                    "expires_at": r.expires_at,
                    "status": "ACTIVE"
                }
                backend_rule_id = self.firewall.add_rule(rule_data)
                self._rule_id_map[r.id] = backend_rule_id
        except Exception as e:
            logger.error(f"Error reapplying active rules: {e}")
        finally:
            db.close()

    def is_ip_blocked(self, source_ip: str) -> bool:
        """Fast O(1) check if an IP is currently blocked (for middleware)."""
        return source_ip in self._blocked_ips_cache

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

        db = SessionLocal()
        try:
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
                if action.upper() in ["BLOCK", "TEMPORARY_BLOCK"]:
                    self._blocked_ips_cache.add(source_ip)
                return rule_id_existing

            # Persist to DB first to get unique ID
            db_rule = FirewallRule(
                source=source_ip,
                action=action.upper(),
                reason=reasons,
                threat_score=score,
                expires_at=expires_at,
                status="ACTIVE"
            )
            db.add(db_rule)
            db.commit()
            db.refresh(db_rule)
            rule_id_val = db_rule.id

            # Create rule in native/simulation backend with matched ID
            rule_data = {
                "id": rule_id_val,
                "source": source_ip,
                "action": action.upper(),
                "reason": reasons,
                "threat_score": score,
                "expires_at": expires_at,
                "status": "ACTIVE"
            }
            backend_rule_id = self.firewall.add_rule(rule_data)
            self._rule_id_map[rule_id_val] = backend_rule_id

            if action.upper() in ["BLOCK", "TEMPORARY_BLOCK"]:
                self._blocked_ips_cache.add(source_ip)

            logger.info(f"Adaptive rule created for {source_ip}: {action} (Score: {score:.1f}, ID: {rule_id_val})")
            return rule_id_val
        except Exception as e:
            logger.error(f"Error creating adaptive rule: {e}")
            db.rollback()
            return None
        finally:
            db.close()

    def cleanup_expired_rules(self):
        """Enforces expiry: removes expired rules from DB, OS firewall, and memory cache."""
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            rules = db.query(FirewallRule).filter(
                FirewallRule.expires_at < now,
                FirewallRule.status == "ACTIVE"
            ).all()

            for rule in rules:
                rule.status = "EXPIRED"
                db.commit()

                # Call native/simulated firewall engine to remove OS rule
                backend_rule_id = self._rule_id_map.get(rule.id, rule.id)
                self.firewall.remove_rule(backend_rule_id)
                self._rule_id_map.pop(rule.id, None)

                # Remove from cache
                self._blocked_ips_cache.discard(rule.source)
                logger.info(f"Rule {rule.id} for {rule.source} has expired and was removed from OS firewall.")
        except Exception as e:
            logger.error(f"Error during rule cleanup: {e}")
            db.rollback()
        finally:
            db.close()

    def remove_rule(self, rule_id: int):
        """Manually lifts a rule from DB, OS firewall, and in-memory cache."""
        db = SessionLocal()
        try:
            rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
            if rule:
                source_ip = rule.source
                rule.status = "REMOVED"
                db.commit()

                # Remove from OS firewall
                backend_rule_id = self._rule_id_map.get(rule_id, rule_id)
                self.firewall.remove_rule(backend_rule_id)
                self._rule_id_map.pop(rule_id, None)

                # Remove from memory cache
                self._blocked_ips_cache.discard(source_ip)
                logger.info(f"Rule {rule_id} ({source_ip}) manually lifted from OS firewall.")
        except Exception as e:
            logger.error(f"Error removing rule {rule_id}: {e}")
            db.rollback()
        finally:
            db.close()

    def clear_all(self):
        """Clears all rules from OS firewall, DB, and cache."""
        self.firewall.clear_rules()
        self._rule_id_map.clear()
        self._blocked_ips_cache.clear()
        logger.info("All firewall rules cleared across OS and memory.")
