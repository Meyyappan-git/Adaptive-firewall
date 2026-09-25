from typing import Dict, Any
from datetime import datetime, timedelta
from ..database import Alert, SessionLocal
from ..utils.logger import logger

# Per-source alert cooldown to prevent alert flooding
_alert_cooldown: Dict[str, datetime] = {}
ALERT_COOLDOWN_SECONDS = 60  # Minimum 60s between alerts for same source at same severity


class AlertManager:
    def __init__(self):
        pass

    def create_alert(self, severity: str, title: str, description: str, source: str, score: float) -> bool:
        """
        Creates an alert, but only if the cooldown for this (source, severity)
        pair has expired. Returns True if alert was created, False if suppressed.
        """
        from ..database import SessionLocal, Alert
        cooldown_key = f"{source}:{severity}"
        now = datetime.utcnow()

        # Check cooldown
        if cooldown_key in _alert_cooldown:
            last_alert_time = _alert_cooldown[cooldown_key]
            if (now - last_alert_time).total_seconds() < ALERT_COOLDOWN_SECONDS:
                return False  # Suppress duplicate alert

        # Update cooldown timestamp
        _alert_cooldown[cooldown_key] = now

        db = SessionLocal()
        try:
            alert = Alert(
                severity=severity,
                title=title,
                description=description,
                source=source,
                threat_score=score
            )
            db.add(alert)
            db.commit()
            logger.warning(f"ALERT [{severity}]: {title} - Source: {source}")
            return True
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            db.rollback()
            return False
        finally:
            db.close()

    def acknowledge_alert(self, alert_id: int):
        from ..database import SessionLocal, Alert
        db = SessionLocal()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.status = "ACKNOWLEDGED"
                db.commit()
                return True
            return False
        finally:
            db.close()
