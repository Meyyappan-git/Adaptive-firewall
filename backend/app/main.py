import asyncio
import random
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import Dict, Any

from .database import get_db, init_db, TrafficEvent, Threat, FirewallRule, Alert, SessionLocal
from .config import settings
from .services.traffic_monitor import SimulationTrafficSource
from .services.feature_extractor import FeatureExtractor
from .services.rule_detector import RuleDetector
from .services.anomaly_detector import MLDetector
from .services.threat_engine import ThreatEngine
from .services.firewall_engine import SimulationFirewall
from .services.rule_manager import RuleManager
from .services.alert_manager import AlertManager
from .utils.logger import logger

app = FastAPI(title="Adaptive Firewall API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global System Components
traffic_source = SimulationTrafficSource()
feature_extractor = FeatureExtractor()
rule_detector = RuleDetector()
ml_detector = MLDetector()
threat_engine = ThreatEngine(rule_detector, ml_detector)
firewall_backend = SimulationFirewall()
rule_manager = RuleManager(firewall_backend)
alert_manager = AlertManager()

# Background Task
processing_loop_task = None

# Threat deduplication: track last threat record time per IP
_threat_cooldown: Dict[str, datetime] = {}
THREAT_COOLDOWN_SECONDS = 30


def _train_ml_model():
    """Auto-train ML model on synthetic normal traffic so it can detect anomalies."""
    logger.info("Training ML model on synthetic baseline traffic...")
    normal_samples = []
    for _ in range(500):
        pc = random.randint(1, 20)
        bc = random.randint(64, 3000)
        cc = random.randint(1, 10)
        duration = max(random.uniform(1, 60), 1.0)
        up = random.randint(1, 4)
        ud = 1
        fc = 0
        normal_samples.append([
            float(pc), float(bc), float(cc),
            pc / duration, bc / duration,
            float(up), float(ud), float(fc),
            cc / duration, bc / max(pc, 1), duration
        ])
    success = ml_detector.train(normal_samples)
    if success:
        logger.info("ML model trained and ready.")
    else:
        logger.warning("ML model training failed.")


def _get_behavior_score(src_ip: str) -> float:
    """Calculate a behavior score 0-100 based on recent threat history."""
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        recent_threats = db.query(Threat).filter(
            Threat.source_ip == src_ip,
            Threat.timestamp >= cutoff
        ).all()
        if not recent_threats:
            return 0.0
        severity_weights = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1}
        total_weight = sum(severity_weights.get(t.severity, 1) for t in recent_threats)
        return min(total_weight * 2.5, 100.0)
    except Exception as e:
        logger.error(f"Error computing behavior score: {e}")
        return 0.0
    finally:
        db.close()


async def processing_loop():
    logger.info("Starting traffic processing loop...")
    loop_counter = 0
    try:
        while True:
            loop_counter += 1
            packet = traffic_source.get_next_packet()
            if packet:
                src_ip = packet["source_ip"]

                # 1. Extract features
                feature_extractor.update(packet)
                features = feature_extractor.extract_features(src_ip)

                # 2. Get behavior score from threat history
                behavior_score = _get_behavior_score(src_ip)

                # 3. Calculate Threat
                threat_info = threat_engine.calculate_threat(features, behavior_score=behavior_score)
                severity = threat_info["severity"]

                # 4. Adaptive action: create firewall rule for HIGH/CRITICAL
                if severity in ["HIGH", "CRITICAL"]:
                    rule_manager.create_adaptive_rule(src_ip, threat_info)

                # 5. Create alert for MODERATE/HIGH/CRITICAL (dedup in AlertManager)
                if severity in ["MODERATE", "HIGH", "CRITICAL"]:
                    alert_manager.create_alert(
                        severity=severity,
                        title=f"Suspicious Activity Detected: {severity}",
                        description=f"Reasons: {', '.join(threat_info['reasons'])}",
                        source=src_ip,
                        score=threat_info["score"]
                    )

                # 6. Log traffic to DB
                db = SessionLocal()
                try:
                    event = TrafficEvent(
                        source_ip=src_ip,
                        destination_ip=packet["destination_ip"],
                        source_port=packet["source_port"],
                        destination_port=packet["destination_port"],
                        protocol=packet["protocol"],
                        packet_count=packet["packet_count"],
                        byte_count=packet["byte_count"],
                        threat_score=threat_info["score"],
                        action=severity
                    )
                    db.add(event)

                    # 7. Log threat record (with cooldown dedup)
                    if severity != "LOW":
                        now = datetime.utcnow()
                        last_threat_time = _threat_cooldown.get(src_ip)
                        if last_threat_time is None or (now - last_threat_time).total_seconds() >= THREAT_COOLDOWN_SECONDS:
                            _threat_cooldown[src_ip] = now
                            threat_record = Threat(
                                source_ip=src_ip,
                                severity=severity,
                                score=threat_info["score"],
                                reasons=", ".join(threat_info["reasons"])
                            )
                            db.add(threat_record)

                    db.commit()
                except Exception as e:
                    logger.error(f"Database error in processing loop: {e}")
                    db.rollback()
                finally:
                    db.close()

            # Periodic Rule Cleanup every 10 iterations
            if loop_counter % 10 == 0:
                rule_manager.cleanup_expired_rules()

            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        logger.info("Processing loop cancelled.")
    except Exception as e:
        logger.error(f"Unexpected error in processing loop: {e}", exc_info=True)


@app.on_event("startup")
async def startup_event():
    global processing_loop_task
    init_db()

    # Auto-train ML model if not already saved
    import os
    model_path = "data/models/anomaly_model.joblib"
    if not os.path.exists(model_path):
        _train_ml_model()

    processing_loop_task = asyncio.create_task(processing_loop())
    logger.info("Adaptive Firewall API started.")


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "mode": settings.firewall_config["firewall"]["mode"]}


@app.get("/api/system/status")
def get_system_status():
    import os
    model_ready = os.path.exists("data/models/anomaly_model.joblib")
    return {
        "status": "healthy",
        "mode": settings.firewall_config["firewall"]["mode"],
        "ml_model_ready": model_ready,
        "scenario": traffic_source.scenario,
        "monitoring": True
    }


@app.get("/api/dashboard/summary")
def get_summary(db: Session = Depends(get_db)):
    return {
        "total_traffic": db.query(TrafficEvent).count(),
        "threats_detected": db.query(Threat).count(),
        "active_rules": db.query(FirewallRule).filter(FirewallRule.status == "ACTIVE").count(),
        "critical_alerts": db.query(Alert).filter(Alert.severity == "CRITICAL").count(),
    }


@app.get("/api/traffic/recent")
def get_recent_traffic(db: Session = Depends(get_db)):
    return db.query(TrafficEvent).order_by(TrafficEvent.timestamp.desc()).limit(50).all()


@app.get("/api/threats")
def get_threats(db: Session = Depends(get_db)):
    return db.query(Threat).order_by(Threat.timestamp.desc()).all()


@app.get("/api/rules")
def get_rules(db: Session = Depends(get_db)):
    return db.query(FirewallRule).all()


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule_manager.remove_rule(rule_id)
    return {"status": "success"}


@app.get("/api/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(Alert).order_by(Alert.timestamp.desc()).all()


@app.post("/api/alerts/{alert_id}/acknowledge")
def ack_alert(alert_id: int, db: Session = Depends(get_db)):
    if alert_manager.acknowledge_alert(alert_id):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/api/simulation/status")
def get_sim_status():
    return {"scenario": traffic_source.scenario}


@app.post("/api/simulation/scenario")
def set_sim_scenario(data: Dict[str, str]):
    scenario = data.get("scenario", "NORMAL")
    traffic_source.set_scenario(scenario)
    return {"status": "success", "scenario": scenario}


@app.post("/api/firewall/reset")
def reset_firewall(db: Session = Depends(get_db)):
    firewall_backend.clear_rules()
    db.query(TrafficEvent).delete()
    db.query(Threat).delete()
    db.query(FirewallRule).delete()
    db.query(Alert).delete()
    db.commit()
    _threat_cooldown.clear()
    from .services.alert_manager import _alert_cooldown
    _alert_cooldown.clear()
    return {"status": "success"}
