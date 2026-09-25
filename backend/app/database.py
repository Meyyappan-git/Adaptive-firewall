from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from .config import settings

Base = declarative_base()

class TrafficEvent(Base):
    __tablename__ = "traffic_events"
    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String)
    packet_count = Column(Integer, default=1)
    byte_count = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)
    threat_score = Column(Float, nullable=True)
    action = Column(String)

class Threat(Base):
    __tablename__ = "threats"
    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True)
    severity = Column(String) # LOW, MODERATE, HIGH, CRITICAL
    score = Column(Float)
    reasons = Column(String) # JSON string or comma-separated
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="ACTIVE") # ACTIVE, RESOLVED, FALSE_POSITIVE

class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, index=True)
    destination = Column(String, nullable=True)
    protocol = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    action = Column(String) # ALLOW, BLOCK, RATE_LIMIT
    reason = Column(String)
    threat_score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    status = Column(String, default="ACTIVE") # ACTIVE, EXPIRED, REMOVED

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    severity = Column(String)
    title = Column(String)
    description = Column(String)
    source = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    threat_score = Column(Float)
    status = Column(String, default="UNACKNOWLEDGED") # UNACKNOWLEDGED, ACKNOWLEDGED

class SystemEvent(Base):
    __tablename__ = "system_events"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String)
    description = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
