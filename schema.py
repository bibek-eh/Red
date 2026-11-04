# backend/app/models/schema.py
from datetime import datetime
import enum
import uuid
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class RoleEnum(str, enum.Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    MENTOR = "mentor"
    ADMIN = "admin"

class SeverityEnum(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatusEnum(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class SessionStatusEnum(str, enum.Enum):
    IDLE = "idle"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.Enum(RoleEnum), default=RoleEnum.BLUE_TEAM, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ExerciseSession(db.Model):
    __tablename__ = "exercise_sessions"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(128), nullable=False)
    scenario_id = db.Column(db.String(64), nullable=False)
    status = db.Column(db.Enum(SessionStatusEnum), default=SessionStatusEnum.IDLE)
    created_by = db.Column(db.String(36), db.ForeignKey("users.id"))
    started_at = db.Column(db.DateTime, nullable=True)
    ended_at = db.Column(db.DateTime, nullable=True)

class SecurityEvent(db.Model):
    __tablename__ = "security_events"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_id = db.Column(db.String(64), unique=True, nullable=False, default=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    session_id = db.Column(db.String(36), db.ForeignKey("exercise_sessions.id"), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    event_type = db.Column(db.String(64), nullable=False) # e.g. http_request, auth_failure, db_query, object_access
    source = db.Column(db.String(64), nullable=False)     # e.g. vulnerable_lab, auth_service
    source_ip = db.Column(db.String(45), nullable=False)
    method = db.Column(db.String(10), nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    severity = db.Column(db.Enum(SeverityEnum), default=SeverityEnum.INFO)
    detection_rule_id = db.Column(db.String(64), nullable=True)
    message = db.Column(db.Text, nullable=False)
    raw_payload = db.Column(db.JSON, nullable=True)

class DetectionRule(db.Model):
    __tablename__ = "detection_rules"
    id = db.Column(db.String(64), primary_key=True) # e.g. SYNORA-RULE-001
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Enum(SeverityEnum), default=SeverityEnum.MEDIUM)
    pattern = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, default=True)

class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = db.Column(db.String(64), unique=True, nullable=False, default=lambda: f"ALT-{uuid.uuid4().hex[:6].upper()}")
    session_id = db.Column(db.String(36), db.ForeignKey("exercise_sessions.id"), nullable=True)
    rule_id = db.Column(db.String(64), db.ForeignKey("detection_rules.id"), nullable=False)
    title = db.Column(db.String(128), nullable=False)
    severity = db.Column(db.Enum(SeverityEnum), nullable=False)
    status = db.Column(db.Enum(AlertStatusEnum), default=AlertStatusEnum.NEW)
    assigned_analyst = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ResponseAction(db.Model):
    __tablename__ = "response_actions"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = db.Column(db.String(36), nullable=False)
    action_type = db.Column(db.String(64), nullable=False) # e.g. ISOLATE_LAB, BLOCK_IP, RATE_LIMIT
    actor = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    result = db.Column(db.String(255), nullable=False)