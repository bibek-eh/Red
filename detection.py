# backend/app/services/detection.py
import re
from datetime import datetime
from app.models.schema import db, SecurityEvent, Alert, DetectionRule, SeverityEnum, AlertStatusEnum

DEFAULT_RULES = [
    {
        "id": "SYNORA-RULE-001",
        "name": "SQL Injection Pattern Detected",
        "description": "Identifies boolean-based or union-based SQL syntax fragments in HTTP parameters.",
        "severity": SeverityEnum.HIGH,
        "pattern": r"(?i)(\%27|\'|\-\-|\%23|union\s+select|select\s+.*from|or\s+1=1)"
    },
    {
        "id": "SYNORA-RULE-002",
        "name": "Unauthorized Object Access (IDOR)",
        "description": "Detects attempts to access object identifiers outside ownership scope.",
        "severity": SeverityEnum.MEDIUM,
        "pattern": r"/lab/documents/doc-(?!001|002).*"
    },
    {
        "id": "SYNORA-RULE-003",
        "name": "Stored XSS Injection Vector",
        "description": "Flags script tags or event handlers within input payloads.",
        "severity": SeverityEnum.HIGH,
        "pattern": r"(?i)(<script>|javascript:|onerror\s*=)"
    },
    {
        "id": "SYNORA-RULE-004",
        "name": "High Volume Auth Failures",
        "description": "Flags repeated failed authentication attempts from a single source IP.",
        "severity": SeverityEnum.CRITICAL,
        "pattern": r"AUTH_FAILURE_BURST"
    }
]

class EventProcessor:
    @staticmethod
    def process_incoming_event(data, socketio=None):
        # 1. Normalize
        event = SecurityEvent(
            event_id=data.get("event_id"),
            session_id=data.get("session_id"),
            timestamp=datetime.fromisoformat(data.get("timestamp")) if data.get("timestamp") else datetime.utcnow(),
            event_type=data.get("event_type", "http_request"),
            source=data.get("source", "vulnerable_lab"),
            source_ip=data.get("source_ip", "127.0.0.1"),
            method=data.get("method"),
            endpoint=data.get("endpoint"),
            status_code=data.get("status_code", 200),
            severity=SeverityEnum(data.get("severity", "info")),
            message=data.get("message", "Telemetry ingested"),
            raw_payload=data.get("metadata", {})
        )
        
        db.session.add(event)
        db.session.commit()

        # 2. Match Rules
        triggered_alert = None
        search_target = f"{event.endpoint or ''} {event.message} {str(event.raw_payload)}"
        
        rules = DetectionRule.query.filter_by(enabled=True).all()
        for rule in rules:
            if re.search(rule.pattern, search_target):
                event.detection_rule_id = rule.id
                event.severity = rule.severity
                db.session.commit()

                # Generate Alert
                triggered_alert = Alert(
                    session_id=event.session_id,
                    rule_id=rule.id,
                    title=rule.name,
                    severity=rule.severity,
                    status=AlertStatusEnum.NEW
                )
                db.session.add(triggered_alert)
                db.session.commit()
                break

        # 3. Broadcast Real-Time Updates via Socket.IO
        if socketio:
            socketio.emit("telemetry_event", {
                "id": event.id,
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "endpoint": event.endpoint,
                "severity": event.severity.value,
                "message": event.message
            })
            
            if triggered_alert:
                socketio.emit("security_alert", {
                    "alert_id": triggered_alert.alert_id,
                    "rule_id": triggered_alert.rule_id,
                    "title": triggered_alert.title,
                    "severity": triggered_alert.severity.value,
                    "status": triggered_alert.status.value,
                    "created_at": triggered_alert.created_at.isoformat()
                })

        return event, triggered_alert