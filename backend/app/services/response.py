"""Threat response: severity scoring, persistence and automatic IP blocking."""

import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Alert, BlockedIP, Detection, Event
from app.services.detector import Prediction

SEVERITY_BY_LABEL = {
    "U2R": "Critical",
    "Malware": "Critical",
    "R2L": "High",
    "DoS": "High",
    "Phishing": "High",
    "Probe": "Medium",
    "Anomaly": "Low",
}
AUTO_BLOCK_SEVERITIES = {"High", "Critical"}


def severity_for(label: str) -> str | None:
    return SEVERITY_BY_LABEL.get(label)


def is_blocked(db: Session, ip: str | None) -> bool:
    if not ip:
        return False
    return db.scalar(select(BlockedIP.id).where(BlockedIP.ip == ip)) is not None


@dataclass(frozen=True)
class Outcome:
    event: Event
    detection: Detection
    alert: Alert | None
    dropped: bool


def handle(
    db: Session,
    prediction: Prediction,
    payload: dict | str,
    source_ip: str | None,
    auto_block: bool,
) -> Outcome:
    """Persist the event + detection, raise an alert and respond if needed."""
    dropped = is_blocked(db, source_ip)
    event = Event(
        source=prediction.source,
        source_ip=source_ip,
        payload=payload if isinstance(payload, str) else json.dumps(payload),
        dropped=dropped,
    )
    detection = Detection(
        event=event,
        model=prediction.model,
        label=prediction.label,
        confidence=prediction.confidence,
        is_threat=prediction.is_threat,
        anomaly=prediction.anomaly,
    )
    db.add_all([event, detection])

    alert = None
    # Traffic from an already-blocked IP is dropped: logged, but no new alert.
    if prediction.is_threat and not dropped:
        severity = severity_for(prediction.label) or "Low"
        alert = Alert(detection=detection, severity=severity, status="open")
        if auto_block and source_ip and severity in AUTO_BLOCK_SEVERITIES:
            db.add(BlockedIP(ip=source_ip,
                             reason=f"Auto-blocked: {prediction.label} ({severity})"))
            alert.status = "blocked"
            alert.action = f"Source IP {source_ip} added to blocklist"
        elif severity in AUTO_BLOCK_SEVERITIES:
            alert.action = "Flagged for analyst review"
        else:
            alert.action = "Logged for monitoring"
        db.add(alert)

    db.commit()
    return Outcome(event=event, detection=detection, alert=alert, dropped=dropped)


def alert_summary(alert: Alert) -> dict:
    """Flat dict used by both the REST API and the WebSocket feed."""
    det = alert.detection
    ev = det.event
    if ev.source == "url":
        summary = ev.payload[:120]
    else:
        data = json.loads(ev.payload)
        summary = f"{data.get('protocol_type')}/{data.get('service')} flag={data.get('flag')}"
    return {
        "id": alert.id,
        "severity": alert.severity,
        "status": alert.status,
        "action": alert.action,
        "created_at": alert.created_at.isoformat(),
        "source": ev.source,
        "source_ip": ev.source_ip,
        "label": det.label,
        "confidence": det.confidence,
        "summary": summary,
    }
