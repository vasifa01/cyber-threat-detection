"""Alert history, status updates, stats and the live WebSocket feed."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.db.models import Alert, BlockedIP, Detection, Event
from app.db.session import get_db
from app.schemas import AlertOut, AlertStatusUpdate, AlertStatus, Severity
from app.services.response import alert_summary

router = APIRouter(tags=["alerts"])


@router.get("/api/alerts", response_model=list[AlertOut])
def list_alerts(
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    source: str | None = Query(default=None, pattern="^(traffic|url)$"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[dict]:
    stmt = (
        select(Alert)
        .join(Alert.detection)
        .join(Detection.event)
        .options(joinedload(Alert.detection).joinedload(Detection.event))
        .order_by(Alert.id.desc())
        .limit(limit)
    )
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    if source:
        stmt = stmt.where(Event.source == source)
    return [alert_summary(a) for a in db.scalars(stmt).unique()]


@router.patch("/api/alerts/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, body: AlertStatusUpdate,
                 db: Session = Depends(get_db)) -> dict:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = body.status
    db.commit()
    return alert_summary(alert)


@router.get("/api/stats")
def stats(minutes: int = Query(default=30, ge=1, le=1440),
          db: Session = Depends(get_db)) -> dict:
    total_events = db.scalar(select(func.count(Event.id))) or 0
    threats = db.scalar(select(func.count(Detection.id)).where(Detection.is_threat)) or 0
    dropped = db.scalar(select(func.count(Event.id)).where(Event.dropped)) or 0
    open_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0
    blocked_ips = db.scalar(select(func.count(BlockedIP.id))) or 0

    by_label = dict(db.execute(
        select(Detection.label, func.count()).where(Detection.is_threat)
        .group_by(Detection.label)
    ).all())
    by_severity = dict(db.execute(
        select(Alert.severity, func.count()).group_by(Alert.severity)
    ).all())

    # Per-minute timeline (bucketed in Python so it works on MySQL and SQLite).
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes)
    rows = db.execute(
        select(Detection.created_at, Detection.is_threat)
        .where(Detection.created_at >= since)
    ).all()
    buckets: dict[str, dict] = {}
    for created_at, is_threat in rows:
        key = created_at.strftime("%H:%M")
        bucket = buckets.setdefault(key, {"time": key, "events": 0, "threats": 0})
        bucket["events"] += 1
        bucket["threats"] += int(is_threat)

    return {
        "total_events": total_events,
        "threats": threats,
        "dropped": dropped,
        "open_alerts": open_alerts,
        "blocked_ips": blocked_ips,
        "detection_rate": round(threats / total_events, 4) if total_events else 0.0,
        "by_label": by_label,
        "by_severity": by_severity,
        "timeline": sorted(buckets.values(), key=lambda b: b["time"]),
    }


@router.websocket("/ws/alerts")
async def alerts_ws(ws: WebSocket) -> None:
    bus = ws.app.state.bus
    await bus.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive; client messages are ignored
    except WebSocketDisconnect:
        bus.disconnect(ws)
