"""POST endpoints that run the ML models on incoming data."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import get_db
from app.schemas import AnalysisResult, TrafficRequest, UrlRequest
from app.services import response
from app.services.detector import Prediction

router = APIRouter(prefix="/api/analyze", tags=["analyze"])


async def _respond(request: Request, db: Session, prediction: Prediction,
                   payload: dict | str, source_ip: str | None) -> AnalysisResult:
    outcome = response.handle(db, prediction, payload, source_ip,
                              auto_block=get_settings().auto_block_enabled)
    alert = outcome.alert
    if alert is not None:
        await request.app.state.bus.publish(
            {"type": "alert", "data": response.alert_summary(alert)}
        )
    await request.app.state.bus.publish({"type": "event", "data": {
        "source": prediction.source, "label": prediction.label,
        "is_threat": prediction.is_threat, "dropped": outcome.dropped,
    }})
    return AnalysisResult(
        event_id=outcome.event.id,
        source=prediction.source,
        label=prediction.label,
        description=prediction.description,
        confidence=prediction.confidence,
        is_threat=prediction.is_threat,
        anomaly=prediction.anomaly,
        severity=alert.severity if alert else None,
        alert_id=alert.id if alert else None,
        action=("Dropped: source IP is on the blocklist" if outcome.dropped
                else alert.action if alert else None),
        blocked=outcome.dropped or (alert is not None and alert.status == "blocked"),
        indicators=prediction.indicators or None,
    )


@router.post("/traffic", response_model=AnalysisResult)
async def analyze_traffic(body: TrafficRequest, request: Request,
                          db: Session = Depends(get_db)) -> AnalysisResult:
    prediction = request.app.state.detector.predict_traffic(body.features)
    return await _respond(request, db, prediction, body.features, body.source_ip)


@router.post("/url", response_model=AnalysisResult)
async def analyze_url(body: UrlRequest, request: Request,
                      db: Session = Depends(get_db)) -> AnalysisResult:
    prediction = request.app.state.detector.predict_url(body.url)
    return await _respond(request, db, prediction, body.url, body.source_ip)
