"""Request / response models (input validation at the API boundary)."""

import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.ml.traffic import CATEGORICAL_COLUMNS, FEATURE_COLUMNS

Severity = Literal["Low", "Medium", "High", "Critical"]
AlertStatus = Literal["open", "blocked", "resolved"]


def _validate_ip(value: str | None) -> str | None:
    if value is None:
        return value
    return str(ipaddress.ip_address(value.strip()))


class TrafficRequest(BaseModel):
    source_ip: str | None = Field(default=None, examples=["203.0.113.7"])
    features: dict[str, float | int | str] = Field(
        description=f"All {len(FEATURE_COLUMNS)} NSL-KDD connection features"
    )

    _ip = field_validator("source_ip")(_validate_ip)

    @field_validator("features")
    @classmethod
    def _check_features(cls, value: dict) -> dict:
        missing = [c for c in FEATURE_COLUMNS if c not in value]
        if missing:
            raise ValueError(f"missing features: {', '.join(missing[:5])}"
                             + (" ..." if len(missing) > 5 else ""))
        cleaned = {}
        for col in FEATURE_COLUMNS:
            raw = value[col]
            if col in CATEGORICAL_COLUMNS:
                cleaned[col] = str(raw)[:30]
            else:
                try:
                    cleaned[col] = float(raw)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"feature '{col}' must be numeric") from exc
        return cleaned


class UrlRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048, examples=["paypal-login.verify-account.tk/signin"])
    source_ip: str | None = None

    _ip = field_validator("source_ip")(_validate_ip)

    @field_validator("url")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("url must be a single token without whitespace")
        return value


class AnalysisResult(BaseModel):
    event_id: int
    source: str
    label: str
    description: str
    confidence: float
    is_threat: bool
    anomaly: bool = False
    severity: Severity | None = None
    alert_id: int | None = None
    action: str | None = None
    blocked: bool = False
    indicators: dict | None = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    severity: Severity
    status: AlertStatus
    action: str | None
    created_at: datetime
    source: str
    source_ip: str | None
    label: str
    confidence: float
    summary: str


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class BlockRequest(BaseModel):
    ip: str
    reason: str = Field(default="Manually blocked", max_length=200)

    _ip = field_validator("ip")(_validate_ip)


class BlockedIPOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip: str
    reason: str
    created_at: datetime
