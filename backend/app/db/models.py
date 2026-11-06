"""Database tables: events -> detections -> alerts, plus the IP blocklist."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Event(Base):
    """A raw input that was analysed (one network flow or one URL)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(20), index=True)  # "traffic" | "url"
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    payload: Mapped[str] = mapped_column(Text)  # JSON for traffic, the URL text for url
    dropped: Mapped[bool] = mapped_column(Boolean, default=False)  # source IP was blocked
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)

    detection: Mapped["Detection"] = relationship(back_populates="event", uselist=False)


class Detection(Base):
    """Model output for an event."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), unique=True)
    model: Mapped[str] = mapped_column(String(50))
    label: Mapped[str] = mapped_column(String(30), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    is_threat: Mapped[bool] = mapped_column(Boolean, index=True)
    anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)

    event: Mapped[Event] = relationship(back_populates="detection")
    alert: Mapped["Alert"] = relationship(back_populates="detection", uselist=False)


class Alert(Base):
    """Raised for every threat detection; drives the dashboard and response."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    detection_id: Mapped[int] = mapped_column(ForeignKey("detections.id"), unique=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    status: Mapped[str] = mapped_column(String(15), default="open", index=True)
    action: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)

    detection: Mapped[Detection] = relationship(back_populates="alert")


class BlockedIP(Base):
    __tablename__ = "blocklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    reason: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
