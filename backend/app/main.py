"""FastAPI entrypoint.

Run from backend/:  ../.venv/bin/uvicorn app.main:app --reload
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db.session import init_engine
from app.routers import alerts, analyze, blocklist
from app.services.alert_bus import AlertBus
from app.services.detector import Detector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_engine(settings.database_url)
    app.state.detector = Detector(settings.models_dir)
    app.state.bus = AlertBus()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AI Cyber Threat Detection System",
        description="Detects and classifies network intrusions and malicious URLs in real time.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )
    app.include_router(analyze.router)
    app.include_router(alerts.router)
    app.include_router(blocklist.router)

    @app.get("/api/health", tags=["health"])
    def health() -> dict:
        return {"status": "ok", "live_clients": app.state.bus.client_count}

    return app


app = create_app()
