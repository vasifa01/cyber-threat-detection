"""Fan-out of live alerts to every connected dashboard over WebSocket."""

import logging

from fastapi import WebSocket

log = logging.getLogger(__name__)


class AlertBus:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def publish(self, message: dict) -> None:
        dead = []
        for ws in list(self._clients):
            try:
                await ws.send_json(message)
            except Exception as exc:  # client vanished mid-send
                log.debug("Dropping websocket client: %s", exc)
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)
