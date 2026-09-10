"""
backend/app/services/websocket_service.py

WebSocket connection manager with Redis pub/sub support for multi-instance deployments.
Falls back to in-process broadcast when Redis is unavailable.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# Redis client (optional — populated during app startup)
_redis_client: Optional[Any] = None


def set_redis_client(client: Any) -> None:
    global _redis_client
    _redis_client = client


REDIS_CHANNEL = "ids:events"


class ConnectionManager:
    """
    Manages active WebSocket connections.
    Broadcasts events to all connected authenticated clients.
    When Redis is available, subscribes to Redis pub/sub so multiple
    backend instances share the same event stream.
    """

    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.debug("WS client connected. Total: %d", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        logger.debug("WS client disconnected. Total: %d", len(self._connections))

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Broadcast a typed event to all connected clients.
        Also publishes to Redis if available (for multi-instance sync).
        """
        message = json.dumps({
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })

        # Publish to Redis for other instances
        if _redis_client is not None:
            try:
                await _redis_client.publish(REDIS_CHANNEL, message)
            except Exception as e:
                logger.warning("Redis publish failed: %s — broadcasting locally only", e)

        await self._broadcast_local(message)

    async def _broadcast_local(self, message: str) -> None:
        """Broadcast to all connections in this process."""
        async with self._lock:
            connections = set(self._connections)

        dead: list[WebSocket] = []
        for ws in connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def start_redis_subscriber(self) -> None:
        """
        Subscribe to Redis pub/sub and rebroadcast to local WS connections.
        Called as a background task when Redis is available.
        """
        if _redis_client is None:
            return
        try:
            pubsub = _redis_client.pubsub()
            await pubsub.subscribe(REDIS_CHANNEL)
            logger.info("Redis WS subscriber started on channel: %s", REDIS_CHANNEL)
            async for msg in pubsub.listen():
                if msg["type"] == "message":
                    await self._broadcast_local(msg["data"].decode())
        except Exception as e:
            logger.error("Redis subscriber error: %s", e)


ws_manager = ConnectionManager()
