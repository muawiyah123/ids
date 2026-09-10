"""
backend/app/api/websocket.py — WebSocket endpoint for real-time events.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import JWTError

from app.security.jwt import decode_access_token
from app.services.websocket_service import ws_manager

router = APIRouter(tags=["WebSocket"])
logger = logging.getLogger(__name__)


@router.websocket("/ws/events")
async def websocket_events(
    ws: WebSocket,
    token: str = Query(description="JWT access token for authentication"),
) -> None:
    """
    Authenticated WebSocket endpoint for real-time detection/alert events.

    Client connects with: ws://host/api/v1/ws/events?token=<access_token>

    Events pushed from server:
    - detection.created
    - alert.created
    - alert.updated
    - agent.heartbeat
    - system.health
    """
    # Authenticate before accepting connection
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            await ws.close(code=4001, reason="Invalid token")
            return
    except JWTError:
        await ws.close(code=4001, reason="Authentication failed")
        return

    await ws_manager.connect(ws)
    logger.info("WS client authenticated: user=%s connections=%d", user_id, ws_manager.connection_count)

    try:
        # Send initial handshake
        await ws.send_text(json.dumps({
            "type": "connection.established",
            "data": {"user_id": user_id, "connections": ws_manager.connection_count},
        }))

        # Keep connection alive — handle client heartbeat pings
        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        logger.info("WS client disconnected: user=%s", user_id)
    except Exception as e:
        logger.warning("WS error for user=%s: %s", user_id, e)
    finally:
        await ws_manager.disconnect(ws)
