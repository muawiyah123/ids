"""Authenticated Security Assistant chat API."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, StringConstraints

from app.config import get_settings
from app.models.user import User
from app.security.dependencies import get_current_active_user
from app.services.security_assistant import answer_question

router = APIRouter(prefix="/assistant", tags=["Security Assistant"])
_CHAT_REQUESTS: dict[str, deque[float]] = defaultdict(deque)
_CHAT_WINDOW_SECONDS = 60
_CHAT_REQUESTS_PER_WINDOW = 12

MessageText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: MessageText


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=16)


@router.get("/status")
async def assistant_status(
    current_user: User = Depends(get_current_active_user),
):
    settings = get_settings()
    return {
        "configured": bool(settings.AI_API_KEY),
        "provider": settings.AI_PROVIDER.lower() if settings.AI_PROVIDER.lower() in {"groq", "openai"} else "unsupported",
    }


@router.post("/chat")
async def chat(
    request: ChatRequest,
    current_user: User = Depends(get_current_active_user),
):
    messages = [{"role": message.role, "content": message.content} for message in request.messages]
    if messages[-1]["role"] != "user":
        raise HTTPException(status_code=422, detail="The final chat message must be from the user")
    now = time.monotonic()
    user_key = str(current_user.id)
    recent = _CHAT_REQUESTS[user_key]
    while recent and now - recent[0] >= _CHAT_WINDOW_SECONDS:
        recent.popleft()
    if len(recent) >= _CHAT_REQUESTS_PER_WINDOW:
        raise HTTPException(status_code=429, detail="Chat limit reached. Please wait a minute before asking again.")
    recent.append(now)
    try:
        return await answer_question(messages)
    except RuntimeError as exc:
        status_code = 503 if "not configured" in str(exc).lower() else 502
        raise HTTPException(status_code=status_code, detail=str(exc)) from None
