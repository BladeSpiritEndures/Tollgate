"""Deterministic local upstream for testing the gateway without model API calls."""

from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="fake-upstream")


async def _events() -> AsyncIterator[bytes]:
    for text in ("fake ", "upstream ", "response"):
        yield f"data: {{\"choices\":[{{\"delta\":{{\"content\":\"{text}\"}}}}]}}\n\n".encode()
    yield b"data: [DONE]\n\n"


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Any:
    body = await request.json()
    if body.get("stream", False):
        return StreamingResponse(_events(), media_type="text/event-stream")
    return JSONResponse(
        {
            "id": "fake-chat-completion",
            "object": "chat.completion",
            "model": body.get("model", "fake-model"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "fake upstream response"},
                    "finish_reason": "stop",
                }
            ],
        }
    )
