from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI

from tollgate.handlers.chat import router as chat_router
from tollgate.security.rules import IMPLEMENTED_COUNT, RULES


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # One shared client: connection pooling across requests, and the
    # streaming response can outlive the handler that created it.
    app.state.http = httpx.AsyncClient()
    try:
        yield
    finally:
        await app.state.http.aclose()


app = FastAPI(title="tollgate", lifespan=lifespan)
app.include_router(chat_router)


@app.get("/health")
async def health() -> dict[str, Any]:
    """ALB target-group health check. Must not require auth."""
    return {"status": "ok", "rules": {"total": len(RULES), "implemented": IMPLEMENTED_COUNT}}
