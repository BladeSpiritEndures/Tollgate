"""
POST /v1/chat/completions

The critical path. Order of operations matters:
    authenticate → scan → classify → dispatch → forward → audit

Streaming: the upstream body is piped through with backpressure preserved.
Do NOT buffer the stream to inspect it — response-side scanning, if you add it
later, has to be incremental over SSE frames.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse

from tollgate.models import DEFAULT_POLICY
from tollgate.routing.dispatcher import dispatch
from tollgate.security.scanner import scan
from tollgate.security.audit_log import AuditEntry, write_audit_log
from tollgate.store.channels import load_channels
from tollgate.store.secrets import resolve_api_key

router = APIRouter()


async def _pipe(upstream: httpx.Response) -> AsyncIterator[bytes]:
    try:
        async for chunk in upstream.aiter_bytes():
            yield chunk  # backpressure honoured by the async generator
            # TODO: parse `usage` out of the final SSE frame for token accounting.
    finally:
        await upstream.aclose()


@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    authorization: str = Header(default=""),
) -> Any:
    trace_id = str(uuid.uuid4())
    started = time.monotonic()
    client: httpx.AsyncClient = request.app.state.http

    # ── 1. Authenticate ─────────────────────────────────────────────────
    token = authorization.removeprefix("Bearer ").strip()
    # TODO: look the key up, check enabled + quota.
    # Use secrets.compare_digest() for the comparison — never ==.
    if not token.startswith("sk-tollgate-"):
        return JSONResponse({"error": {"message": "invalid api key"}}, status_code=401)

    body: dict[str, Any] = await request.json()
    model: str = body.get("model", "")
    wants_stream: bool = bool(body.get("stream", False))

    def latency() -> int:
        return int((time.monotonic() - started) * 1000)

    # ── 2. Scan + classify ──────────────────────────────────────────────
    verdict = scan(body)

    if DEFAULT_POLICY.action == "block" and verdict.risk.rank >= DEFAULT_POLICY.action_threshold.rank:
        await write_audit_log(AuditEntry(trace_id, token, verdict, None, "blocked", latency()))
        return JSONResponse(
            {
                "error": {
                    "message": "request blocked by data policy",
                    "trace_id": trace_id,
                    "findings": [f.rule_id for f in verdict.findings],
                }
            },
            status_code=403,
        )

    # TODO: if policy.action == "redact", rewrite `body` here before forwarding.
    # Redact the dict tree, never the serialised string — otherwise you break JSON escaping.

    # ── 3. Dispatch under classification constraints ────────────────────
    channels = await load_channels()
    result = dispatch(channels, model, verdict.classification, DEFAULT_POLICY)

    if not result.queue:
        await write_audit_log(
            AuditEntry(trace_id, token, verdict, None, "no_eligible_channel", latency())
        )
        return JSONResponse(
            {
                "error": {
                    "message": f'no channel satisfies classification "{verdict.classification.value}"',
                    "trace_id": trace_id,
                    "rejected": result.rejected,
                }
            },
            status_code=503,
        )

    # ── 4. Forward with failover ────────────────────────────────────────
    for channel in result.queue:
        upstream_model = channel.model_mapping.get(model, model)
        api_key = await resolve_api_key(channel.api_key_ref)
        timeout = httpx.Timeout(channel.timeout_ms / 1000)

        try:
            req = client.build_request(
                "POST",
                f"{channel.base_url}/chat/completions",
                json={**body, "model": upstream_model},
                headers={"authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            upstream = await client.send(req, stream=True)
        except httpx.HTTPError:
            continue  # failover to next channel

        if upstream.status_code != 200:
            await upstream.aclose()
            continue

        await write_audit_log(
            AuditEntry(trace_id, token, verdict, channel.id, "forwarded", latency())
        )

        gateway_headers = {
            "x-tollgate-trace-id": trace_id,
            "x-tollgate-classification": verdict.classification.value,
        }

        if not wants_stream:
            try:
                payload = await upstream.aread()
            finally:
                await upstream.aclose()
            return JSONResponse(content=json.loads(payload), headers=gateway_headers)

        return StreamingResponse(
            _pipe(upstream),
            media_type="text/event-stream",
            headers={**gateway_headers, "cache-control": "no-cache"},
        )

    await write_audit_log(
        AuditEntry(trace_id, token, verdict, None, "upstream_failed", latency())
    )
    return JSONResponse(
        {"error": {"message": "all upstream channels failed", "trace_id": trace_id}},
        status_code=502,
    )
