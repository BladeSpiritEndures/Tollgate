# Tollgate

An LLM API gateway that classifies request content and uses that classification
as a **hard routing constraint** — not just as an audit signal.

A request containing what looks like credentials, exfiltration commands or
proprietary data is classified `restricted` and can only leave through channels
whose data residency and retention terms satisfy that classification. If no
channel qualifies, the request fails with 503. That is the intended behaviour.

```
authenticate → scan → classify → dispatch (constrained) → forward → audit
```

## Status

v0 skeleton. Python 3.12 / FastAPI / httpx / Pydantic. `ruff` and
`mypy --strict` clean. `smoke.py` demonstrates the core mechanic end-to-end;
the app boots and serves `/health` and the auth + scan + dispatch path.
All AWS integrations are stubbed — see TODO.

```
$ python smoke.py
classification: restricted | risk: critical | score: 100 | ms: 0
queue: ['bedrock-syd']
rejected: [{'channel_id': 'openai-us',
            'reason': 'classification restricted > channel max internal'}]
```

## Run

```
pip install -e ".[dev]"
uvicorn tollgate.main:app --port 8777 --reload
curl localhost:8777/health
```

For deterministic local gateway testing, start the fake upstream in another
terminal and point the restricted Bedrock channel at it:

```
uvicorn fake_upstream:app --port 9000
TOLLGATE_UPSTREAM_BASE_URL=http://127.0.0.1:9000/v1 \
  uvicorn tollgate.main:app --port 8777 --reload
```

It returns a fixed JSON response for normal requests and four fixed SSE frames
when `stream` is `true`, so authentication, scanning, routing, and audit
changes can be tested without calling a real model provider.

## API contract

| Method | Path                   | Auth                        | Notes                                  |
| ------ | ---------------------- | --------------------------- | -------------------------------------- |
| POST   | `/v1/chat/completions`  | `Authorization: Bearer sk-tollgate-*` | OpenAI-compatible. SSE when `stream: true`. |
| POST   | `/v1/messages`          | `x-api-key: sk-tollgate-*`  | Anthropic protocol. **Not implemented.** |
| POST   | `/v1/embeddings`        | `Authorization: Bearer …`   | **Not implemented.**                    |
| GET    | `/v1/models`            | `Authorization: Bearer …`   | Union of models across enabled channels. **Not implemented.** |
| GET    | `/health`               | none                        | ALB target group health check.          |
| GET    | `/api/channels`         | admin                       | Channel CRUD for the dashboard. **Not implemented.** |
| GET    | `/api/audit`            | admin                       | Audit log query. **Not implemented.** |
| GET    | `/api/policy`           | admin                       | Read/update residency + retention rules. **Not implemented.** |

Response headers added by the gateway on success:

| Header                        | Value                                             |
| ----------------------------- | ------------------------------------------------- |
| `x-tollgate-trace-id`         | UUID, joins the response to its audit log entry    |
| `x-tollgate-classification`   | `public` \| `internal` \| `confidential` \| `restricted` |

Error shape is OpenAI-compatible (`{ error: { message, trace_id, … } }`) so
existing SDKs surface it without special handling. 403 = blocked by policy,
503 = no eligible channel, 502 = all upstreams failed. Every request writes
exactly one audit entry, including the failure cases.

## Layout

```
tollgate/
├── main.py                  FastAPI app, shared httpx client, /health
├── models.py                Pydantic: classification / channel / policy
├── security/
│   ├── rules.py             25-rule catalogue (17 implemented, 8 stubbed)
│   └── scanner.py           budget-limited JSON tree walk, fails closed
├── routing/dispatcher.py    constraint filter + priority/weight ordering
├── handlers/chat.py         SSE streaming proxy with failover
└── store/                   channels / secrets / audit log — all stubbed
```

## TODO — in this order

Ship each row before starting the next. Do not open the next file early.

1. **Real key auth.** `secrets.compare_digest`, DynamoDB lookup via boto3,
   enabled flag. ~80 lines.
2. **DynamoDB audit log.** Table `tollgate-audit`, PK `trace_id`, TTL attribute.
   Hash the API key before writing. Never persist the raw body.
3. **Deploy to Fargate behind an ALB.** Reuse your existing Terraform + GitHub
   Actions. Raise the ALB idle timeout above 60s and prove SSE survives it
   with `curl -N`. This is the point at which the project becomes
   demonstrable — everything after is polish.
4. **Secrets Manager** for upstream keys.
5. **Redaction path** (`policy.action == "redact"`). Rewrite the dict tree,
   never the serialised string.
6. **Anthropic adaptor** + `/v1/messages`. Protocol conversion lives here;
   budget a full weekend.
7. **React dashboard** (TypeScript). Audit log table, channel config, policy
   editor. No template — this is where the TS comes back.

The remaining 8 detection rules are optional. 17 is plenty for a demo, and
"I deliberately scoped detection to the highest-signal rules" is a better
interview answer than 25 half-tested regexes.

## Testing

The rule catalogue is a natural input-space-partitioning target: each rule has
clean equivalence classes (match / no match / boundary length / Unicode
boundary / nested path). Regex rules also respond well to mutation testing.
If you are doing CITS5501 this semester, this is your test subject.
