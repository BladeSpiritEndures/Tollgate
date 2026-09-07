import json
from dataclasses import asdict, dataclass
from typing import Literal

from tollgate.models import ScanVerdict


@dataclass
class AuditEntry:
    trace_id: str
    token: str
    verdict: ScanVerdict
    channel_id: str | None
    outcome: Literal["forwarded", "blocked", "no_eligible_channel", "upstream_failed"]
    latency_ms: int


async def write_audit_log(entry: AuditEntry) -> None:
    """
    TODO: DynamoDB `tollgate-audit`, PK `trace_id`, TTL attribute for retention.

    Two things to get right:
      1. Never persist the raw request body. Persist findings + redacted previews.
      2. Hash the API key before writing it. Do not store `sk-tollgate-*` in plain.
    """
    record = asdict(entry)
    record["token"] = "[redacted]"
    record["verdict"] = entry.verdict.model_dump(mode="json")
    print(json.dumps(record))
