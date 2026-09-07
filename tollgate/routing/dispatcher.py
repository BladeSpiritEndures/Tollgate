"""
Classification-constrained dispatcher.

WaLiAPI selects channels on (enabled, model support, priority, weight).
Tollgate inserts a hard constraint layer BEFORE any of that: the scan verdict's
classification restricts which channels are even eligible.

The ordering of the two stages is the whole point. Constraints are not a
tiebreaker applied after ranking — a `restricted` request must never reach a
US-hosted channel even if that channel is the only one configured. In that
case dispatch returns an empty queue and the handler fails the request.
"No eligible channel" is a correct outcome, not an error to route around.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from tollgate.models import Channel, Classification, Policy


@dataclass
class DispatchResult:
    queue: list[Channel]
    # Channels removed by constraints, with the reason. For the audit log.
    rejected: list[dict[str, str]] = field(default_factory=list)


def _order_by_priority_weight(channels: list[Channel]) -> list[Channel]:
    """Priority first (higher wins), then weighted shuffle within each band.
    Ported from WaLiAPI's `order_by_priority_weight`."""
    bands: dict[int, list[Channel]] = {}
    for c in channels:
        bands.setdefault(c.priority, []).append(c)

    ordered: list[Channel] = []
    for priority in sorted(bands, reverse=True):
        pool = list(bands[priority])
        # Weighted sampling without replacement → full failover queue.
        while pool:
            total = sum(max(c.weight, 1) for c in pool)
            roll = random.random() * total
            idx = len(pool) - 1
            for i, c in enumerate(pool):
                roll -= max(c.weight, 1)
                if roll <= 0:
                    idx = i
                    break
            ordered.append(pool.pop(idx))
    return ordered


def _supports_model(channel: Channel, model: str) -> bool:
    if not channel.models:
        return True  # empty = wildcard
    return model in channel.models or model in channel.model_mapping


def dispatch(
    channels: list[Channel],
    requested_model: str,
    classification: Classification,
    policy: Policy,
) -> DispatchResult:
    rejected: list[dict[str, str]] = []
    eligible: list[Channel] = []

    allowed_residency = policy.residency_rules.get(classification)
    needs_zero_retention = classification.at_least(policy.zero_retention_floor)

    for c in channels:
        if not c.enabled:
            rejected.append({"channel_id": c.id, "reason": "disabled"})
            continue
        if not _supports_model(c, requested_model):
            rejected.append({"channel_id": c.id, "reason": f"model {requested_model}"})
            continue
        # ── Hard constraints. Never traded off against priority. ──
        if not c.max_classification.at_least(classification):
            rejected.append({
                "channel_id": c.id,
                "reason": f"classification {classification.value} > channel max {c.max_classification.value}",
            })
            continue
        if allowed_residency is not None and c.residency not in allowed_residency:
            rejected.append({
                "channel_id": c.id,
                "reason": f"residency {c.residency} not permitted for {classification.value}",
            })
            continue
        if needs_zero_retention and not c.zero_retention:
            rejected.append({"channel_id": c.id, "reason": "zero-retention required"})
            continue
        eligible.append(c)

    return DispatchResult(queue=_order_by_priority_weight(eligible), rejected=rejected)
