"""
Tollgate core models.

Key architectural difference from WaLiAPI: the scan verdict is not just a gate
(allow / redact / block). It produces a Classification which becomes a
*routing constraint*. A request classified RESTRICTED can only be dispatched
to channels whose residency and provider satisfy that constraint — regardless
of priority or weight.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

# ─── Classification ──────────────────────────────────────────────────────────


class Classification(str, Enum):
    """Ordered least → most sensitive. Comparison relies on this order."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return _CLASS_ORDER.index(self)

    def at_least(self, floor: Classification) -> bool:
        return self.rank >= floor.rank


_CLASS_ORDER = list(Classification)


def max_class(a: Classification, b: Classification) -> Classification:
    return a if a.rank >= b.rank else b


# ─── Risk / findings ─────────────────────────────────────────────────────────


class Risk(str, Enum):
    CLEAN = "clean"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RISK_ORDER.index(self)

    @property
    def score(self) -> int:
        return _RISK_SCORES[self]


_RISK_ORDER = list(Risk)
_RISK_SCORES = {
    Risk.CLEAN: 0,
    Risk.INFO: 5,
    Risk.LOW: 15,
    Risk.MEDIUM: 40,
    Risk.HIGH: 70,
    Risk.CRITICAL: 100,
}


def max_risk(a: Risk, b: Risk) -> Risk:
    return a if a.rank >= b.rank else b


RuleCategory = Literal[
    "credential", "file", "infra", "personal", "unicode", "network", "tool", "prompt"
]


class Finding(BaseModel):
    rule_id: str
    category: RuleCategory
    severity: Risk
    path: str  # JSON path, e.g. $.messages[2].content
    preview: str  # never the raw match — a redacted preview only


class ScanVerdict(BaseModel):
    findings: list[Finding]
    risk: Risk
    score: int  # 0–100
    classification: Classification
    truncated: bool  # scan hit a budget limit — treat as UNSCANNED, not clean
    elapsed_ms: int


# ─── Channels ────────────────────────────────────────────────────────────────

Residency = Literal["ap-southeast-2", "us", "eu", "cn", "unknown"]


class Channel(BaseModel):
    id: str
    name: str
    adaptor: Literal["openai", "anthropic", "bedrock"]
    base_url: str
    api_key_ref: str  # never the raw key — see store/secrets.py
    models: list[str] = Field(default_factory=list)  # empty = wildcard
    model_mapping: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    priority: int = 0  # higher wins
    weight: int = 1
    timeout_ms: int = 120_000

    # ── Tollgate-specific routing metadata (not in WaLiAPI) ──
    residency: Residency
    # Most sensitive classification this channel may receive.
    max_classification: Classification
    # Upstream contractually does not train on / retain submitted data.
    zero_retention: bool = False


# ─── Policy ──────────────────────────────────────────────────────────────────

PolicyAction = Literal["audit", "warn", "redact", "block"]


class Policy(BaseModel):
    action: PolicyAction = "redact"
    action_threshold: Risk = Risk.HIGH
    # Classification → residency allowlist.
    residency_rules: dict[Classification, list[Residency]] = Field(default_factory=dict)
    # Classification at or above this requires zero_retention channels.
    zero_retention_floor: Classification = Classification.CONFIDENTIAL


DEFAULT_POLICY = Policy(
    action="redact",
    action_threshold=Risk.HIGH,
    residency_rules={
        Classification.CONFIDENTIAL: ["ap-southeast-2", "us", "eu"],
        Classification.RESTRICTED: ["ap-southeast-2"],
    },
    zero_retention_floor=Classification.CONFIDENTIAL,
)
