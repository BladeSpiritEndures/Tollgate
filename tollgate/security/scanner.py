"""
Budget-limited request scanner.

The budget design is the single best idea in WaLiAPI's security module and is
ported almost verbatim: a hostile request body must not be able to turn the
scanner into a DoS vector. Every walk is bounded on four axes — bytes,
string-node count, nesting depth and wall clock — and each individual string
is truncated before the rules ever see it.

Interview note: if a scan hits a budget limit, `truncated` is True and the
request MUST be treated as unscanned, not as clean. Failing open here is the
classic mistake.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from tollgate.models import Classification, Finding, Risk, ScanVerdict, max_class, max_risk
from tollgate.security.rules import RULES


@dataclass(frozen=True)
class ScanBudget:
    max_total_bytes: int = 32 * 1024 * 1024
    max_string_nodes: int = 50_000
    max_depth: int = 256
    max_elapsed_ms: int = 800
    max_text_bytes_per_string: int = 64 * 1024


DEFAULT_BUDGET = ScanBudget()


def _preview(match: str) -> str:
    """Never put a raw match in a log line."""
    head = match[:4]
    return f"{head}***" if len(match) <= 8 else f"{head}***{match[-2:]}"


def scan(body: Any, budget: ScanBudget = DEFAULT_BUDGET) -> ScanVerdict:
    started = time.monotonic()
    findings: list[Finding] = []
    bytes_seen = 0
    nodes_seen = 0
    truncated = False

    def over_budget() -> bool:
        return (
            bytes_seen > budget.max_total_bytes
            or nodes_seen > budget.max_string_nodes
            or (time.monotonic() - started) * 1000 > budget.max_elapsed_ms
        )

    def walk(node: Any, path: str, depth: int) -> None:
        nonlocal bytes_seen, nodes_seen, truncated
        if truncated:
            return
        if depth > budget.max_depth or over_budget():
            truncated = True
            return

        if isinstance(node, str):
            nodes_seen += 1
            bytes_seen += len(node)
            text = node[: budget.max_text_bytes_per_string]
            if len(text) < len(node):
                truncated = True
            for rule in RULES:
                if rule.detect is None:
                    continue
                hits = rule.detect(text)
                if not hits:
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        path=path,
                        preview=_preview(hits[0]),
                    )
                )
            return

        if isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]", depth + 1)
                if truncated:
                    return
            return

        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}", depth + 1)
                if truncated:
                    return

    walk(body, "$", 0)

    risk = Risk.CLEAN
    classification = Classification.PUBLIC
    rules_by_id = {r.rule_id: r for r in RULES}
    for f in findings:
        risk = max_risk(risk, f.severity)
        classification = max_class(classification, rules_by_id[f.rule_id].contributes)

    # Fail closed: an incomplete scan is not a clean scan.
    if truncated:
        classification = max_class(classification, Classification.CONFIDENTIAL)

    return ScanVerdict(
        findings=findings,
        risk=risk,
        score=risk.score,
        classification=classification,
        truncated=truncated,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )
