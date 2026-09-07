"""
Rule catalogue.

Taxonomy ported from WaLiAPI (MIT) `src-tauri/src/security/rules.rs`.
The 25 rule IDs, categories and severities are theirs. The detection
implementations and the `contributes` classification mapping are ours.

Rules with `detect=None` are DELIBERATELY unimplemented — write them yourself.
Start with the credential.* family; that is where 80% of the demo value is.
Do NOT implement all 25 before shipping v0.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from tollgate.models import Classification, Risk, RuleCategory

Detector = Callable[[str], list[str]]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: RuleCategory
    severity: Risk
    title: str
    description: str
    # Classification floor this rule pushes a request to when it fires.
    contributes: Classification
    # Return matched substrings, or [] for no match. None = not implemented.
    detect: Detector | None


def _regex(pattern: str, flags: int = 0) -> Detector:
    compiled = re.compile(pattern, flags)

    def detect(text: str) -> list[str]:
        return [m.group(0) for m in compiled.finditer(text)]

    return detect


def _exfiltration(text: str) -> list[str]:
    """The combination is the signal, not either half."""
    reads_secret = re.search(
        r"(?:cat|less|head|tail|type)\s+\S*(?:\.env|id_rsa|credentials|\.pem)", text, re.IGNORECASE
    )
    sends_out = re.search(
        r"\|\s*(?:curl|wget|nc)\b|--data-binary\s*@|-F\s+[\"']?file=@", text, re.IGNORECASE
    )
    return ["read+send combination"] if reads_secret and sends_out else []


RULES: list[Rule] = [
    # ── credential ────────────────────────────────────────────────────────
    Rule(
        "credential.secret_token", "credential", Risk.HIGH,
        "Suspected API key or token",
        "sk-*, ghp_*, AKIA*, AIza*, JWT, Bearer token formats",
        Classification.RESTRICTED,
        _regex(
            r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}"
            r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}"
            r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
    ),
    Rule(
        "credential.private_key", "credential", Risk.CRITICAL,
        "Private key material", "PEM / OpenSSH private key headers",
        Classification.RESTRICTED,
        _regex(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
    Rule(
        "credential.named_secret", "credential", Risk.HIGH,
        "Sensitive credential field name",
        "Authorization, Cookie, Session, Secret field names",
        Classification.CONFIDENTIAL,
        _regex(
            r"\b(?:authorization|x-api-key|cookie|set-cookie|session[_-]?(?:id|token)"
            r"|client[_-]?secret|refresh[_-]?token)\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "credential.database_url", "credential", Risk.HIGH,
        "Database connection string",
        "mysql://, postgres://, mongodb://, redis:// with credentials",
        Classification.RESTRICTED,
        _regex(
            r"\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s\"'<>]+",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "credential.cloud_key", "credential", Risk.HIGH,
        "Cloud provider credential", "AWS secret half, Aliyun AccessKey, Tencent SecretId",
        Classification.RESTRICTED,
        None,  # TODO: AKIA already covered above — target the 40-char secret half.
    ),
    # ── file ──────────────────────────────────────────────────────────────
    Rule(
        "file.sensitive_path", "file", Risk.HIGH,
        "Sensitive file path", ".env, ~/.ssh, .aws/credentials and similar",
        Classification.CONFIDENTIAL,
        _regex(
            r"(?:(?:^|[\s\"'`])(?:~|\.)?/?\.(?:env(?:\.[a-z]+)?|ssh/|aws/credentials"
            r"|kube/config|docker/config\.json))",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "file.ssh_key", "file", Risk.CRITICAL,
        "SSH key filename", "id_rsa, id_ed25519, id_ecdsa",
        Classification.RESTRICTED,
        _regex(r"\bid_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?\b"),
    ),
    Rule(
        "file.cloud_credentials", "file", Risk.HIGH,
        "Credential file reference", ".npmrc, .pypirc, .git-credentials, .netrc",
        Classification.CONFIDENTIAL,
        None,  # TODO
    ),
    # ── infra ─────────────────────────────────────────────────────────────
    Rule(
        "infra.local_path", "infra", Risk.MEDIUM,
        "Local user path", "/Users/, C:\\Users\\, /home/ — leaks usernames",
        Classification.INTERNAL,
        _regex(r"(?:/Users/|/home/|[A-Z]:\\Users\\)[A-Za-z0-9._-]+"),
    ),
    # ── personal ──────────────────────────────────────────────────────────
    Rule(
        "personal.email", "personal", Risk.LOW,
        "Email address", "Any RFC-ish email address",
        Classification.INTERNAL,
        _regex(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    Rule(
        "personal.phone", "personal", Risk.LOW,
        "Phone number", "AU mobile (04xx) and +61 formats",
        Classification.INTERNAL,
        # WaLiAPI matches mainland-China mobiles. Localised to AU here.
        _regex(r"\b(?:\+?61\s?4|04)\d{2}[\s-]?\d{3}[\s-]?\d{3}\b"),
    ),
    # ── unicode ───────────────────────────────────────────────────────────
    Rule(
        "unicode.zero_width", "unicode", Risk.MEDIUM,
        "Zero-width characters", "U+200B/200C/200D/2060/FEFF — invisible smuggling",
        Classification.CONFIDENTIAL,
        _regex(r"[\u200B-\u200D\u2060\uFEFF]"),
    ),
    Rule(
        "unicode.bidi_control", "unicode", Risk.HIGH,
        "Bidirectional control characters", "U+202A–202E, U+2066–2069 — Trojan Source",
        Classification.CONFIDENTIAL,
        _regex(r"[\u202A-\u202E\u2066-\u2069]"),
    ),
    Rule(
        "unicode.variation_selector", "unicode", Risk.MEDIUM,
        "Variation selectors", "U+FE00–FE0F, U+E0100–E01EF",
        Classification.INTERNAL,
        None,  # TODO — Python str is code points, so the U+E01xx plane is easy here.
    ),
    Rule(
        "unicode.homograph", "unicode", Risk.MEDIUM,
        "Homograph characters", "Cyrillic/Greek lookalikes for domain confusion",
        Classification.INTERNAL,
        None,  # TODO — high false-positive risk on legitimately mixed text
    ),
    # ── network ───────────────────────────────────────────────────────────
    Rule(
        "network.ip_probe", "network", Risk.HIGH,
        "Public IP lookup service", "ifconfig.me, ipinfo.io, ipify.org",
        Classification.CONFIDENTIAL,
        _regex(
            r"\b(?:ifconfig\.me|ipinfo\.io|api\.ipify\.org|icanhazip\.com"
            r"|checkip\.amazonaws\.com)\b",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "network.suspicious_domain", "network", Risk.HIGH,
        "Suspicious exfiltration domain", "webhook.site, ngrok, pastebin, requestbin",
        Classification.RESTRICTED,
        _regex(
            r"\b(?:webhook\.site|[\w-]+\.ngrok(?:-free)?\.(?:io|app|dev)|pastebin\.com"
            r"|requestbin\.\w+|burpcollaborator\.net|\S*\.trycloudflare\.com)\b",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "network.external_url", "network", Risk.INFO,
        "External URL", "Any outbound http(s) link",
        Classification.PUBLIC,
        None,  # TODO — noisy; allowlist first
    ),
    Rule(
        "network.tracking_pixel", "network", Risk.HIGH,
        "Tracking pixel", "1x1 images, track/pixel/beacon paths",
        Classification.CONFIDENTIAL,
        None,  # TODO
    ),
    # ── tool ──────────────────────────────────────────────────────────────
    Rule(
        "tool.shell.network_or_exec", "tool", Risk.MEDIUM,
        "High-risk shell command", "curl, wget, nc, scp, bash -c, python -c",
        Classification.INTERNAL,
        _regex(r"\b(?:curl|wget|nc|ncat|scp|rsync)\s+\S|\b(?:bash|sh|python3?)\s+-c\s"),
    ),
    Rule(
        "tool.shell.exfiltration", "tool", Risk.CRITICAL,
        "Suspected data exfiltration command", "Sensitive file read piped to network",
        Classification.RESTRICTED,
        _exfiltration,
    ),
    Rule(
        "tool.remote_script_exec", "tool", Risk.CRITICAL,
        "Remote script execution", "curl/wget piped into bash/sh",
        Classification.CONFIDENTIAL,
        _regex(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
    ),
    Rule(
        "tool.git_info", "tool", Risk.LOW,
        "Git information disclosure", "git remote, git config, gh auth token",
        Classification.INTERNAL,
        None,  # TODO
    ),
    # ── prompt ────────────────────────────────────────────────────────────
    Rule(
        "prompt.fingerprint_context", "prompt", Risk.MEDIUM,
        "Account profiling / anti-fraud context",
        "Co-occurrence of timezone, proxy, fingerprint, risk terms",
        Classification.CONFIDENTIAL,
        None,  # TODO — needs co-occurrence counting, not a single regex
    ),
    Rule(
        "prompt.injection", "prompt", Risk.HIGH,
        "Prompt injection / audit bypass",
        "Instructions to ignore rules, hide behaviour, evade logging",
        Classification.CONFIDENTIAL,
        _regex(
            r"\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
            r"|disregard\s+(?:the\s+)?(?:system|previous)|do\s+not\s+log|without\s+logging"
            r"|bypass\s+(?:the\s+)?(?:audit|filter|policy))\b",
            re.IGNORECASE,
        ),
    ),
]

RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in RULES}
IMPLEMENTED_COUNT = sum(1 for r in RULES if r.detect is not None)
