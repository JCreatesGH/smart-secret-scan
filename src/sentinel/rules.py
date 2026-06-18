"""Known token-format rules + entropy fallback."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List
from .entropy import looks_random

# name -> compiled regex for well-known credential formats
PATTERNS = {
    "github-pat": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "github-oauth": re.compile(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    "github-fine": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "gitlab-pat": re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "slack-webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe-secret": re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "stripe-restricted": re.compile(r"\brk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "openai-key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    "sendgrid-key": re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    "npm-token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}

# obvious assignment of a secret-like variable
_ASSIGN = re.compile(r"""(?ix)\b(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\b\s*[:=]\s*['"]([^'"]{8,})['"]""")

# Inline "this isn't a real secret" markers (detect-secrets / gitleaks conventions).
# Specific markers only — a loose word like "nosecret" would hide real findings.
_ALLOW_MARKER = re.compile(r"(?i)(pragma:\s*allowlist\s*secret|gitleaks:\s*allow|sentinel:\s*allow)")

# Substrings that mark an obvious placeholder/example rather than a live credential.
# Deliberately excludes bare "test" (real `sk_test_…` Stripe keys contain it) and
# bare repeated chars (low entropy already filters those, and provider-format
# fixtures like `ghp_aaaa…` should still be reported).
_PLACEHOLDER_WORDS = ("example", "changeme", "placeholder", "redacted", "dummy",
                      "your-", "your_", "yourapi", "notreal", "fakekey", "sample", "test-token")


def is_placeholder(value: str) -> bool:
    """True for obvious non-secrets: example/placeholder words or a `<...>` template
    (e.g. the AWS `AKIA…EXAMPLE` doc key, or `your-token-here`)."""
    low = value.lower()
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return True
    return "<" in value and ">" in value


@dataclass
class Finding:
    line: int
    rule: str
    secret: str
    confidence: str       # high | medium

    def redacted(self) -> str:
        s = self.secret
        return s[:4] + "…" + s[-2:] if len(s) > 8 else "…"


def scan_text(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        # an inline allow marker suppresses every finding on that line
        if _ALLOW_MARKER.search(line):
            continue
        for name, rx in PATTERNS.items():
            for m in rx.finditer(line):
                if is_placeholder(m.group(0)):
                    continue
                findings.append(Finding(i, name, m.group(0), "high"))
        for m in _ASSIGN.finditer(line):
            val = m.group(1)
            if is_placeholder(val):
                continue
            if not any(f.secret == val for f in findings) and looks_random(val, min_len=12, min_entropy=3.0):
                findings.append(Finding(i, "assigned-secret", val, "medium"))
        # bare high-entropy tokens
        for tok in re.findall(r"[A-Za-z0-9_\-]{20,}", line):
            if is_placeholder(tok):
                continue
            if looks_random(tok) and not any(f.secret == tok for f in findings):
                findings.append(Finding(i, "high-entropy", tok, "medium"))
    return findings
