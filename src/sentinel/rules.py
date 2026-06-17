"""Known token-format rules + entropy fallback."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List
from .entropy import looks_random

# name -> compiled regex for well-known credential formats
PATTERNS = {
    "github-pat": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "github-fine": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "gitlab-pat": re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "slack-webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe-secret": re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "openai-key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    "sendgrid-key": re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    "npm-token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}

# obvious assignment of a secret-like variable
_ASSIGN = re.compile(r"""(?ix)\b(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\b\s*[:=]\s*['"]([^'"]{8,})['"]""")


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
        for name, rx in PATTERNS.items():
            for m in rx.finditer(line):
                findings.append(Finding(i, name, m.group(0), "high"))
        for m in _ASSIGN.finditer(line):
            val = m.group(1)
            if not any(f.secret == val for f in findings) and looks_random(val, min_len=12, min_entropy=3.0):
                findings.append(Finding(i, "assigned-secret", val, "medium"))
        # bare high-entropy tokens
        for tok in re.findall(r"[A-Za-z0-9_\-]{20,}", line):
            if looks_random(tok) and not any(f.secret == tok for f in findings):
                findings.append(Finding(i, "high-entropy", tok, "medium"))
    return findings
