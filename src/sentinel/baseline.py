"""Remember confirmed false positives so the scanner stops crying wolf."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Set


def fingerprint(path: str, secret: str) -> str:
    """Stable id for a finding = hash of (file, secret value)."""
    return hashlib.sha256(f"{path}:{secret}".encode()).hexdigest()[:16]


class Baseline:
    """Set of allowlisted fingerprints, persisted as JSON."""

    def __init__(self, fingerprints: Set[str] | None = None) -> None:
        self.fingerprints: Set[str] = set(fingerprints or set())

    @classmethod
    def load(cls, path: str) -> "Baseline":
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text())
        return cls(set(data.get("allowlisted", [])))

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(
            {"allowlisted": sorted(self.fingerprints)}, indent=2))

    def allow(self, fp: str) -> None:
        self.fingerprints.add(fp)

    def is_allowed(self, fp: str) -> bool:
        return fp in self.fingerprints
