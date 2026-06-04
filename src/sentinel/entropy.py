"""Shannon entropy + a heuristic for 'this looks like a random secret'."""
from __future__ import annotations
import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_random(token: str, min_len: int = 20, min_entropy: float = 3.5) -> bool:
    """High-entropy, long, mixed-charset strings that aren't obviously words."""
    if len(token) < min_len:
        return False
    if shannon_entropy(token) < min_entropy:
        return False
    has_digit = any(c.isdigit() for c in token)
    has_alpha = any(c.isalpha() for c in token)
    # require some mix so prose/UUID-free identifiers don't all trip it
    return has_digit and has_alpha
