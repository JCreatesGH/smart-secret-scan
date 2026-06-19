"""sentinel: a self-learning secret scanner for pre-commit hooks."""
from .entropy import shannon_entropy, looks_random
from .rules import PATTERNS, scan_text, Finding, is_placeholder
from .baseline import Baseline, fingerprint
__all__ = ["shannon_entropy", "looks_random", "PATTERNS", "scan_text",
           "Finding", "is_placeholder", "Baseline", "fingerprint"]
__version__ = "0.3.0"
