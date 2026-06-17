"""Pre-commit hook entry: sentinel [--update-baseline] [--json] <files...>"""
from __future__ import annotations
import json
import sys
from pathlib import Path
from .rules import scan_text
from .baseline import Baseline, fingerprint

BASELINE = ".secrets.baseline.json"
R, Y, DIM, X = "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def main(argv=None):
    argv = list(argv if argv is not None else sys.argv[1:])
    update = "--update-baseline" in argv
    as_json = "--json" in argv
    files = [a for a in argv if not a.startswith("-")]
    baseline = Baseline.load(BASELINE)
    hits = []   # collected new (non-allowlisted) findings: (path, finding, fingerprint)
    for path in files:
        try:
            text = Path(path).read_text(errors="ignore")
        except (OSError, IsADirectoryError):
            continue
        for f in scan_text(text):
            fp = fingerprint(path, f.secret)
            if baseline.is_allowed(fp):
                continue
            if update:
                baseline.allow(fp)
                continue
            hits.append((path, f, fp))

    if update:
        baseline.save(BASELINE)
        if not as_json:
            print(f"baseline updated -> {BASELINE}")
        return 0

    if as_json:
        # Emit redacted findings only — never the raw secret.
        print(json.dumps([
            {"file": p, "line": f.line, "rule": f.rule, "confidence": f.confidence,
             "redacted": f.redacted(), "fingerprint": fp}
            for p, f, fp in hits
        ], indent=2))
        return 1 if hits else 0

    for path, f, fp in hits:
        color = R if f.confidence == "high" else Y
        print(f"{color}{f.confidence.upper():6}{X} {f.rule}  {path}:{f.line}  "
              f"{DIM}{f.redacted()}{X}  (fp {fp})")
    if hits:
        print(f"\n{R}{len(hits)} potential secret(s) found.{X} "
              f"Real? remove them. False positive? run with --update-baseline.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
