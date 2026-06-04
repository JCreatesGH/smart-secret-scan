"""Pre-commit hook entry: sentinel [--update-baseline] <files...>"""
from __future__ import annotations
import sys
from pathlib import Path
from .rules import scan_text
from .baseline import Baseline, fingerprint

BASELINE = ".secrets.baseline.json"
R, Y, DIM, X = "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def main(argv=None):
    argv = list(argv if argv is not None else sys.argv[1:])
    update = "--update-baseline" in argv
    files = [a for a in argv if not a.startswith("-")]
    baseline = Baseline.load(BASELINE)
    new_findings = 0
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
            color = R if f.confidence == "high" else Y
            print(f"{color}{f.confidence.upper():6}{X} {f.rule}  {path}:{f.line}  "
                  f"{DIM}{f.redacted()}{X}  (fp {fp})")
            new_findings += 1
    if update:
        baseline.save(BASELINE)
        print(f"baseline updated -> {BASELINE}")
        return 0
    if new_findings:
        print(f"\n{R}{new_findings} potential secret(s) found.{X} "
              f"Real? remove them. False positive? run with --update-baseline.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
