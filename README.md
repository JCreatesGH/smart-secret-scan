# sentinel — self-learning secret scanner

[![CI](https://github.com/JCreatesGH/smart-secret-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/JCreatesGH/smart-secret-scan/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A pre-commit secret scanner that blocks credentials from being committed — and then **remembers your confirmed false positives** so it stops crying wolf. Known token formats plus an entropy fallback, with a learnable baseline. Zero dependencies.

![screenshot](assets/screenshot.png)

## Install

```bash
pip install sentinel-scan
```

As a [pre-commit](https://pre-commit.com) hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/JCreatesGH/smart-secret-scan
    rev: v0.1.0
    hooks:
      - id: sentinel
```

## How it works

```bash
sentinel app.py config.py        # exits 1 if it finds anything new
```

- **Known formats** — GitHub PATs, AWS access keys, Slack/Stripe/Google keys, JWTs, PEM private keys, and `password = "…"`-style assignments.
- **Entropy fallback** — long, high-entropy, mixed-charset tokens are flagged even if they don't match a known pattern.
- **Redaction** — secrets are never printed in full.

## The "self-learning" part

When something is a genuine false positive (an example token, a test fixture), allowlist it once:

```bash
sentinel --update-baseline tests/fixtures.py
```

That records a `(file, secret)` **fingerprint** in `.secrets.baseline.json` (commit it). The scanner stays quiet about that exact string in that file forever — but still catches it if it shows up somewhere new.

## Library

```python
from sentinel import scan_text, Baseline, fingerprint
findings = scan_text(open("app.py").read())
```

## Development

```bash
python -m pytest -q   # 10 tests
```

## License

MIT
