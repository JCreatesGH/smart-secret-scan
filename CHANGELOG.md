# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [0.2.0]

### Added
- **Inline allow markers** — a line carrying `# pragma: allowlist secret`,
  `gitleaks:allow`, or `sentinel:allow` is skipped entirely (the conventions
  detect-secrets/gitleaks use).
- **Placeholder/example suppression** (`is_placeholder`) — obvious non-secrets
  are ignored: the AWS `AKIA…EXAMPLE` documentation key, `your-token-here`,
  `<YOUR_TOKEN>`, and similar. Deliberately does not suppress `sk_test_…` keys.
- New patterns: GitHub OAuth/app tokens (`gho_`/`ghu_`/`ghs_`/`ghr_`) and Stripe
  **restricted** keys (`rk_live_`/`rk_test_`).

## [0.1.0]

### Added
- Secret scanner with known token formats, an entropy fallback, secret
  redaction, a learnable `.secrets.baseline.json` allowlist, `--json` output,
  and a `sentinel` pre-commit hook.
