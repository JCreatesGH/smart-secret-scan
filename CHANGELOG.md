# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [0.3.0]

### Added
- **12 new credential detectors**: Anthropic (`sk-ant-`), Hugging Face (`hf_`), DigitalOcean
  (`dop_v1_`), PyPI (`pypi-`), Telegram bot, Databricks (`dapi`), Doppler (`dp.pt.`), Square
  (`sq0atp-`/`sq0csp-`), Twilio API key, Postman (`PMAK-`), Linear (`lin_api_`), and Slack
  app-level tokens (`xapp-`).

### Changed
- The broad OpenAI `sk-` rule now excludes `sk-ant-`, so Anthropic keys are labeled as
  Anthropic rather than mis-tagged OpenAI.
- A token is reported by only the first (most specific) matching rule — no more double
  findings when patterns overlap.

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
