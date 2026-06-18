from sentinel import scan_text


def rules(findings):
    return {f.rule for f in findings}


def test_detects_known_tokens():
    text = (
        "gh = 'ghp_" + "a" * 36 + "'\n"
        "aws = 'AKIAABCDEFGHIJKLMNOP'\n"
        "stripe = 'sk_live_" + "a1B2c3D4e5F6g7H8" + "'\n"
    )
    r = rules(scan_text(text))
    assert "github-pat" in r
    assert "aws-access-key" in r
    assert "stripe-secret" in r


def test_detects_assigned_secret():
    findings = scan_text('password = "Tr0ub4dor&3xK9mZ"')
    assert any(f.rule == "assigned-secret" for f in findings)


def test_private_key_and_jwt():
    r = rules(scan_text("-----BEGIN RSA PRIVATE KEY-----"))
    assert "private-key" in r
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w"
    assert "jwt" in rules(scan_text(f"auth = '{jwt}'"))


def test_detects_more_known_tokens():
    text = (
        "gl = 'glpat-" + "a" * 20 + "'\n"
        "npm = 'npm_" + "b" * 36 + "'\n"
        "oai = 'sk-proj-" + "c" * 30 + "'\n"
        "hook = 'https://hooks.slack.com/services/T00/B11/abcDEF'\n"
    )
    r = rules(scan_text(text))
    assert {"gitlab-pat", "npm-token", "openai-key", "slack-webhook"} <= r


def test_clean_code_has_no_findings():
    text = "def add(a, b):\n    return a + b  # just normal code\n"
    assert scan_text(text) == []


def test_findings_carry_line_and_redaction():
    f = scan_text("\nkey = 'ghp_" + "b" * 36 + "'")[0]
    assert f.line == 2
    assert "…" in f.redacted() and f.secret not in f.redacted()


def test_detects_github_oauth_and_stripe_restricted():
    text = ("gho = 'gho_" + "a" * 36 + "'\n"
            "rk = 'rk_live_" + "a1B2c3D4e5F6g7H8" + "'\n")
    r = rules(scan_text(text))
    assert "github-oauth" in r and "stripe-restricted" in r


def test_inline_allow_marker_suppresses_line():
    # a real-looking token, but the line is annotated as allowed
    line = "token = 'ghp_" + "a" * 36 + "'  # pragma: allowlist secret"
    assert scan_text(line) == []
    assert scan_text("k = 'ghp_" + "a" * 36 + "'  # gitleaks:allow") == []
    # without the marker it IS reported
    assert rules(scan_text("token = 'ghp_" + "a" * 36 + "'")) == {"github-pat"}


def test_placeholder_and_example_values_are_ignored():
    # the canonical AWS documentation key ends in EXAMPLE -> not a real secret
    assert scan_text("aws = 'AKIAIOSFODNN7EXAMPLE'") == []
    # template / placeholder assignments
    assert scan_text('api_key = "your-api-key-here"') == []
    assert scan_text('token = "<YOUR_TOKEN_HERE>"') == []
    # a genuine AKIA key (no EXAMPLE) is still caught
    assert "aws-access-key" in rules(scan_text("aws = 'AKIA1B2C3D4E5F6G7H8J'"))
