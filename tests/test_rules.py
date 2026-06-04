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


def test_clean_code_has_no_findings():
    text = "def add(a, b):\n    return a + b  # just normal code\n"
    assert scan_text(text) == []


def test_findings_carry_line_and_redaction():
    f = scan_text("\nkey = 'ghp_" + "b" * 36 + "'")[0]
    assert f.line == 2
    assert "…" in f.redacted() and f.secret not in f.redacted()
