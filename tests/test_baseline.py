from sentinel import Baseline, fingerprint, scan_text


def test_fingerprint_stable_and_file_specific():
    a = fingerprint("a.py", "ghp_x")
    assert a == fingerprint("a.py", "ghp_x")
    assert a != fingerprint("b.py", "ghp_x")


def test_baseline_suppresses_known_false_positive(tmp_path):
    secret = "ghp_" + "c" * 36
    findings = scan_text(f"k='{secret}'")
    fp = fingerprint("conf.py", findings[0].secret)

    b = Baseline()
    assert not b.is_allowed(fp)
    b.allow(fp)
    path = tmp_path / "bl.json"
    b.save(str(path))

    reloaded = Baseline.load(str(path))
    assert reloaded.is_allowed(fp)


def test_load_missing_returns_empty(tmp_path):
    assert Baseline.load(str(tmp_path / "nope.json")).fingerprints == set()
