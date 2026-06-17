import json
import os
from sentinel.cli import main


def _write(tmp_path, body):
    f = tmp_path / "leak.py"
    f.write_text(body)
    return str(f)


def test_cli_flags_secret_and_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)   # baseline lives in cwd; isolate it
    path = _write(tmp_path, "tok = 'ghp_" + "a" * 36 + "'\n")
    code = main([path])
    out = capsys.readouterr().out
    assert code == 1
    assert "github-pat" in out


def test_cli_json_is_redacted(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    secret = "ghp_" + "a" * 36
    path = _write(tmp_path, f"tok = '{secret}'\n")
    code = main([path, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert len(data) == 1
    assert data[0]["rule"] == "github-pat"
    assert secret not in json.dumps(data)   # raw secret never emitted
    assert "…" in data[0]["redacted"]


def test_cli_baseline_suppresses_after_update(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = _write(tmp_path, "tok = 'ghp_" + "a" * 36 + "'\n")
    assert main([path]) == 1                       # flagged
    assert main(["--update-baseline", path]) == 0  # allowlist it
    assert main([path]) == 0                        # now quiet
    assert os.path.exists(".secrets.baseline.json")


def test_cli_clean_file_exits_0(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = _write(tmp_path, "def add(a, b):\n    return a + b\n")
    assert main([path]) == 0
