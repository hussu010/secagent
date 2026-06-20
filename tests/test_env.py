"""Unit tests for the stdlib .env loader."""

import os

from secagent.env import load_dotenv, parse_env


def test_parse_basic_and_quotes_and_comments_and_export():
    text = (
        "# a comment\n"
        "\n"
        "ANTHROPIC_API_KEY=sk-ant-123\n"
        'QUOTED="has spaces"\n'
        "SINGLE='single quoted'\n"
        "export EXPORTED=ok\n"
        "  SPACED = trimmed \n"
        "no_equals_here\n"
        "=novalue\n"
    )
    env = parse_env(text)
    assert env["ANTHROPIC_API_KEY"] == "sk-ant-123"
    assert env["QUOTED"] == "has spaces"
    assert env["SINGLE"] == "single quoted"
    assert env["EXPORTED"] == "ok"
    assert env["SPACED"] == "trimmed"
    assert "no_equals_here" not in env
    assert "" not in env  # bare "=novalue" has empty key → skipped


def test_load_missing_file_is_noop():
    assert load_dotenv("/nonexistent/path/.env") == {}


def test_load_applies_new_keys(tmp_path, monkeypatch):
    monkeypatch.delenv("SECAGENT_TEST_KEY", raising=False)
    p = tmp_path / ".env"
    p.write_text("SECAGENT_TEST_KEY=fromfile\n")
    applied = load_dotenv(str(p))
    assert applied == {"SECAGENT_TEST_KEY": "fromfile"}
    assert os.environ["SECAGENT_TEST_KEY"] == "fromfile"


def test_existing_env_var_wins_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SECAGENT_TEST_KEY", "fromenv")
    p = tmp_path / ".env"
    p.write_text("SECAGENT_TEST_KEY=fromfile\n")
    applied = load_dotenv(str(p))
    assert applied == {}                                   # not overridden
    assert os.environ["SECAGENT_TEST_KEY"] == "fromenv"


def test_override_true_replaces(tmp_path, monkeypatch):
    monkeypatch.setenv("SECAGENT_TEST_KEY", "fromenv")
    p = tmp_path / ".env"
    p.write_text("SECAGENT_TEST_KEY=fromfile\n")
    load_dotenv(str(p), override=True)
    assert os.environ["SECAGENT_TEST_KEY"] == "fromfile"
