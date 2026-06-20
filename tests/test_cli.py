"""CLI tests — arg parsing + allowlist refusal exit codes (no browser/LLM)."""

import pytest

from secagent.cli import main


def test_capture_refuses_remote_host(capsys):
    # v1 behaviour: a non-loopback capture target exits 2 before launching a browser.
    assert main(["capture", "http://example.com"]) == 2
    assert "refused" in capsys.readouterr().out


def test_hunt_refuses_offscope_target(capsys):
    # Refusal happens before the browser/LLM stack is imported, so no anthropic needed.
    code = main(["hunt", "http://evil.com", "--goal", "x", "--lab-id", "y"])
    assert code == 2
    assert "refused" in capsys.readouterr().out


def test_hunt_refuses_offscope_even_with_unrelated_suffix(capsys):
    code = main([
        "hunt", "https://app.evil.net/", "--goal", "x", "--lab-id", "y",
        "--allow-suffix", ".other-lab.net",
    ])
    assert code == 2


def test_hunt_requires_goal_and_lab_id():
    with pytest.raises(SystemExit):  # argparse: missing required --goal/--lab-id
        main(["hunt", "https://0a1b.web-security-academy.net"])
