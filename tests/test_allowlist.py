"""Unit tests for the host allowlist guardrail."""

import pytest

from secagent.allowlist import TargetNotAllowed, assert_allowed, is_allowed


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:3000",
        "http://localhost:3000/#/search",
        "http://127.0.0.1:3000",
        "https://localhost",
        "LOCALHOST:3000",            # case-insensitive, scheme-less
        "http://[::1]:3000",
    ],
)
def test_loopback_allowed(url):
    assert is_allowed(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://juice-shop.herokuapp.com",
        "http://192.168.1.50:3000",
        "http://evil.localhost.attacker.com",   # not actually loopback
    ],
)
def test_remote_hosts_refused(url):
    assert is_allowed(url) is False


def test_extra_host_allows():
    url = "http://staging.internal:3000"
    assert is_allowed(url) is False
    assert is_allowed(url, extra_hosts=("staging.internal",)) is True


def test_assert_allowed_passes_for_localhost():
    assert_allowed("http://localhost:3000")  # no raise


def test_assert_allowed_raises_for_remote():
    with pytest.raises(TargetNotAllowed) as exc:
        assert_allowed("http://example.com")
    assert "example.com" in str(exc.value)


def test_garbage_url_refused():
    assert is_allowed("not a url") is False
