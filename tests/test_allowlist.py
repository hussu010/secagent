"""Unit tests for the host allowlist guardrail."""

import pytest

from secagent.allowlist import (
    WEB_SECURITY_ACADEMY_SUFFIX,
    TargetNotAllowed,
    assert_allowed,
    is_allowed,
)

WSA = (WEB_SECURITY_ACADEMY_SUFFIX,)


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


# ------------------------------------------------ suffix match (v2 / PortSwigger)
@pytest.mark.parametrize(
    "url",
    [
        "https://0a1b00c2030d.web-security-academy.net/",
        "https://0a1b00c2030d.web-security-academy.net/login",
        "https://web-security-academy.net",          # bare apex matches too
        "HTTPS://0A1B.WEB-SECURITY-ACADEMY.NET/x",    # case-insensitive
        "https://0a1b.web-security-academy.net./y",   # trailing FQDN dot stripped
    ],
)
def test_lab_instances_allowed_with_suffix(url):
    assert is_allowed(url, extra_suffixes=WSA) is True


def test_suffix_not_active_by_default():
    # Without the suffix opted in, lab hosts are refused (v1 behaviour unchanged).
    assert is_allowed("https://0a1b.web-security-academy.net/") is False


@pytest.mark.parametrize(
    "url",
    [
        "https://evilweb-security-academy.net/",            # no dot boundary before web
        "https://web-security-academy.net.evil.com/",       # suffix only in the middle
        "https://web-security-academy.evil.net/",
    ],
)
def test_suffix_lookalikes_refused(url):
    assert is_allowed(url, extra_suffixes=WSA) is False


def test_embedded_credentials_refused():
    # urlsplit would resolve the host to localhost, but userinfo is rejected outright.
    assert is_allowed("http://evil.com@localhost:3000/") is False
    assert is_allowed("http://localhost@0a1b.web-security-academy.net/", extra_suffixes=WSA) is False


def test_assert_allowed_passes_for_lab_with_suffix():
    assert_allowed("https://0a1b.web-security-academy.net/", extra_suffixes=WSA)  # no raise


def test_assert_allowed_raises_for_lab_without_suffix():
    with pytest.raises(TargetNotAllowed):
        assert_allowed("https://0a1b.web-security-academy.net/")


# --------------------------------------------------- non-web schemes (allowlisted host)
@pytest.mark.parametrize(
    "url",
    [
        "file://localhost/etc/passwd",
        "javascript://localhost/%0aalert(1)",
        "ws://localhost:3000/socket",
        "wss://localhost:3000/socket",
        "ftp://localhost/x",
        "data://localhost/text",
    ],
)
def test_nonweb_schemes_refused_even_on_allowed_host(url):
    # host is loopback (allowed) but the scheme isn't http/https → must be refused.
    assert is_allowed(url) is False


def test_http_and_https_schemes_allowed():
    assert is_allowed("http://localhost:3000") is True
    assert is_allowed("https://localhost:3000") is True
