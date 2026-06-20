"""
Host allowlist — the legal/scope constraint as an enforced guardrail, not a policy.

"Only deliberately-vulnerable targets" is worthless if a typo (or a hunting agent
that picks its own URLs) can point an automated browser at a real host. So the tool
physically refuses to act on any URL whose host is not allowlisted.

    target url ──▶ canonical host ──▶ allowed? ──no──▶ raise TargetNotAllowed
                       │                  │
                       │                 yes ──▶ proceed
                       └─ lowercase, strip trailing dot, IDNA/punycode,
                          reject embedded credentials

Two ways to allow a host:
  - exact host  — loopback by default (Juice Shop runs at localhost:3000)
  - suffix      — e.g. ".web-security-academy.net" matches the random per-instance
                  subdomains PortSwigger labs spin up. Opt-in: default suffix set is
                  empty, so v1 capture behaviour is unchanged. The v2 hunter passes
                  WEB_SECURITY_ACADEMY_SUFFIX.

Suffix matching is boundary-anchored on a leading dot: ".web-security-academy.net"
matches "0a1b.web-security-academy.net" and the bare "web-security-academy.net", but
NOT "evilweb-security-academy.net" (no dot before "web"). The host is IDNA-canonical
first, so a unicode homograph cannot smuggle a lookalike suffix past the check.

v2 note (per-action + per-redirect): the hunter calls assert_allowed on EVERY
navigation and HTTP action, and on the FINAL url after redirects — not once at
startup. This module is that single chokepoint; both browser nav and the HTTP tool
route through it.
"""

from __future__ import annotations

from urllib.parse import urlsplit

DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "::1")
# Opt-in suffixes (empty by default → v1 capture unaffected). The hunt path adds
# the PortSwigger suffix below.
DEFAULT_ALLOWED_SUFFIXES: tuple[str, ...] = ()

# The authorized v2 target family: every WSA lab instance is a random subdomain.
WEB_SECURITY_ACADEMY_SUFFIX = ".web-security-academy.net"


class TargetNotAllowed(Exception):
    """Raised when a target host is not on the allowlist."""


def _canonical_host(url: str) -> str | None:
    """
    Canonical hostname for an allowlist decision, or None if the URL is unusable
    or carries embedded credentials.

    Normalizes case + trailing FQDN dot, rejects userinfo (an agent must never pass
    creds in a URL), and IDNA-encodes so a unicode homograph of an allowed suffix
    cannot slip through.
    """
    if "://" not in url:
        url = "http://" + url
    try:
        split = urlsplit(url)
    except ValueError:
        return None
    # Only web schemes. file://localhost/etc/passwd, javascript://localhost, ws://...
    # all carry an allowlisted host but must never be reachable.
    if split.scheme not in ("http", "https"):
        return None
    # Defense-in-depth: refuse "http://localhost@evil.com" style userinfo outright.
    if split.username or split.password:
        return None
    host = split.hostname
    if not host:
        return None
    host = host.rstrip(".").lower()
    if not host:
        return None
    try:
        # IDNA gives the punycode (ascii) form; defeats homograph suffixes. Fails
        # on IPs / IPv6 / spaces — keep the lowercased form in that case.
        host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        pass
    return host


def _suffix_match(host: str, suffixes: tuple[str, ...]) -> bool:
    for suf in suffixes:
        s = suf.lower()
        if not s.startswith("."):
            s = "." + s
        if host == s[1:] or host.endswith(s):
            return True
    return False


def is_allowed(
    url: str,
    extra_hosts: tuple[str, ...] = (),
    extra_suffixes: tuple[str, ...] = (),
) -> bool:
    host = _canonical_host(url)
    if host is None:
        return False
    allowed = {h.lower() for h in DEFAULT_ALLOWED_HOSTS} | {h.lower() for h in extra_hosts}
    if host in allowed:
        return True
    return _suffix_match(host, tuple(DEFAULT_ALLOWED_SUFFIXES) + tuple(extra_suffixes))


def assert_allowed(
    url: str,
    extra_hosts: tuple[str, ...] = (),
    extra_suffixes: tuple[str, ...] = (),
) -> None:
    """Raise TargetNotAllowed unless the URL's host is allowlisted."""
    if not is_allowed(url, extra_hosts, extra_suffixes):
        host = _canonical_host(url)
        allowed = ", ".join(
            DEFAULT_ALLOWED_HOSTS
            + tuple(extra_hosts)
            + tuple(s for s in (DEFAULT_ALLOWED_SUFFIXES + tuple(extra_suffixes)))
        )
        raise TargetNotAllowed(
            f"target host {host!r} is not allowlisted (allowed: {allowed}). "
            f"Pass --allow-host {host} only if you are authorized to test it."
        )
