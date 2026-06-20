"""
Host allowlist — the legal/scope constraint as an enforced guardrail, not a policy.

"Only deliberately-vulnerable targets" is worthless if a typo can point an
automated browser at a real host. So the tool physically refuses to start unless
the target host is on the allowlist. Default = loopback only (Juice Shop runs at
localhost:3000); any other host needs an explicit --allow-host / config entry.

    target url ──▶ hostname ──▶ in allowlist? ──no──▶ raise TargetNotAllowed (CLI exits)
                                     │
                                    yes ──▶ proceed
"""

from __future__ import annotations

from urllib.parse import urlsplit

DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "::1")


class TargetNotAllowed(Exception):
    """Raised when a target host is not on the allowlist."""


def _hostname(url: str) -> str | None:
    # urlsplit needs a scheme to populate .hostname; assume http if missing.
    if "://" not in url:
        url = "http://" + url
    host = urlsplit(url).hostname
    return host.lower() if host else None


def is_allowed(url: str, extra_hosts: tuple[str, ...] = ()) -> bool:
    host = _hostname(url)
    if host is None:
        return False
    allowed = {h.lower() for h in DEFAULT_ALLOWED_HOSTS} | {h.lower() for h in extra_hosts}
    return host in allowed


def assert_allowed(url: str, extra_hosts: tuple[str, ...] = ()) -> None:
    """Raise TargetNotAllowed unless the URL's host is allowlisted."""
    if not is_allowed(url, extra_hosts):
        host = _hostname(url)
        allowed = ", ".join(DEFAULT_ALLOWED_HOSTS + tuple(extra_hosts))
        raise TargetNotAllowed(
            f"target host {host!r} is not allowlisted (allowed: {allowed}). "
            f"Pass --allow-host {host} only if you are authorized to test it."
        )
