"""Replay a real recorded Juice Shop session — deterministic integration test, no browser."""

import json
import pathlib

from secagent import capture
from secagent.store import Store

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "juiceshop_session.json"


def _replayed() -> Store:
    events = json.loads(FIXTURE.read_text())
    s = Store(":memory:")
    capture.replay(s, events)
    return s


def test_real_session_builds_expected_surface():
    s = _replayed()
    sigs = {e["signature"] for e in s.endpoints()}
    # the expected-smoke endpoints a real Juice Shop browse must surface
    assert "GET /rest/products/search {q}" in sigs
    assert any(sig.startswith("GET /api/Challenges") for sig in sigs)
    assert "GET /rest/admin/application-configuration {}" in sigs
    s.close()


def test_static_assets_are_dropped():
    s = _replayed()
    bad = [e["path"] for e in s.endpoints() if e["path"].endswith((".js", ".css", ".png", ".woff2"))]
    assert bad == [], f"static assets leaked into the map: {bad}"
    s.close()


def test_pages_recorded_with_auth_state():
    s = _replayed()
    pages = s.pages()
    assert len(pages) >= 3
    assert all(p["auth_state"] in ("anon", "authed") for p in pages)
    s.close()


def test_replay_is_deterministic():
    a, b = _replayed(), _replayed()
    assert {e["signature"] for e in a.endpoints()} == {e["signature"] for e in b.endpoints()}
    assert len(a.pages()) == len(b.pages())
    a.close()
    b.close()
