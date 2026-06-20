"""Unit tests for the capture core and the replay engine."""

import pytest

from secagent.capture import auth_state, cap_body, ingest, replay, should_capture
from secagent.store import Store


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


# ----------------------------------------------------------- should_capture
@pytest.mark.parametrize("rtype", ["xhr", "fetch", "document", "other", "websocket", "eventsource"])
def test_keeps_non_static(rtype):
    assert should_capture(rtype) is True


@pytest.mark.parametrize("rtype", ["image", "stylesheet", "font", "media", "script", "manifest", "texttrack"])
def test_drops_static(rtype):
    assert should_capture(rtype) is False


# --------------------------------------------------------------- auth_state
def test_auth_state_authed():
    assert auth_state({"authorization": "Bearer abc"}) == "authed"


def test_auth_state_case_insensitive_header():
    assert auth_state({"Authorization": "Bearer abc"}) == "authed"


def test_auth_state_anon_when_absent_or_empty():
    assert auth_state({}) == "anon"
    assert auth_state(None) == "anon"
    assert auth_state({"authorization": "   "}) == "anon"


# ------------------------------------------------------------------ cap_body
def test_cap_body_passthrough():
    assert cap_body("hello") == ("hello", None)


def test_cap_body_none():
    assert cap_body(None) == (None, None)


def test_cap_body_truncates():
    big = "x" * (64 * 1024 + 10)
    text, reason = cap_body(big)
    assert reason == "truncated"
    assert len(text) == 64 * 1024


# -------------------------------------------------------------------- ingest
def test_ingest_static_returns_none_and_records_nothing(store):
    ev = {"type": "request", "method": "GET", "url": "http://x/logo.png", "resource_type": "image"}
    assert ingest(store, ev, None) is None
    assert len(store.endpoints()) == 0


def test_ingest_records_endpoint_and_links_page(store):
    pid = store.upsert_page(route="/#/search", auth_state="anon")
    ev = {
        "type": "request", "method": "GET",
        "url": "http://localhost:3000/rest/products/search?q=apple",
        "status": 200, "resource_type": "xhr", "req_headers": {},
    }
    eid = ingest(store, ev, pid)
    assert eid is not None
    eps = store.endpoints()
    assert len(eps) == 1
    assert eps[0]["signature"] == "GET /rest/products/search {q}"
    assert len(store.endpoints_for_page(pid)) == 1


def test_ingest_unreadable_response_stored_as_null_plus_reason(store):
    ev = {
        "type": "request", "method": "GET", "url": "http://x/rest/redirect",
        "status": 302, "resource_type": "other", "req_headers": {},
        "resp_body": None, "resp_reason": "no-body",
    }
    eid = ingest(store, ev, None)
    ex = store.exemplars(eid)[0]
    assert ex["response_body"] is None and ex["response_reason"] == "no-body"


def test_ingest_authed_request_records_auth(store):
    ev = {
        "type": "request", "method": "GET", "url": "http://x/rest/basket/1",
        "status": 200, "resource_type": "xhr",
        "req_headers": {"authorization": "Bearer x"},
    }
    eid = ingest(store, ev, None)
    assert store.exemplars(eid)[0]["auth_state"] == "authed"


# -------------------------------------------------------------------- replay
def test_replay_builds_map(store):
    events = [
        {"type": "navigate", "route": "/#/search", "auth_state": "anon", "title": "Search"},
        {"type": "request", "method": "GET",
         "url": "http://localhost:3000/rest/products/search?q=a",
         "status": 200, "resource_type": "xhr", "req_headers": {}},
        {"type": "request", "method": "GET",
         "url": "http://localhost:3000/api/Products/6",
         "status": 200, "resource_type": "xhr", "req_headers": {}},
        {"type": "request", "method": "GET",
         "url": "http://localhost:3000/main.js", "status": 200, "resource_type": "script"},
        {"type": "navigate", "route": "/#/basket", "auth_state": "authed", "title": "Basket"},
        {"type": "request", "method": "GET",
         "url": "http://localhost:3000/api/BasketItems/3",
         "status": 200, "resource_type": "xhr",
         "req_headers": {"authorization": "Bearer x"}},
    ]
    replay(store, events)

    eps = {e["signature"] for e in store.endpoints()}
    assert "GET /rest/products/search {q}" in eps
    assert "GET /api/Products/:id {}" in eps
    assert "GET /api/BasketItems/:id {}" in eps
    # the script asset was dropped
    assert not any(e["path"].endswith("main.js") for e in store.endpoints())
    # two pages, distinct auth
    pages = {(p["route"], p["auth_state"]) for p in store.pages()}
    assert pages == {("/#/search", "anon"), ("/#/basket", "authed")}
