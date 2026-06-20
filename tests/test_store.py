"""Unit tests for the SQLite store — in-memory, no browser."""

import pytest

from secagent.store import Store, page_key


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def _req(store, **over):
    """Record a request with sensible defaults; override per test."""
    base = dict(
        signature="GET /api/Users/:id {}",
        method="GET",
        path="/api/Users/:id",
        param_names="",
        url="http://x/api/Users/42",
        status=200,
        resource_type="xhr",
        auth_state="anon",
    )
    base.update(over)
    return store.record_request(**base)


# --------------------------------------------------------------------- dedupe
def test_new_signature_inserts_one_endpoint(store):
    _req(store)
    assert len(store.endpoints()) == 1


def test_duplicate_signature_dedupes(store):
    id1 = _req(store, url="http://x/api/Users/42")
    id2 = _req(store, url="http://x/api/Users/99")  # same signature, different id
    assert id1 == id2
    assert len(store.endpoints()) == 1


def test_distinct_signatures_are_distinct_rows(store):
    _req(store, signature="GET /api/Users/:id {}")
    _req(store, signature="POST /rest/user/login {email,password}", method="POST")
    assert len(store.endpoints()) == 2


# ------------------------------------------------------------- exemplar policy
def _slots(store, endpoint_id):
    return {r["slot"]: r["status"] for r in store.exemplars(endpoint_id)}


def test_nonerror_then_error(store):
    eid = _req(store, status=200, url="http://x/a/1")
    _req(store, status=500, url="http://x/a/2")
    assert _slots(store, eid) == {"primary": 200, "secondary": 500}


def test_error_first_then_nonerror_fills_primary(store):
    eid = _req(store, status=404, url="http://x/a/1")
    _req(store, status=200, url="http://x/a/2")
    # error went to secondary; the later non-error fills the empty primary slot
    assert _slots(store, eid) == {"primary": 200, "secondary": 404}


def test_two_nonerrors_first_wins(store):
    eid = _req(store, status=200, url="http://x/a/FIRST")
    _req(store, status=204, url="http://x/a/SECOND")
    assert _slots(store, eid) == {"primary": 200}
    primary = [r for r in store.exemplars(eid) if r["slot"] == "primary"][0]
    assert primary["url"] == "http://x/a/FIRST"


def test_two_errors_first_kept(store):
    eid = _req(store, status=500, url="http://x/a/FIRST")
    _req(store, status=403, url="http://x/a/SECOND")
    assert _slots(store, eid) == {"secondary": 500}


def test_only_errors_leaves_primary_empty(store):
    eid = _req(store, status=401)
    assert "primary" not in _slots(store, eid)


def test_status_none_treated_as_primary(store):
    eid = _req(store, status=None)
    assert "primary" in _slots(store, eid)


# ---------------------------------------------------- response null + reason
def test_response_body_null_with_reason(store):
    eid = _req(store, status=304, response_body=None, response_reason="cached")
    sec = store.exemplars(eid)
    # 304 is an error-class slot? No — 304 < 400 so it's primary.
    row = [r for r in sec if r["slot"] == "primary"][0]
    assert row["response_body"] is None
    assert row["response_reason"] == "cached"


# ----------------------------------------------------------- page identity
def test_page_key_format():
    assert page_key("/#/basket", "authed") == "/#/basket|authed"


def test_same_route_same_auth_is_one_page(store):
    a = store.upsert_page(route="/#/basket", auth_state="authed")
    b = store.upsert_page(route="/#/basket", auth_state="authed")
    assert a == b
    assert len(store.pages()) == 1


def test_same_route_different_auth_is_two_pages(store):
    store.upsert_page(route="/#/basket", auth_state="anon")
    store.upsert_page(route="/#/basket", auth_state="authed")
    assert len(store.pages()) == 2


# ---------------------------------------------------------- page summary
def test_set_page_summary_ok(store):
    pid = store.upsert_page(route="/#/login", auth_state="anon")
    store.set_page_summary(pid, summary='{"purpose":"login"}', summary_input="<dom>", status="ok")
    page = store.pages()[0]
    assert page["summary_status"] == "ok"
    assert page["summary_input"] == "<dom>"


def test_set_page_summary_missing(store):
    pid = store.upsert_page(route="/#/x", auth_state="anon")
    store.set_page_summary(pid, summary=None, summary_input="<dom>", status="missing")
    assert store.pages()[0]["summary_status"] == "missing"


# ------------------------------------------------------------ page<->endpoint
def test_link_and_join(store):
    eid = _req(store)
    pid = store.upsert_page(route="/#/profile", auth_state="authed")
    store.link(pid, eid)
    linked = store.endpoints_for_page(pid)
    assert len(linked) == 1
    assert linked[0]["id"] == eid


def test_link_is_idempotent(store):
    eid = _req(store)
    pid = store.upsert_page(route="/#/profile", auth_state="authed")
    store.link(pid, eid)
    store.link(pid, eid)
    assert len(store.endpoints_for_page(pid)) == 1
