"""Unit tests for the SQLite store — in-memory, no browser."""

import pytest

from secagent.status import BUDGET_EXHAUSTED, SOLVED, TOOL_ERROR
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


# ============================================================ hunt trace (v2)
def _run(store, **over):
    base = dict(lab_id="sqli-login-bypass", base_url="https://x.web-security-academy.net", goal="Log in as administrator")
    base.update(over)
    return store.start_run(**base)


def test_start_run_is_in_progress(store):
    rid = _run(store)
    row = store.run(rid)
    assert row["status"] is None  # in-progress until finished
    assert row["ended_at"] is None
    assert row["goal"] == "Log in as administrator"


def test_record_and_read_steps_in_order(store):
    rid = _run(store)
    store.record_step(rid, 0, "hypothesize", input_bundle="goal only", observation="hyp: try SQLi")
    store.record_step(rid, 1, "act", action='{"tool":"http.request"}')
    store.record_step(rid, 2, "score", score="not_solved")
    steps = store.steps(rid)
    assert [s["idx"] for s in steps] == [0, 1, 2]
    assert steps[0]["input_bundle"] == "goal only"
    assert steps[2]["score"] == "not_solved"


def test_record_step_is_idempotent_on_run_idx(store):
    rid = _run(store)
    store.record_step(rid, 0, "act", action="v1")
    store.record_step(rid, 0, "act", action="v2")  # same (run, idx) → update, not dup
    steps = store.steps(rid)
    assert len(steps) == 1
    assert steps[0]["action"] == "v2"


def test_finish_run_sets_terminal_status(store):
    rid = _run(store)
    store.finish_run(rid, SOLVED)
    row = store.run(rid)
    assert row["status"] == SOLVED
    assert row["ended_at"] is not None


def test_finish_run_rejects_unknown_status(store):
    rid = _run(store)
    with pytest.raises(ValueError):
        store.finish_run(rid, "totally_made_up")


def test_finalize_unfinished_recovers_crashed_runs(store):
    crashed = _run(store)              # never finished → simulates a killed process
    done = _run(store)
    store.finish_run(done, SOLVED)
    n = store.finalize_unfinished(TOOL_ERROR)
    assert n == 1                       # only the crashed one
    assert store.run(crashed)["status"] == TOOL_ERROR
    assert store.run(done)["status"] == SOLVED  # untouched


def test_finalize_unfinished_rejects_unknown_status(store):
    _run(store)
    with pytest.raises(ValueError):
        store.finalize_unfinished("nope")


def test_touch_run_updates_last_seen(store):
    rid = _run(store, launched_at="2026-06-20T00:00:00Z")
    store.touch_run(rid, now="2026-06-20T00:05:00Z")
    assert store.run(rid)["last_seen"] == "2026-06-20T00:05:00Z"


def test_runs_listing(store):
    _run(store, lab_id="a")
    _run(store, lab_id="b")
    assert [r["lab_id"] for r in store.runs()] == ["a", "b"]


def test_budget_exhausted_is_a_valid_terminal(store):
    rid = _run(store)
    store.finish_run(rid, BUDGET_EXHAUSTED, note="hit step cap")
    assert store.run(rid)["status"] == BUDGET_EXHAUSTED
    assert store.run(rid)["note"] == "hit step cap"
