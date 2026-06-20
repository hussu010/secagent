"""Unit tests for the page annotator — fake LLM client, no network or key."""

import json

import pytest

from secagent import annotate
from secagent.store import Store

VALID = '{"purpose": "login", "user_actions": ["log in"], "input_fields": ["email", "password"], "notable": []}'


class FakeClient:
    """Records calls and returns scripted responses (one per call)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def __call__(self, prompt: str) -> str:
        self.calls += 1
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


# ----------------------------------------------------------------- summarize
def test_summarize_success():
    summary, status = annotate.summarize("page text", FakeClient([VALID]))
    assert status == "ok"
    assert summary["purpose"] == "login"


def test_summarize_strips_code_fence():
    fenced = "```json\n" + VALID + "\n```"
    summary, status = annotate.summarize("p", FakeClient([fenced]))
    assert status == "ok" and summary["input_fields"] == ["email", "password"]


def test_summarize_retries_then_succeeds():
    client = FakeClient(["not json", VALID])
    summary, status = annotate.summarize("p", client)
    assert status == "ok"
    assert client.calls == 2  # failed once, retried once


def test_summarize_missing_after_retries():
    client = FakeClient(["nope", "still nope"])
    summary, status = annotate.summarize("p", client)
    assert status == "missing" and summary is None
    assert client.calls == 2


def test_summarize_handles_exception_from_client():
    client = FakeClient([RuntimeError("api down"), VALID])
    summary, status = annotate.summarize("p", client)
    assert status == "ok" and client.calls == 2


def test_summarize_rejects_non_object_json():
    summary, status = annotate.summarize("p", FakeClient(["[1,2,3]", "[4]"]))
    assert status == "missing"


# ------------------------------------------------------------ annotate_pending
@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def test_annotate_pending_marks_ok(store):
    pid = store.upsert_page(route="/#/login", auth_state="anon")
    store.set_page_summary(pid, summary=None, summary_input="login form text", status="pending")
    counts = annotate.annotate_pending(store, FakeClient([VALID]))
    assert counts["ok"] == 1
    page = store.pages()[0]
    assert page["summary_status"] == "ok"
    assert json.loads(page["summary"])["purpose"] == "login"


def test_annotate_pending_marks_missing_on_failure(store):
    pid = store.upsert_page(route="/#/x", auth_state="anon")
    store.set_page_summary(pid, summary=None, summary_input="text", status="pending")
    counts = annotate.annotate_pending(store, FakeClient(["bad", "bad"]))
    assert counts["missing"] == 1
    assert store.pages()[0]["summary_status"] == "missing"


def test_annotate_pending_skips_already_done(store):
    pid = store.upsert_page(route="/#/done", auth_state="anon")
    store.set_page_summary(pid, summary='{"purpose":"x"}', summary_input="t", status="ok")
    client = FakeClient([VALID])
    counts = annotate.annotate_pending(store, client)
    assert counts["skipped"] == 1 and client.calls == 0


def test_annotate_pending_missing_when_no_snapshot(store):
    pid = store.upsert_page(route="/#/blank", auth_state="anon")
    store.set_page_summary(pid, summary=None, summary_input=None, status="pending")
    counts = annotate.annotate_pending(store, FakeClient([VALID]))
    assert counts["missing"] == 1
