"""Unit tests for the report/inspection view."""

import pytest

from secagent import capture, report
from secagent.store import Store

EVENTS = [
    {"type": "navigate", "route": "/#/search", "auth_state": "anon", "title": "Search"},
    {"type": "request", "method": "GET",
     "url": "http://localhost:3000/rest/products/search?q=a",
     "status": 200, "resource_type": "xhr", "req_headers": {}},
    {"type": "navigate", "route": "/#/basket", "auth_state": "authed", "title": "Basket"},
    {"type": "request", "method": "GET",
     "url": "http://localhost:3000/api/BasketItems/3",
     "status": 200, "resource_type": "xhr", "req_headers": {"authorization": "Bearer x"}},
]


@pytest.fixture
def store():
    s = Store(":memory:")
    capture.replay(s, EVENTS)
    yield s
    s.close()


def test_render_text_lists_endpoints_and_pages(store):
    text = report.render_text(store)
    assert "GET /rest/products/search {q}" in text
    assert "GET /api/BasketItems/:id {}" in text
    assert "/#/search" in text and "anon" in text
    assert "/#/basket" in text and "authed" in text


def test_render_text_shows_exemplar_status(store):
    text = report.render_text(store)
    assert "[primary 200]" in text


def test_render_html_renders_tables(store):
    out = report.render_html(store)
    assert "<table" in out
    assert "products/search" in out
    assert "BasketItems/:id" in out


def test_render_html_escapes_signature():
    s = Store(":memory:")
    # a signature with HTML-ish chars should be escaped, not injected
    s.record_request(
        signature="GET /x/<script> {}", method="GET", path="/x/<script>",
        param_names="", url="http://x/x/<script>", status=200, resource_type="xhr",
    )
    out = report.render_html(s)
    assert "<script>" not in out  # raw tag must not appear
    assert "&lt;script&gt;" in out
    s.close()
