"""
Capture core — turn observed traffic into store records.

One ingest path, two feeders:

    live Playwright events ──┐
                             ├─▶ ingest() ─▶ normalize ─▶ store.record_request + link
    replayed fixture events ─┘

The live browser driver (recon.py) builds event dicts from Playwright objects;
tests replay recorded event dicts from a fixture. Both call the same ingest(),
so the integration is tested deterministically with no browser.

Event dict shape (see tests/fixtures):
    {"type": "navigate", "route": "/#/search", "auth_state": "anon", "title": "..."}
    {"type": "request",  "method": "GET", "url": "...", "status": 200,
     "resource_type": "xhr", "req_headers": {...}, "req_body": null,
     "req_content_type": null, "resp_body": "...", "resp_reason": null}

Locked decisions encoded here:
  - capture ALL non-static (drop only true assets by resource_type)
  - response body capped at 64 KB; unreadable bodies stored as NULL + reason
  - auth_state derived from presence of an Authorization header
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .normalize import extract_param_names, normalize_path, signature
from .store import Store

# Pure asset noise — dropped. Everything else (document/xhr/fetch/other/websocket/
# eventsource/...) is KEPT, because Playwright sometimes mislabels API calls.
STATIC_TYPES = {"image", "stylesheet", "font", "media", "manifest", "texttrack", "script"}

BODY_LIMIT = 64 * 1024


def should_capture(resource_type: str | None) -> bool:
    return resource_type not in STATIC_TYPES


def auth_state(headers: dict[str, str] | None) -> str:
    """'authed' if the request carries a non-empty Authorization header, else 'anon'."""
    if not headers:
        return "anon"
    for k, v in headers.items():
        if k.lower() == "authorization" and v and v.strip():
            return "authed"
    return "anon"


def cap_body(text: str | None, limit: int = BODY_LIMIT) -> tuple[str | None, str | None]:
    """Return (stored_text, reason). Truncates oversized bodies with reason='truncated'."""
    if text is None:
        return None, None
    if len(text) > limit:
        return text[:limit], "truncated"
    return text, None


def ingest(store: Store, event: dict, page_id: int | None, now: str | None = None) -> int | None:
    """
    Feed one 'request' event into the store. Returns the endpoint id, or None if
    the event was filtered out as a static asset.
    """
    rtype = event.get("resource_type")
    if not should_capture(rtype):
        return None

    method = event["method"]
    url = event["url"]
    req_body = event.get("req_body")
    req_ctype = event.get("req_content_type")

    split = urlsplit(url)
    sig = signature(method, url, req_body, req_ctype)
    npath = normalize_path(split.path)
    pnames = ",".join(sorted(extract_param_names(split.query, req_body, req_ctype)))

    raw_resp = event.get("resp_body")
    if raw_resp is None:
        resp_body, resp_reason = None, event.get("resp_reason")
    else:
        resp_body, resp_reason = cap_body(raw_resp)

    capped_req, _ = cap_body(req_body) if isinstance(req_body, str) else (req_body, None)

    endpoint_id = store.record_request(
        signature=sig,
        method=method,
        path=npath,
        param_names=pnames,
        url=url,
        status=event.get("status"),
        resource_type=rtype,
        auth_state=auth_state(event.get("req_headers")),
        request_content_type=req_ctype,
        request_body=capped_req,
        response_body=resp_body,
        response_reason=resp_reason,
        now=now,
    )
    if page_id is not None:
        store.link(page_id, endpoint_id)
    return endpoint_id


def replay(store: Store, events: list[dict], now: str | None = None) -> None:
    """
    Replay a recorded session into a store. 'navigate' events open/resolve the
    current page (by route + auth); 'request' events ingest under it. This is the
    exact sequence the live driver produces, so replaying a fixture reproduces a
    real capture run deterministically.
    """
    current_page: int | None = None
    for ev in events:
        kind = ev.get("type")
        if kind == "navigate":
            current_page = store.upsert_page(
                route=ev["route"],
                auth_state=ev.get("auth_state", "anon"),
                title=ev.get("title"),
                now=now,
            )
            # Stash the page snapshot as the (pending) annotator input — the
            # auditable exact input T5 will summarize. Last snapshot per page wins.
            if ev.get("snapshot"):
                store.set_page_summary(
                    current_page, summary=None, summary_input=ev["snapshot"], status="pending"
                )
        elif kind == "request":
            ingest(store, ev, current_page, now=now)
