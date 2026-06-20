"""
Live capture driver (T2 wiring + T6 route watcher).

Records a browse session as a flat list of events, then replays them into the
store. Recording and replaying share one format, so:
  - a manual session both populates the SQLite map AND can be dumped as a
    deterministic test fixture
  - the tested capture core (capture.ingest/replay) is the exact code path used
    live — no separate "real" path to drift

    requests  ──(context.on 'response')──┐
                                         ├─▶ events[] ──▶ capture.replay(store, events)
    routes    ──(poll page.url + settle)─┘

Route detection note: Juice Shop is hash-routed (/#/...), where framenavigated
does NOT fire and in-binding page calls deadlock the sync API. So we poll
page.url for route changes (human-paced, cheap) and capture requests via events.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

from . import capture
from .allowlist import assert_allowed
from .store import Store

SNAPSHOT_LIMIT = 4000  # chars of page text stored as the (pending) annotator input


def resolve_route(url: str) -> str:
    """Page identity route, reusing the path normalizer (DRY with endpoints)."""
    from .normalize import normalize_path

    split = urlsplit(url)
    if split.fragment:
        return "/#" + normalize_path(split.fragment)
    return normalize_path(split.path)


def run_session(
    target: str = "http://localhost:3000",
    db_path: str = "recon.db",
    *,
    extra_hosts: tuple[str, ...] = (),
    record_to: str | None = None,
    auto_routes: list[str] | None = None,
) -> dict:
    """
    Drive a browse of `target`, capture into `db_path`. Manual unless `auto_routes`
    is given (headless scripted drive — used to record fixtures / smoke). Returns
    a small summary dict.
    """
    assert_allowed(target, extra_hosts)

    events: list[dict] = []
    state = {"auth": "anon", "route": None}

    def on_response(response) -> None:
        try:
            request = response.request
            rtype = request.resource_type
            if not capture.should_capture(rtype):
                return
            headers = request.all_headers()
            if any(k.lower() == "authorization" and v.strip() for k, v in headers.items()):
                state["auth"] = "authed"  # session becomes authenticated, stays so

            resp_body, resp_reason = None, None
            try:
                resp_body = response.text()
            except Exception:
                resp_reason = "unreadable"

            events.append({
                "type": "request",
                "method": request.method,
                "url": request.url,
                "status": response.status,
                "resource_type": rtype,
                "req_headers": headers,
                "req_body": request.post_data,
                "req_content_type": headers.get("content-type"),
                "resp_body": resp_body,
                "resp_reason": resp_reason,
            })
        except Exception:
            pass  # never let capture crash the browse

    def record_route(page) -> None:
        route = resolve_route(page.url)
        if route == state["route"]:
            return
        state["route"] = route
        snapshot = None
        try:
            snapshot = page.inner_text("body", timeout=2000)[:SNAPSHOT_LIMIT]
        except Exception:
            pass
        title = None
        try:
            title = page.title()
        except Exception:
            pass
        events.append({
            "type": "navigate",
            "route": route,
            "auth_state": state["auth"],
            "title": title,
            "snapshot": snapshot,
        })

    with sync_playwright() as p:
        headless = auto_routes is not None
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context()
        context.on("response", on_response)
        page = context.new_page()
        page.goto(target, wait_until="domcontentloaded")
        page.wait_for_timeout(1200)
        record_route(page)

        if auto_routes is not None:
            for route in auto_routes:
                try:
                    page.goto(target.rstrip("/") + route, wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(700)
                    record_route(page)
                except Exception:
                    pass
        else:
            print(f"\nBrowsing {target} — drive by hand. Ctrl-C (or close window) to finish.\n")
            try:
                while not page.is_closed():
                    page.wait_for_timeout(500)
                    record_route(page)
            except KeyboardInterrupt:
                pass
            except Exception:
                pass

        try:
            browser.close()
        except Exception:
            pass

    if record_to:
        with open(record_to, "w") as f:
            json.dump(events, f, indent=2)

    store = Store(db_path)
    try:
        capture.replay(store, events)
        summary = {
            "endpoints": len(store.endpoints()),
            "pages": len(store.pages()),
            "events": len(events),
            "db": db_path,
        }
    finally:
        store.close()
    return summary
