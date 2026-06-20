"""
recon_v0.py — v0 proof of concept (throwaway).

Goal: prove the one risky capability the whole project rests on —
can we observe a live MANUAL browse of a target and collapse it into an
attack-surface list?

What it does, and nothing more:
  - launches a headed Chromium you drive by hand
  - listens to every request the browser makes (context-wide, all tabs)
  - drops static assets (images/css/fonts/etc) by resource type
  - dedupes the rest to `METHOD /path` (query string stripped)
  - on exit (Ctrl-C, or close the browser window) prints the sorted unique list

No database, no LLM, no schema, no screenshots. That is v1+.

Usage:
  python recon_v0.py                  # browse http://localhost:3000 manually
  python recon_v0.py http://localhost:3000
  python recon_v0.py --smoke          # auto-drive a few routes (verification only)
"""

import sys
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

DEFAULT_TARGET = "http://localhost:3000"

# Resource types that are pure asset noise — dropped from the capture.
# Everything else (document, xhr, fetch, other, websocket, eventsource, ...) is
# KEPT and labelled, because Playwright sometimes classifies real API calls as
# "other"/"document" — filtering those out at capture time loses real endpoints.
STATIC_TYPES = {"image", "stylesheet", "font", "media", "manifest", "texttrack", "script"}

# A few well-known Juice Shop API calls, used only by --smoke to sanity-check
# that capture is finding the real attack surface and not drowning in assets.
SMOKE_ROUTES = ["/#/", "/#/search", "/#/login", "/#/basket", "/#/score-board"]


def main() -> int:
    args = [a for a in sys.argv[1:]]
    smoke = "--smoke" in args
    args = [a for a in args if a != "--smoke"]
    target = args[0] if args else DEFAULT_TARGET

    # signature -> resource_type (one exemplar; v0 keeps the first seen)
    seen: dict[str, str] = {}

    def on_request(request) -> None:
        rtype = request.resource_type
        if rtype in STATIC_TYPES:
            return
        path = urlsplit(request.url).path or "/"
        sig = f"{request.method:6} {path}"
        seen.setdefault(sig, rtype)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=smoke)
        context = browser.new_context()
        context.on("request", on_request)  # context-wide: captures every tab
        page = context.new_page()
        page.goto(target, wait_until="domcontentloaded")

        if smoke:
            for route in SMOKE_ROUTES:
                try:
                    page.goto(target.rstrip("/") + route, wait_until="networkidle")
                    page.wait_for_timeout(800)
                except Exception:
                    pass
        else:
            print(f"\nBrowsing {target} — drive the app by hand.")
            print("Finish: press Ctrl-C here, or close the browser window.\n")
            try:
                page.wait_for_event("close", timeout=0)  # block until window closed
            except KeyboardInterrupt:
                pass
            except Exception:
                pass

        try:
            browser.close()
        except Exception:
            pass

    print_results(seen, target)
    return 0


def print_results(seen: dict[str, str], target: str) -> None:
    print(f"\n=== unique endpoints captured from {target} ===")
    if not seen:
        print("(nothing captured — did the browser reach the target?)")
        return
    for sig in sorted(seen):
        rtype = seen[sig]
        tag = "" if rtype in ("xhr", "fetch") else f"   [{rtype}]"
        print(f"{sig}{tag}")
    print(f"\n{len(seen)} unique endpoints.")


if __name__ == "__main__":
    raise SystemExit(main())
