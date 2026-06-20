"""
BrowserSession — the hunter's hands (T3).

v1's recon.run_session is browse-then-replay-at-end: open, drive, close, replay.
The hunter instead needs a LONG-LIVED context it drives one action at a time, with
an observation back after each. So we factor that out here.

    hunter ──▶ goto/click/fill/submit/read_dom/http ──▶ Observation
                       │                                     ▲
                       ├─ assert_allowed(url) BEFORE acting ─┤  (per-action, A2/R4)
                       └─ assert_allowed(final url) AFTER ───┘  (per-redirect hop)

Two enforcement points matter: we refuse to navigate/fetch a non-allowlisted URL
BEFORE acting, and we re-check the FINAL url AFTER (a click or a 30x can redirect
off-target). A scope violation raises TargetNotAllowed straight up so the hunter can
end the run as `blocked_by_scope` — it is NOT swallowed like an ordinary action
failure. Everything else (missing selector, nav timeout) is caught and returned as
an Observation(ok=False), so one bad action never crashes the loop.

HTTP goes through the SAME browser context via Playwright's APIRequestContext
(`context.request`), so the lab JWT/cookies are shared — no parallel cookie jar that
could desync auth (A4).

Injectable by design: `page` and `request_context` are passed in, so tests drive a
fake page with zero browser. `open_session()` builds the real Playwright pair.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

from .allowlist import WEB_SECURITY_ACADEMY_SUFFIX, TargetNotAllowed, assert_allowed, is_allowed
from .capture import cap_body


@dataclass
class Observation:
    """What the agent learns from one action. JSON-serializable for the step trace."""

    action: str
    ok: bool
    url: str | None = None
    status: int | None = None
    text: str | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


class BrowserSession:
    def __init__(
        self,
        page,
        request_context,
        *,
        base_url: str = "",
        extra_hosts: tuple[str, ...] = (),
        extra_suffixes: tuple[str, ...] = (WEB_SECURITY_ACADEMY_SUFFIX,),
    ) -> None:
        self._page = page
        self._req = request_context
        self._base_url = base_url
        self._extra_hosts = extra_hosts
        self._extra_suffixes = extra_suffixes

    # -------------------------------------------------------------- enforcement
    def _resolve(self, url: str) -> str:
        """Resolve a relative/path/scheme-relative URL to absolute against the current
        page (or base_url). The model's prompt allows path URLs like '/login', so
        '/login' must become the lab origin, not 'http:///login'. '//evil.com/x'
        resolves to the base scheme + evil.com and is then refused by the host check.

        The current page is only a usable base once it's on a real http(s) URL — on a
        fresh page it's 'about:blank', so the FIRST relative action must resolve against
        base_url, not about:blank."""
        cur = self.current_url()
        base = cur if (cur and cur.startswith(("http://", "https://"))) else self._base_url
        return urljoin(base, url) if base else url

    def _check(self, url: str) -> None:
        """Raise TargetNotAllowed if url is off-scope. Propagates (not swallowed)."""
        assert_allowed(url, self._extra_hosts, self._extra_suffixes)

    def _after(self) -> None:
        """Re-check the page url after an action — catches redirect drift."""
        try:
            final = self._page.url
        except Exception:
            return
        if final:
            self._check(final)

    # -------------------------------------------------------------- inspectors
    def current_url(self) -> str | None:
        try:
            return self._page.url
        except Exception:
            return None

    def content(self) -> str | None:
        """Full HTML — used by the scorer's isolated read provider."""
        return self._page.content()

    # ----------------------------------------------------------------- actions
    def goto(self, url: str) -> Observation:
        target = self._resolve(url)
        self._check(target)
        try:
            resp = self._page.goto(target, wait_until="domcontentloaded")
            self._after()
            status = getattr(resp, "status", None) if resp is not None else None
            return Observation("goto", True, url=self._page.url, status=_call(status))
        except TargetNotAllowed:
            raise
        except Exception as e:  # noqa: BLE001
            return Observation("goto", False, url=target, error=_err(e))

    def click(self, selector: str) -> Observation:
        try:
            self._page.click(selector)
            self._after()
            return Observation("click", True, url=self._page.url)
        except TargetNotAllowed:
            raise
        except Exception as e:  # noqa: BLE001
            return Observation("click", False, error=_err(e))

    def fill(self, selector: str, value: str) -> Observation:
        try:
            self._page.fill(selector, value)
            self._after()  # fill fires input/change; page JS can redirect off-scope
            return Observation("fill", True, url=self.current_url())
        except TargetNotAllowed:
            raise
        except Exception as e:  # noqa: BLE001
            return Observation("fill", False, error=_err(e))

    def submit(self, selector: str) -> Observation:
        """Submit the form owning `selector` by pressing Enter in it."""
        try:
            self._page.press(selector, "Enter")
            self._after()
            return Observation("submit", True, url=self._page.url)
        except TargetNotAllowed:
            raise
        except Exception as e:  # noqa: BLE001
            return Observation("submit", False, error=_err(e))

    def read_dom(self) -> Observation:
        try:
            text, _ = cap_body(self._page.inner_text("body"))
            return Observation("read_dom", True, url=self.current_url(), text=text)
        except Exception as e:  # noqa: BLE001
            return Observation("read_dom", False, error=_err(e))

    def http(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        body: str | None = None,
    ) -> Observation:
        target = self._resolve(url)
        self._check(target)
        try:
            # max_redirects=0: never auto-follow a redirect off-scope. A 3xx is handed
            # back to the agent, which must issue a fresh (pre-checked) request to follow.
            resp = self._req.fetch(
                target, method=method.upper(), headers=headers, data=body, max_redirects=0
            )
            final = getattr(resp, "url", target)
            self._check(final)  # defensive: confirm the response url is still in scope
            text, _ = cap_body(resp.text())
            return Observation("http", True, url=final, status=resp.status, text=text)
        except TargetNotAllowed:
            raise
        except Exception as e:  # noqa: BLE001
            return Observation("http", False, url=target, error=_err(e))


def _call(v):
    """Status may be a value or a zero-arg callable depending on the driver/fake."""
    return v() if callable(v) else v


def _err(e: Exception) -> str:
    return f"{type(e).__name__}: {e}"


@contextmanager
def open_session(
    target: str,
    *,
    extra_hosts: tuple[str, ...] = (),
    extra_suffixes: tuple[str, ...] = (WEB_SECURITY_ACADEMY_SUFFIX,),
    headless: bool = False,
):
    """
    Build a real Playwright BrowserSession for `target`. Refuses up front if the
    target is off-scope. Yields (session, scorer_page) — scorer_page is a SECOND page
    in the same context so the banner read never perturbs the hunter's active page
    (R1).
    """
    assert_allowed(target, extra_hosts, extra_suffixes)
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        # Disable HTTP/2: headless Chromium intermittently throws
        # ERR_HTTP2_PROTOCOL_ERROR against PortSwigger's HTTP/2 stack, AND request
        # interception (the guardrail below) would downgrade off HTTP/2 anyway. Forcing
        # HTTP/1.1 makes the lab reliable and lets the network gate run safely.
        browser = p.chromium.launch(headless=headless, args=["--disable-http2"])
        context = browser.new_context()

        # Network-layer guardrail (the teeth behind P2a): abort any request — top-level
        # nav, redirect hop, subresource, on EITHER page — whose host isn't allowlisted,
        # BEFORE it leaves the machine. The matcher is a predicate over off-scope URLs
        # only; with HTTP/2 already disabled, interception no longer breaks the lab.
        def _offscope(url: str) -> bool:
            return not is_allowed(url, extra_hosts, extra_suffixes)

        context.route(_offscope, lambda route: route.abort())

        page = context.new_page()
        scorer_page = context.new_page()  # isolated read surface (R1)
        session = BrowserSession(
            page, context.request, base_url=target,
            extra_hosts=extra_hosts, extra_suffixes=extra_suffixes,
        )
        try:
            yield session, scorer_page
        finally:
            try:
                browser.close()
            except Exception:
                pass
