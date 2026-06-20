"""Unit tests for BrowserSession — fake page/request, no real browser."""

import pytest

from secagent.allowlist import TargetNotAllowed
from secagent.session import BrowserSession, Observation

LAB = "https://0a1b.web-security-academy.net"


class FakeResp:
    def __init__(self, status=200, url=None, body="<html>ok</html>"):
        self.status = status
        self.url = url
        self._body = body

    def text(self):
        return self._body


class FakePage:
    """Minimal Playwright-page stand-in. `redirect_to` simulates a nav landing
    somewhere other than the requested URL (a 30x or client redirect)."""

    def __init__(self, url=LAB, redirect_to=None, fail_selectors=()):
        self.url = url
        self._redirect_to = redirect_to
        self._fail = set(fail_selectors)
        self.dom = "body text here"
        self.html = "<html><body>body text here</body></html>"

    def goto(self, url, wait_until=None):
        self.url = self._redirect_to or url
        return FakeResp(status=200, url=self.url)

    def click(self, selector):
        if selector in self._fail:
            raise RuntimeError("no element matches selector")
        if self._redirect_to:
            self.url = self._redirect_to

    def fill(self, selector, value):
        if selector in self._fail:
            raise RuntimeError("no element matches selector")
        if self._redirect_to:  # page JS can navigate on input
            self.url = self._redirect_to

    def press(self, selector, key):
        if selector in self._fail:
            raise RuntimeError("no element matches selector")
        if self._redirect_to:
            self.url = self._redirect_to

    def inner_text(self, sel):
        return self.dom

    def content(self):
        return self.html


class FakeRequest:
    def __init__(self, resp=None, raises=None):
        self._resp = resp or FakeResp(status=200, url=LAB + "/api")
        self._raises = raises
        self.calls = []

    def fetch(self, url, method=None, headers=None, data=None, max_redirects=None):
        self.calls.append((method, url, data))
        self.last_max_redirects = max_redirects
        if self._raises:
            raise self._raises
        return self._resp


def _session(page=None, req=None):
    return BrowserSession(page or FakePage(), req or FakeRequest())


# --------------------------------------------------------------------- goto
def test_goto_allowed_returns_observation():
    obs = _session().goto(LAB + "/login")
    assert isinstance(obs, Observation)
    assert obs.ok and obs.action == "goto"
    assert obs.url == LAB + "/login"


def test_goto_offscope_raises_before_navigating():
    page = FakePage()
    with pytest.raises(TargetNotAllowed):
        _session(page).goto("https://evil.com/")


def test_goto_relative_path_resolves_to_base():
    # The model is allowed to emit path URLs like "/login"; they must resolve against
    # the current page (lab origin), not become http:///login → wrongly blocked.
    page = FakePage(url=LAB)
    obs = _session(page).goto("/login")
    assert obs.ok
    assert obs.url == LAB + "/login"


def test_first_relative_goto_resolves_against_base_url_not_about_blank():
    # Fresh page is at about:blank; the first "/" must resolve to base_url (the lab),
    # not to a hostless about:blank-relative URL.
    page = FakePage(url="about:blank")
    sess = BrowserSession(page, FakeRequest(), base_url=LAB)
    obs = sess.goto("/")
    assert obs.ok
    assert obs.url == LAB + "/"


def test_goto_scheme_relative_offscope_refused():
    # "//evil.com/x" resolves to the base scheme + evil.com, then fails the host check.
    with pytest.raises(TargetNotAllowed):
        _session(FakePage(url=LAB)).goto("//evil.com/x")


@pytest.mark.parametrize(
    "url",
    [
        "file://localhost/etc/passwd",
        "javascript://localhost/%0aalert(1)",
        "ws://localhost:3000/socket",
        "ftp://localhost/x",
    ],
)
def test_nonweb_schemes_refused(url):
    with pytest.raises(TargetNotAllowed):
        _session(FakePage(url=LAB)).goto(url)


def test_goto_redirect_drift_offscope_raises():
    # nav requested an allowed url but landed off-scope → caught by the post-check.
    page = FakePage(redirect_to="https://evil.com/phish")
    with pytest.raises(TargetNotAllowed):
        _session(page).goto(LAB + "/redirect")


# --------------------------------------------------------------------- click/fill/submit
def test_click_follows_navigation():
    page = FakePage(redirect_to=LAB + "/admin")
    obs = _session(page).click("a.admin")
    assert obs.ok and obs.url == LAB + "/admin"


def test_click_missing_selector_is_soft_failure():
    page = FakePage(fail_selectors=("a.admin",))
    obs = _session(page).click("a.admin")
    assert obs.ok is False
    assert "no element" in obs.error


def test_click_redirect_offscope_raises():
    page = FakePage(redirect_to="https://evil.com/")
    with pytest.raises(TargetNotAllowed):
        _session(page).click("a.evil")


def test_fill_ok_and_failure():
    assert _session(FakePage()).fill("#user", "admin").ok is True
    bad = _session(FakePage(fail_selectors=("#user",))).fill("#user", "admin")
    assert bad.ok is False


def test_fill_redirect_offscope_raises():
    # fill triggers page JS that navigates off-scope → caught by the post-action check.
    page = FakePage(url=LAB, redirect_to="https://evil.com/")
    with pytest.raises(TargetNotAllowed):
        _session(page).fill("#user", "x")


def test_submit_presses_enter():
    page = FakePage(redirect_to=LAB + "/my-account")
    obs = _session(page).submit("#password")
    assert obs.ok and obs.url == LAB + "/my-account"


def test_read_dom_returns_text():
    obs = _session(FakePage()).read_dom()
    assert obs.ok and obs.text == "body text here"


# --------------------------------------------------------------------- http
def test_http_allowed_shares_context():
    req = FakeRequest(FakeResp(status=200, url=LAB + "/filter?cat=Gifts"))
    obs = _session(FakePage(), req).http("GET", LAB + "/filter?cat=Gifts")
    assert obs.ok and obs.status == 200
    assert req.calls == [("GET", LAB + "/filter?cat=Gifts", None)]


def test_http_does_not_autofollow_redirects():
    req = FakeRequest(FakeResp(status=302, url=LAB + "/x"))
    _session(FakePage(), req).http("GET", LAB + "/x")
    assert req.last_max_redirects == 0  # never auto-follow off-scope


def test_http_offscope_raises_before_fetch():
    req = FakeRequest()
    with pytest.raises(TargetNotAllowed):
        _session(FakePage(), req).http("GET", "https://evil.com/x")
    assert req.calls == []  # never fetched


def test_http_redirect_to_offscope_raises():
    # request followed a redirect to an off-scope final url.
    req = FakeRequest(FakeResp(status=200, url="https://evil.com/landing"))
    with pytest.raises(TargetNotAllowed):
        _session(FakePage(), req).http("GET", LAB + "/redirect")


def test_http_fetch_error_is_soft_failure():
    req = FakeRequest(raises=RuntimeError("connection reset"))
    obs = _session(FakePage(), req).http("POST", LAB + "/login", body="x=1")
    assert obs.ok is False
    assert "connection reset" in obs.error


def test_content_passthrough_for_scorer():
    assert "body text here" in _session(FakePage()).content()
