"""Unit tests for the hunt loop — drives the REAL sync LangGraph with fakes."""

import json

import pytest

from secagent.allowlist import TargetNotAllowed
from secagent.hunter import AnthropicHunter, _parse_action, run_hunt, validate_action
from secagent.session import Observation
from secagent.status import (
    AUTH_EXPIRED,
    BLOCKED_BY_SCOPE,
    BUDGET_EXHAUSTED,
    INVALID_ACTION,
    LAB_EXPIRED,
    NOT_SOLVED,
    RATE_LIMITED,
    SOLVED,
    TOOL_ERROR,
)
from secagent.store import Store

LAB = "https://0a1b.web-security-academy.net"
GOAL = "Log in as administrator"


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


class FakeLLM:
    def __init__(self, actions):
        self._actions = list(actions)
        self._i = 0
        self.contexts = []

    def propose(self, context):
        self.contexts.append(context)
        a = self._actions[min(self._i, len(self._actions) - 1)]
        self._i += 1
        return a


class FakeSession:
    """Returns a configurable status; can raise TargetNotAllowed for a given tool."""

    def __init__(self, status=200, raise_on=None):
        self.status = status
        self.raise_on = raise_on
        self.calls = []

    def _maybe_raise(self, tool):
        if self.raise_on == tool:
            raise TargetNotAllowed("off-scope")

    def goto(self, url):
        self.calls.append(("goto", url))
        self._maybe_raise("goto")
        return Observation("goto", True, url=url, status=self.status)

    def click(self, selector):
        self.calls.append(("click", selector))
        self._maybe_raise("click")
        return Observation("click", True, url=LAB, status=self.status)

    def fill(self, selector, value):
        self.calls.append(("fill", selector))
        return Observation("fill", True, status=None)

    def submit(self, selector):
        self.calls.append(("submit", selector))
        self._maybe_raise("submit")
        return Observation("submit", True, url=LAB, status=self.status)

    def read_dom(self):
        self.calls.append(("read_dom", None))
        return Observation("read_dom", True, text="dom", status=None)

    def http(self, method, url, headers=None, body=None):
        self.calls.append(("http", url))
        self._maybe_raise("http")
        return Observation("http", True, url=url, status=self.status, text="resp")


def _scorer(*statuses):
    it = iter(statuses)
    last = statuses[-1]

    def read():
        nonlocal last
        try:
            last = next(it)
        except StopIteration:
            pass
        return (last, None)

    return read


def _run(store, llm, session, scorer, **kw):
    base = dict(
        session=session, scorer_read=scorer, llm=llm, store=store,
        lab_id="sqli-login-bypass", base_url=LAB, goal=GOAL,
        clock=lambda: 0.0, sleeper=lambda s: None,
    )
    base.update(kw)
    return run_hunt(**base)


# ----------------------------------------------------------------- happy path
def test_scripted_solve():
    store = Store(":memory:")
    llm = FakeLLM([
        {"tool": "fill", "selector": "#u", "value": "x' OR 1=1--"},
        {"tool": "submit", "selector": "#u"},
    ])
    final = _run(store, llm, FakeSession(), _scorer(NOT_SOLVED, SOLVED))
    assert final["status"] == SOLVED
    assert store.run(1)["status"] == SOLVED
    # steps recorded: hypothesize+act+score for 2 steps = 6 step rows (idempotent idx reuse)
    assert len(store.steps(1)) >= 2
    store.close()


def test_input_bundle_has_goal_not_lab_title(store):
    # R10 / P2b: the recorded model input is goal + base_url + history only — never a
    # lab title or slug. This row is the leakage proof.
    llm = FakeLLM([{"tool": "read_dom"}])
    _run(store, llm, FakeSession(), _scorer(SOLVED))
    hyp = [s for s in store.steps(1) if s["node"] == "hypothesize"][0]
    bundle = json.loads(hyp["input_bundle"])
    assert bundle["goal"] == GOAL
    assert bundle["base_url"] == LAB
    assert "title" not in bundle and "slug" not in bundle


# ----------------------------------------------------------------- terminals
def test_budget_exhausted_by_steps(store):
    llm = FakeLLM([{"tool": "read_dom"}])  # never solves
    final = _run(store, llm, FakeSession(), _scorer(NOT_SOLVED), max_steps=3)
    assert final["status"] == BUDGET_EXHAUSTED
    assert "step budget" in store.run(1)["note"]


def test_budget_exhausted_by_requests(store):
    llm = FakeLLM([{"tool": "http", "method": "GET", "url": LAB + "/x"}])
    final = _run(store, llm, FakeSession(), _scorer(NOT_SOLVED), max_steps=20, max_requests=2)
    assert final["status"] == BUDGET_EXHAUSTED
    assert "request budget" in store.run(1)["note"]


def test_budget_exhausted_by_time(store):
    ticks = iter([0.0, 0.0, 99.0])  # t0=0, then decide sees 99s elapsed

    def clock():
        try:
            return next(ticks)
        except StopIteration:
            return 99.0

    llm = FakeLLM([{"tool": "read_dom"}])
    final = _run(store, llm, FakeSession(), _scorer(NOT_SOLVED),
                 max_steps=20, max_seconds=10.0, clock=clock)
    assert final["status"] == BUDGET_EXHAUSTED
    assert "time budget" in store.run(1)["note"]


def test_invalid_action(store):
    llm = FakeLLM([{"tool": "frobnicate", "target": "everything"}])
    final = _run(store, llm, FakeSession(), _scorer(NOT_SOLVED))
    assert final["status"] == INVALID_ACTION
    assert "frobnicate" in store.run(1)["note"]


def test_give_up_is_not_solved(store):
    llm = FakeLLM([{"tool": "give_up"}])
    final = _run(store, llm, FakeSession(), _scorer(NOT_SOLVED))
    assert final["status"] == NOT_SOLVED
    assert "gave up" in store.run(1)["note"]


def test_rate_limited(store):
    llm = FakeLLM([{"tool": "http", "method": "GET", "url": LAB + "/x"}])
    final = _run(store, llm, FakeSession(status=429), _scorer(NOT_SOLVED))
    assert final["status"] == RATE_LIMITED


def test_forbidden_is_not_terminal(store):
    # 403 is a normal payload rejection in hunting — the agent must keep going,
    # not abort. The run ends on budget, not rate_limited.
    llm = FakeLLM([{"tool": "http", "method": "GET", "url": LAB + "/x"}])
    final = _run(store, llm, FakeSession(status=403), _scorer(NOT_SOLVED), max_steps=3)
    assert final["status"] == BUDGET_EXHAUSTED
    assert final["status"] != RATE_LIMITED
    # the 403 observation is recorded so the model can adapt to it
    acts = [s for s in store.steps(1) if s["node"] == "act"]
    assert any('"status": 403' in (a["observation"] or "") for a in acts)


@pytest.mark.parametrize("code", [502, 503, 504])
def test_lab_expired_on_5xx(store, code):
    # a downed/expired lab (gateway errors) ends the run fast, not 12 wasted steps
    llm = FakeLLM([{"tool": "goto", "url": LAB + "/"}])
    final = _run(store, llm, FakeSession(status=code), _scorer("indeterminate"))
    assert final["status"] == LAB_EXPIRED


def test_auth_expired_no_relogin(store):
    llm = FakeLLM([{"tool": "http", "method": "GET", "url": LAB + "/me"}])
    final = _run(store, llm, FakeSession(status=401), _scorer(NOT_SOLVED))
    assert final["status"] == AUTH_EXPIRED


def test_blocked_by_scope(store):
    llm = FakeLLM([{"tool": "http", "method": "GET", "url": LAB + "/x"}])
    final = _run(store, llm, FakeSession(raise_on="http"), _scorer(NOT_SOLVED))
    assert final["status"] == BLOCKED_BY_SCOPE


class _RaisingLLM:
    def propose(self, context):
        raise RuntimeError("anthropic transport boom")


def test_llm_transport_error_is_tool_error_not_invalid_action(store):
    # A transport/auth failure must record tool_error (and re-raise), NOT masquerade
    # as the model emitting a bad action (invalid_action). Codex #6.
    with pytest.raises(RuntimeError):
        _run(store, _RaisingLLM(), FakeSession(), _scorer(NOT_SOLVED))
    assert store.run(1)["status"] == TOOL_ERROR
    assert "transport boom" in store.run(1)["note"]


def test_terminal_returns_record_a_step(store):
    # budget-exhausted on the very first network action still leaves an act-row.
    llm = FakeLLM([{"tool": "http", "method": "GET", "url": LAB + "/x"}])
    _run(store, llm, FakeSession(), _scorer(NOT_SOLVED), max_steps=20, max_requests=0)
    acts = [s for s in store.steps(1) if s["node"] == "act"]
    assert acts and "budget" in (acts[-1]["observation"] or "")


# ----------------------------------------------------------------- validation unit
@pytest.mark.parametrize(
    "text,expected_tool",
    [
        ('{"tool":"read_dom"}', "read_dom"),
        ('here you go: {"tool":"goto","url":"/x"} ', "goto"),
        ('```json\n{"tool":"http","method":"GET","url":"/a"}\n```', "http"),
        ("no json here", "__unparseable__"),
    ],
)
def test_parse_action(text, expected_tool):
    assert _parse_action(text)["tool"] == expected_tool


class _Block:
    def __init__(self, text):
        self.text = text


class _FakeMsgs:
    def __init__(self, replies):
        self._replies = list(replies)
        self._i = 0

    def create(self, **kw):
        r = self._replies[min(self._i, len(self._replies) - 1)]
        self._i += 1
        if isinstance(r, Exception):
            raise r

        class _Resp:
            content = [_Block(r)]

        return _Resp()


class _FakeAnthropic:
    def __init__(self, replies):
        self.messages = _FakeMsgs(replies)


def test_anthropic_hunter_parses_action():
    h = AnthropicHunter("claude-x", client=_FakeAnthropic(['{"tool":"read_dom"}']))
    assert h.propose({"base_url": LAB, "goal": GOAL, "history": []}) == {"tool": "read_dom"}


def test_anthropic_hunter_retries_then_gives_unparseable():
    # first reply is junk → retry → still junk → unparseable (→ invalid_action upstream)
    h = AnthropicHunter("claude-x", client=_FakeAnthropic(["nope", "still nope"]))
    assert h.propose({"base_url": LAB, "goal": GOAL, "history": []})["tool"] == "__unparseable__"


def test_anthropic_hunter_retries_unparseable_then_succeeds():
    # junk reply → retry → valid action returned (the retry-on-unparseable fix, Codex #6)
    h = AnthropicHunter("claude-x", client=_FakeAnthropic(["nope", '{"tool":"read_dom"}']))
    assert h.propose({"base_url": LAB, "goal": GOAL, "history": []}) == {"tool": "read_dom"}


def test_anthropic_hunter_raises_on_transport_failure():
    # every attempt is an exception (never reached the model) → raise, not __unparseable__
    h = AnthropicHunter("claude-x", client=_FakeAnthropic([RuntimeError("net"), RuntimeError("net")]))
    with pytest.raises(RuntimeError):
        h.propose({"base_url": LAB, "goal": GOAL, "history": []})


@pytest.mark.parametrize(
    "action,ok",
    [
        ({"tool": "goto", "url": "x"}, True),
        ({"tool": "http", "method": "GET", "url": "x"}, True),
        ({"tool": "read_dom"}, True),
        ({"tool": "give_up"}, True),
        ({"tool": "goto"}, False),            # missing url
        ({"tool": "fill", "selector": "#u"}, False),  # missing value
        ({"tool": "nope"}, False),
        ("not a dict", False),
    ],
)
def test_validate_action(action, ok):
    assert validate_action(action)[0] is ok
