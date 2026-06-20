"""
Solve-banner scorer — the answer key (T2).

PortSwigger labs render a status widget whose modifier class is the ground truth:

    <div class="widgetcontainer-lab-status is-notsolved"> ... </div>   ← not solved
    <div class="widgetcontainer-lab-status is-solved">    ... </div>   ← solved

We classify on that SELECTOR (the widget element's class list), not on a substring
search for the word "Solved" — because "Solved" also appears in nav, scripts, help
text, and accessibility labels, and a substring match would lie (Codex R3).

    page/lab html ──▶ HTMLParser finds .widgetcontainer-lab-status
                            │
              has is-solved ┤──▶ "solved"
           has is-notsolved ┤──▶ "not_solved"
            widget missing / ┘──▶ "indeterminate"  (NOT terminal — one inconclusive
            unknown modifier         read; the loop reads again next step)

Isolation (R1): the scorer never touches the hunter's active page. It works off HTML
captured separately — `read_status` takes a zero-arg provider (e.g. a dedicated
scorer page's `.content`), so a banner read can't perturb the run's state. A provider
that throws becomes the terminal `scorer_error`, never an uncaught exception that
kills the loop (CQ2).
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Callable

from .status import INDETERMINATE, NOT_SOLVED, SCORER_ERROR, SOLVED

_STATUS_CLASS = "widgetcontainer-lab-status"
_SOLVED_CLASS = "is-solved"
_NOTSOLVED_CLASS = "is-notsolved"


class _LabStatusFinder(HTMLParser):
    """Capture the class list of the first lab-status widget element."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.classes: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.classes is not None:
            return
        cls = (dict(attrs).get("class") or "").split()
        if _STATUS_CLASS in cls:
            self.classes = cls


def classify_status(html: str | None) -> str:
    """
    Map lab page HTML to 'solved' / 'not_solved' / 'indeterminate' via the status
    widget's modifier class. 'indeterminate' means inconclusive (widget absent or an
    unrecognized modifier) — it is NOT a terminal failure.
    """
    if not html:
        return INDETERMINATE
    finder = _LabStatusFinder()
    try:
        finder.feed(html)
    except Exception:
        return INDETERMINATE
    cls = finder.classes
    if cls is None:
        return INDETERMINATE
    if _SOLVED_CLASS in cls:
        return SOLVED
    if _NOTSOLVED_CLASS in cls:
        return NOT_SOLVED
    return INDETERMINATE


def read_status(html_provider: Callable[[], str | None]) -> tuple[str, str | None]:
    """
    Read + classify the banner from an isolated HTML source. Returns (status, reason).
    A provider that raises yields ('scorer_error', '<Type>: <msg>') so a flaky banner
    read terminates the run cleanly instead of crashing it.
    """
    try:
        html = html_provider()
    except Exception as e:  # noqa: BLE001 — any provider failure is a scorer_error
        return SCORER_ERROR, f"{type(e).__name__}: {e}"
    return classify_status(html), None
