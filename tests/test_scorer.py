"""Unit tests for the solve-banner scorer — fixture-backed, no browser."""

from pathlib import Path

import pytest

from secagent.scorer import classify_status, read_status
from secagent.status import INDETERMINATE, NOT_SOLVED, SCORER_ERROR, SOLVED

FIXTURES = Path(__file__).parent / "fixtures"


def _html(name: str) -> str:
    return (FIXTURES / name).read_text()


# ------------------------------------------------------------ selector classify
def test_solved_banner():
    assert classify_status(_html("lab_banner_solved.html")) == SOLVED


def test_notsolved_banner():
    assert classify_status(_html("lab_banner_notsolved.html")) == NOT_SOLVED


def test_substring_decoy_does_not_false_positive():
    # "Solved" appears in a <script> and an aria-label, but the widget modifier is
    # is-notsolved — selector-level detection must report not_solved.
    html = _html("lab_banner_notsolved.html")
    assert "Solved" in html  # decoy really is present
    assert classify_status(html) == NOT_SOLVED


def test_missing_widget_is_indeterminate():
    assert classify_status(_html("lab_banner_missing.html")) == INDETERMINATE


@pytest.mark.parametrize("html", [None, "", "<html></html>", "not html at all"])
def test_empty_or_junk_is_indeterminate(html):
    assert classify_status(html) == INDETERMINATE


def test_unknown_modifier_is_indeterminate():
    html = '<div class="widgetcontainer-lab-status is-something-new"><p>?</p></div>'
    assert classify_status(html) == INDETERMINATE


def test_first_widget_wins():
    html = (
        '<div class="widgetcontainer-lab-status is-notsolved"></div>'
        '<div class="widgetcontainer-lab-status is-solved"></div>'
    )
    assert classify_status(html) == NOT_SOLVED


# ------------------------------------------------------------ read_status wrapper
def test_read_status_classifies():
    status, reason = read_status(lambda: _html("lab_banner_solved.html"))
    assert status == SOLVED
    assert reason is None


def test_read_status_provider_throws_is_scorer_error():
    def boom():
        raise TimeoutError("page closed")

    status, reason = read_status(boom)
    assert status == SCORER_ERROR
    assert "TimeoutError" in reason
    assert "page closed" in reason
