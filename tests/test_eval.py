"""Tests for the goal-only hypothesize eval — deterministic, no live model."""

import pytest

from evals.hypothesize_eval import (
    CASES,
    action_matches,
    normalize_class,
    run_class_eval,
    run_eval,
)


# ----------------------------------------------------------------- detectors
def test_sqli_payload_hits():
    assert action_matches({"tool": "fill", "selector": "#u", "value": "' OR 1=1--"}, "sqli")
    assert action_matches({"tool": "http", "url": "/filter?category=Gifts' UNION SELECT"}, "sqli")


def test_benign_action_misses_sqli():
    assert action_matches({"tool": "read_dom"}, "sqli") is False
    assert action_matches({"tool": "fill", "selector": "#u", "value": "alice"}, "sqli") is False


def test_access_control_path_hits():
    assert action_matches({"tool": "goto", "url": "https://lab/admin"}, "access-control")
    assert action_matches({"tool": "http", "method": "POST", "url": "/admin/delete?username=carlos"},
                          "access-control")


def test_access_control_benign_misses():
    assert action_matches({"tool": "goto", "url": "https://lab/catalog"}, "access-control") is False


def test_unknown_class_never_matches():
    assert action_matches({"tool": "goto", "url": "/admin"}, "made-up-class") is False


# ----------------------------------------------------------------- run_eval
def _smart_proposer(context):
    # A proposer that aims correctly per goal — should pass all cases.
    goal = context["goal"].lower()
    if "delete" in goal or "carlos" in goal:
        return {"tool": "goto", "url": context["base_url"] + "/admin"}
    return {"tool": "fill", "selector": "input[name=username]", "value": "administrator'--"}


def _dumb_proposer(context):
    return {"tool": "read_dom"}  # never aims at anything


def test_run_eval_all_pass_with_smart_proposer():
    report = run_eval(_smart_proposer)
    assert report["passed"] == report["total"] == len(CASES)


def test_run_eval_fails_with_dumb_proposer():
    report = run_eval(_dumb_proposer)
    assert report["passed"] == 0
    assert report["total"] == len(CASES)


# ----------------------------------------------------- classification eval
@pytest.mark.parametrize(
    "reply,expected",
    [
        ("sqli", "sqli"),
        ("SQLi", "sqli"),
        ("This is SQL injection", "sqli"),
        ("access-control", "access-control"),
        ("broken access control / authorization", "access-control"),
        ("xss", "xss"),
        ("complete nonsense", "other"),
    ],
)
def test_normalize_class(reply, expected):
    assert normalize_class(reply) == expected


def _good_classifier(goal):
    g = goal.lower()
    if "delete" in g or "carlos" in g:
        return "access-control"
    return "sqli"  # both sqli cases


def _bad_classifier(goal):
    return "xss"  # always wrong for these cases


def test_run_class_eval_all_pass():
    report = run_class_eval(_good_classifier)
    assert report["passed"] == report["total"] == len(CASES)


def test_run_class_eval_all_fail():
    report = run_class_eval(_bad_classifier)
    assert report["passed"] == 0
