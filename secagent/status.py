"""
Terminal statuses for a hunt run — the single source of truth (DRY).

Every run ends in exactly one of these. Keeping them as distinct values (rather
than collapsing failures into one "indeterminate" bucket) is load-bearing for the
measurement: "the agent ran out of budget" and "the lab expired" and "the model
emitted a malformed action" are very different facts about a non-solve, and the
whole project is about telling them apart.

    solved          the lab banner flipped to solved (the only "win")
    not_solved      run ended, banner still not solved
    budget_exhausted hit the step / request / time cap
    auth_expired    session/auth was lost mid-run (NO silent re-login — see design T2)
    lab_expired     the lab instance went away / a new instance invalidated the run
    rate_limited    target returned 429/403/account-challenge; we backed off and stopped
    tool_error      an action primitive failed unrecoverably (browser crash, etc.)
    invalid_action  the model emitted an action that failed schema validation
    scorer_error    the solve-banner read itself threw / was unreadable
    blocked_by_scope the agent tried to act on a non-allowlisted host
"""

from __future__ import annotations

SOLVED = "solved"
NOT_SOLVED = "not_solved"
BUDGET_EXHAUSTED = "budget_exhausted"
AUTH_EXPIRED = "auth_expired"
LAB_EXPIRED = "lab_expired"
RATE_LIMITED = "rate_limited"
TOOL_ERROR = "tool_error"
INVALID_ACTION = "invalid_action"
SCORER_ERROR = "scorer_error"
BLOCKED_BY_SCOPE = "blocked_by_scope"

# Statuses the scorer alone can produce from a banner read.
SCORER_STATUSES = frozenset({SOLVED, NOT_SOLVED, SCORER_ERROR})

TERMINAL_STATUSES = frozenset(
    {
        SOLVED,
        NOT_SOLVED,
        BUDGET_EXHAUSTED,
        AUTH_EXPIRED,
        LAB_EXPIRED,
        RATE_LIMITED,
        TOOL_ERROR,
        INVALID_ACTION,
        SCORER_ERROR,
        BLOCKED_BY_SCOPE,
    }
)

# "indeterminate" is NOT terminal — it means a single banner read was inconclusive
# (widget missing / ambiguous). The loop keeps going; only a genuine read failure
# becomes the terminal SCORER_ERROR.
INDETERMINATE = "indeterminate"


def is_terminal(status: str) -> bool:
    return status in TERMINAL_STATUSES
