"""
SQLite store — the attack-surface map (the core v1 artifact).

The schema enforces the dedupe and exemplar rules so the Python stays dumb:

    endpoints                         pages
    ─────────                         ─────
    id                                id
    signature  UNIQUE  ◀── dedupe     page_key  UNIQUE = "<route>|<auth>"  ◀── identity
    method                            route
    path                              auth_state   ('anon' | 'authed')
    param_names                       title
    first_seen                        summary / summary_status / summary_input (auditable)
        ▲                             first_seen
        │                                 ▲
        │ endpoint_exemplars              │
        │ ─────────────────               │  page_endpoints (link)
        │ endpoint_id ───────┘            │  ─────────────────
        │ slot  ('primary'|'secondary')   └─ page_id  ─┐
        │ UNIQUE(endpoint_id, slot)          endpoint_id ┘
        │ status / response_body / response_reason / ...
        │
        └─ Exemplar policy: first NON-error fills 'primary', first error fills
           'secondary'. UNIQUE(endpoint_id, slot) + INSERT OR IGNORE means the
           first of each class wins and later ones are ignored — no app logic.

Locked decisions encoded here (eng review 2026-06-20):
  - Page identity = normalized route + auth state (modal/item granularity is v2)
  - one primary + one secondary exemplar per endpoint
  - response_body may be NULL with a response_reason (capture Finding 3)
  - summary_input stored verbatim so a bad page summary can be regenerated
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .status import TERMINAL_STATUSES

_SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    id          INTEGER PRIMARY KEY,
    signature   TEXT NOT NULL UNIQUE,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    param_names TEXT NOT NULL,
    first_seen  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoint_exemplars (
    id                   INTEGER PRIMARY KEY,
    endpoint_id          INTEGER NOT NULL REFERENCES endpoints(id),
    slot                 TEXT NOT NULL CHECK (slot IN ('primary', 'secondary')),
    url                  TEXT NOT NULL,
    status               INTEGER,
    resource_type        TEXT,
    auth_state           TEXT,
    request_content_type TEXT,
    request_body         TEXT,
    response_body        TEXT,
    response_reason      TEXT,
    captured_at          TEXT NOT NULL,
    UNIQUE (endpoint_id, slot)
);

CREATE TABLE IF NOT EXISTS pages (
    id             INTEGER PRIMARY KEY,
    page_key       TEXT NOT NULL UNIQUE,
    route          TEXT NOT NULL,
    auth_state     TEXT NOT NULL,
    title          TEXT,
    summary        TEXT,
    summary_status TEXT,
    summary_input  TEXT,
    first_seen     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS page_endpoints (
    page_id     INTEGER NOT NULL REFERENCES pages(id),
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    PRIMARY KEY (page_id, endpoint_id)
);

-- v2 hunt trace (the measurement deliverable). A run is one hunt of one lab
-- instance; steps are its hypothesize/act/observe/score/decide trace.
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY,
    lab_id      TEXT NOT NULL,          -- stable lab label, e.g. 'sqli-login-bypass'
    base_url    TEXT NOT NULL,          -- the per-instance URL
    goal        TEXT NOT NULL,          -- goal-only input fed to the agent
    status      TEXT,                   -- terminal status; NULL while running / crashed
    note        TEXT,                   -- terminal reason (e.g. scorer_error detail)
    launched_at TEXT,                   -- lab instance launch time (lifecycle, R9)
    last_seen   TEXT,                   -- last time the instance answered (R9)
    started_at  TEXT NOT NULL,
    ended_at    TEXT
);

CREATE TABLE IF NOT EXISTS steps (
    id           INTEGER PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES runs(id),
    idx          INTEGER NOT NULL,      -- step number within the run
    node         TEXT NOT NULL,         -- hypothesize | act | observe | score | decide
    action       TEXT,                  -- JSON of the action taken (or NULL)
    observation  TEXT,                  -- observation text/JSON (or NULL)
    input_bundle TEXT,                  -- R10: exact model input shown this step (verbatim)
    score        TEXT,                  -- per-step banner read (or NULL)
    created_at   TEXT NOT NULL,
    UNIQUE (run_id, idx)                -- idempotent step writes (crash-safe, R8)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def page_key(route: str, auth_state: str) -> str:
    """Page identity = normalized route + auth state."""
    return f"{route}|{auth_state}"


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ----------------------------------------------------------------- endpoints
    def record_request(
        self,
        *,
        signature: str,
        method: str,
        path: str,
        param_names: str,
        url: str,
        status: int | None = None,
        resource_type: str | None = None,
        auth_state: str | None = None,
        request_content_type: str | None = None,
        request_body: str | None = None,
        response_body: str | None = None,
        response_reason: str | None = None,
        now: str | None = None,
    ) -> int:
        """
        Record one captured request. Dedupes the endpoint by signature and stores
        at most one primary (first non-error) and one secondary (first error)
        exemplar. Returns the endpoint id.
        """
        ts = now or _now()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO endpoints(signature, method, path, param_names, first_seen)"
            " VALUES (?, ?, ?, ?, ?)",
            (signature, method.upper(), path, param_names, ts),
        )
        endpoint_id = cur.execute(
            "SELECT id FROM endpoints WHERE signature = ?", (signature,)
        ).fetchone()[0]

        slot = "secondary" if (status is not None and status >= 400) else "primary"
        cur.execute(
            "INSERT OR IGNORE INTO endpoint_exemplars"
            "(endpoint_id, slot, url, status, resource_type, auth_state,"
            " request_content_type, request_body, response_body, response_reason, captured_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                endpoint_id, slot, url, status, resource_type, auth_state,
                request_content_type, request_body, response_body, response_reason, ts,
            ),
        )
        self.conn.commit()
        return endpoint_id

    # --------------------------------------------------------------------- pages
    def upsert_page(
        self,
        *,
        route: str,
        auth_state: str,
        title: str | None = None,
        now: str | None = None,
    ) -> int:
        """Dedupe a page by (route, auth_state). Returns the page id."""
        ts = now or _now()
        key = page_key(route, auth_state)
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO pages(page_key, route, auth_state, title, first_seen)"
            " VALUES (?, ?, ?, ?, ?)",
            (key, route, auth_state, title, ts),
        )
        self.conn.commit()
        return cur.execute("SELECT id FROM pages WHERE page_key = ?", (key,)).fetchone()[0]

    def set_page_summary(
        self,
        page_id: int,
        *,
        summary: str | None,
        summary_input: str | None,
        status: str = "ok",
    ) -> None:
        """Attach the page-understanding result. status='missing' when the LLM failed."""
        self.conn.execute(
            "UPDATE pages SET summary = ?, summary_input = ?, summary_status = ? WHERE id = ?",
            (summary, summary_input, status, page_id),
        )
        self.conn.commit()

    def link(self, page_id: int, endpoint_id: int) -> None:
        """Link an endpoint to the page that triggered it (idempotent)."""
        self.conn.execute(
            "INSERT OR IGNORE INTO page_endpoints(page_id, endpoint_id) VALUES (?, ?)",
            (page_id, endpoint_id),
        )
        self.conn.commit()

    # ------------------------------------------------------------------- readers
    def endpoints(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM endpoints ORDER BY method, path"
        ).fetchall()

    def exemplars(self, endpoint_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM endpoint_exemplars WHERE endpoint_id = ? ORDER BY slot",
            (endpoint_id,),
        ).fetchall()

    def pages(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM pages ORDER BY page_key").fetchall()

    def endpoints_for_page(self, page_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT e.* FROM endpoints e"
            " JOIN page_endpoints pe ON pe.endpoint_id = e.id"
            " WHERE pe.page_id = ? ORDER BY e.method, e.path",
            (page_id,),
        ).fetchall()

    # ------------------------------------------------------------- hunt runs (v2)
    def start_run(
        self,
        *,
        lab_id: str,
        base_url: str,
        goal: str,
        launched_at: str | None = None,
        now: str | None = None,
    ) -> int:
        """Open a hunt run (status NULL = in-progress). Returns the run id."""
        ts = now or _now()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO runs(lab_id, base_url, goal, launched_at, last_seen, started_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (lab_id, base_url, goal, launched_at, launched_at, ts),
        )
        self.conn.commit()
        return cur.lastrowid

    def touch_run(self, run_id: int, now: str | None = None) -> None:
        """Mark the lab instance as still alive (lifecycle, R9)."""
        self.conn.execute(
            "UPDATE runs SET last_seen = ? WHERE id = ?", (now or _now(), run_id)
        )
        self.conn.commit()

    def record_step(
        self,
        run_id: int,
        idx: int,
        node: str,
        *,
        action: str | None = None,
        observation: str | None = None,
        input_bundle: str | None = None,
        score: str | None = None,
        now: str | None = None,
    ) -> int:
        """
        Write one step. Idempotent on (run_id, idx): re-writing the same step (e.g.
        on a crash-resume) updates in place instead of duplicating (R8). Returns the
        step id.
        """
        ts = now or _now()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO steps(run_id, idx, node, action, observation, input_bundle,"
            " score, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(run_id, idx) DO UPDATE SET"
            " node=excluded.node, action=excluded.action, observation=excluded.observation,"
            " input_bundle=excluded.input_bundle, score=excluded.score",
            (run_id, idx, node, action, observation, input_bundle, score, ts),
        )
        self.conn.commit()
        return cur.execute(
            "SELECT id FROM steps WHERE run_id = ? AND idx = ?", (run_id, idx)
        ).fetchone()[0]

    def finish_run(
        self, run_id: int, status: str, *, note: str | None = None, now: str | None = None
    ) -> None:
        """Close a run with a terminal status. Rejects unknown statuses so a typo
        can't silently produce an unmeasurable run."""
        if status not in TERMINAL_STATUSES:
            raise ValueError(f"{status!r} is not a terminal status")
        self.conn.execute(
            "UPDATE runs SET status = ?, note = ?, ended_at = ? WHERE id = ?",
            (status, note, now or _now(), run_id),
        )
        self.conn.commit()

    def finalize_unfinished(
        self, status: str, *, note: str = "process exited before finishing", now: str | None = None
    ) -> int:
        """
        Crash recovery (R8): any run still status NULL (process was killed mid-run)
        gets a terminal status so it never lingers as an unmeasurable ghost. Returns
        how many runs were finalized. Call at startup before a new hunt.
        """
        if status not in TERMINAL_STATUSES:
            raise ValueError(f"{status!r} is not a terminal status")
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE runs SET status = ?, note = ?, ended_at = ? WHERE status IS NULL",
            (status, note, now or _now()),
        )
        self.conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------- hunt readers
    def runs(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM runs ORDER BY id").fetchall()

    def run(self, run_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()

    def steps(self, run_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM steps WHERE run_id = ? ORDER BY idx", (run_id,)
        ).fetchall()
