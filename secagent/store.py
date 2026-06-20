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
