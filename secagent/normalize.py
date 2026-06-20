"""
Request normalization — the core of the recon map.

Two requests are "the same endpoint" when they share a SIGNATURE. The signature
collapses hundreds of concrete requests into the ~dozens of real endpoints that
make up the attack surface.

    raw request                       signature
    ─────────────────────────────     ─────────────────────────────────────
    GET /api/Users/42?sort=name   ──┐
    GET /api/Users/99?sort=email  ──┼─▶ GET /api/Users/:id {sort}
    GET /api/Users/7?sort=name    ──┘

Pipeline:

    method ─┐
    url ────┼─▶ normalize_path(path) ──┐
            │     :id / :uuid / literal │
            │                           ├─▶ signature()  "GET /api/Users/:id {sort}"
    query ──┤                           │
    body  ──┴─▶ extract_param_names() ──┘
                 query keys + body keys (NAMES only, values ignored)

Design decisions locked in the eng review (2026-06-20):
  - values are always ignored for v1 (value-sensitivity is a deferred v2 TODO)
  - param names = query keys + top-level JSON body keys + form/multipart field names
  - nested JSON keys are out of scope (Juice Shop bodies are flat) but MUST NOT crash
  - only numeric segments -> :id, dashed-UUID or 32+ contiguous hex -> :uuid
    (an 8-char word like "deadbeef" stays literal on purpose)
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlsplit

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HEX32 = re.compile(r"^[0-9a-fA-F]{32,}$")
# `(?<![A-Za-z])` so we match the field `name="..."` but NOT `filename="..."`.
_MULTIPART_NAME = re.compile(r'(?<![A-Za-z])name="([^"]+)"')


def normalize_segment(segment: str) -> str:
    """Classify one path segment into :id, :uuid, or itself (literal)."""
    if _NUMERIC.match(segment):
        return ":id"
    if _UUID.match(segment) or _HEX32.match(segment):
        return ":uuid"
    return segment


def normalize_path(path: str) -> str:
    """
    Normalize a URL path so variable segments collapse.

      /api/Users/42            -> /api/Users/:id
      /api/Users/42/Reviews/7  -> /api/Users/:id/Reviews/:id
      /api/Users/              -> /api/Users      (trailing slash dropped)
      /                        -> /               (root preserved)

    Values are not decoded; a percent-encoded segment is treated literally.
    """
    if not path:
        return "/"
    # Split into segments, classify each non-empty one. Empty segments come from
    # leading/trailing/duplicate slashes and are dropped (so trailing "/" vanishes).
    parts = [normalize_segment(seg) for seg in path.split("/") if seg != ""]
    if not parts:
        return "/"
    return "/" + "/".join(parts)


def extract_param_names(
    query_string: str | None = None,
    body: str | bytes | None = None,
    content_type: str | None = None,
) -> set[str]:
    """
    Collect the NAME of every parameter a request carries. Values are ignored.

      query keys                       (?sort=name&page=2   -> {sort, page})
      + JSON body top-level keys        ({"email": "...", "password": "..."})
      + form / multipart field names

    Malformed bodies, non-dict JSON, and unknown content types yield no body
    params rather than raising.
    """
    names: set[str] = set()

    if query_string:
        names.update(parse_qs(query_string, keep_blank_values=True).keys())

    if body is None or content_type is None:
        return names

    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    ctype = content_type.split(";", 1)[0].strip().lower()

    if ctype == "application/json":
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return names
        if isinstance(parsed, dict):
            names.update(str(k) for k in parsed.keys())
        # non-dict JSON (list/scalar) contributes no named params — and does not crash
    elif ctype == "application/x-www-form-urlencoded":
        names.update(parse_qs(text, keep_blank_values=True).keys())
    elif ctype == "multipart/form-data":
        names.update(_MULTIPART_NAME.findall(text))

    return names


def signature(
    method: str,
    url: str,
    body: str | bytes | None = None,
    content_type: str | None = None,
) -> str:
    """
    Stable, order-independent endpoint signature:

        "<METHOD> <normalized-path> {<sorted,comma,param,names>}"
        "GET /api/Users/:id {page,sort}"

    Same endpoint hit with params in any order -> identical signature.
    """
    split = urlsplit(url)
    npath = normalize_path(split.path)
    names = extract_param_names(split.query, body, content_type)
    params = "{" + ",".join(sorted(names)) + "}"
    return f"{method.upper()} {npath} {params}"
