"""
Page understanding (T5) — DOM/a11y-first, vision optional.

We summarize a page from its captured text snapshot (the accessibility/visible
text), NOT a screenshot. Vision was deliberately made optional in the eng review:
prove DOM-only is inadequate before paying for vision.

    page.summary_input (stored at capture, status 'pending')
        │
        ▼
    summarize(text, client)  ── LLM ──▶ structured JSON {purpose, user_actions,
        │   retry once on failure                       input_fields, notable}
        ▼
    store.set_page_summary(..., status='ok')  OR  status='missing' (never dropped)

The LLM client is INJECTED — a callable `(prompt: str) -> str`. Tests pass a fake;
the real Anthropic client is built lazily (so the package imports without the key
or the anthropic SDK installed).
"""

from __future__ import annotations

import json
from typing import Callable

from .store import Store

Client = Callable[[str], str]

PROMPT = """You are mapping a web app's attack surface. Below is the visible text and
structure of one page. Summarize it as STRICT JSON with exactly these keys:
  "purpose": one sentence on what this page is for
  "user_actions": list of actions a user can take here
  "input_fields": list of input/form field names or labels you can see
  "notable": list of anything security-relevant (uploads, admin links, tokens, redirects)
Return ONLY the JSON object, no prose.

PAGE:
{page}
"""


def _parse_json(text: str) -> dict:
    """Parse model output as JSON, tolerating ```json fences."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```", 2)[1]
        if t.startswith("json"):
            t = t[4:]
        t = t.strip()
    parsed = json.loads(t)
    if not isinstance(parsed, dict):
        raise ValueError("expected a JSON object")
    return parsed


def summarize(text: str, client: Client, retries: int = 1) -> tuple[dict | None, str]:
    """
    Summarize one page's text. Returns (summary_dict, "ok") on success, or
    (None, "missing") after exhausting retries. Never raises.
    """
    prompt = PROMPT.format(page=text)
    attempts = retries + 1
    for _ in range(attempts):
        try:
            return _parse_json(client(prompt)), "ok"
        except Exception:
            continue
    return None, "missing"


def annotate_pending(store: Store, client: Client) -> dict:
    """Annotate every page whose summary is still 'pending'. Returns counts."""
    ok = missing = skipped = 0
    for page in store.pages():
        if page["summary_status"] != "pending":
            skipped += 1
            continue
        text = page["summary_input"]
        if not text:
            store.set_page_summary(page["id"], summary=None, summary_input=text, status="missing")
            missing += 1
            continue
        summary, status = summarize(text, client)
        store.set_page_summary(
            page["id"],
            summary=json.dumps(summary) if summary is not None else None,
            summary_input=text,
            status=status,
        )
        ok += status == "ok"
        missing += status == "missing"
    return {"ok": ok, "missing": missing, "skipped": skipped}


def anthropic_client(model: str = "claude-sonnet-4-6") -> Client:
    """
    Build a real LLM client. Lazy-imports anthropic so the package works without
    it. Requires ANTHROPIC_API_KEY in the environment.
    """
    import anthropic  # lazy: only needed when actually annotating for real

    sdk = anthropic.Anthropic()

    def call(prompt: str) -> str:
        resp = sdk.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in resp.content if block.type == "text")

    return call
