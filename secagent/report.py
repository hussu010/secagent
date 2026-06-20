"""
Report / inspection view (v1 recon map + v2 hunt runs).

Renders the attack-surface map AND, for v2, the hunt trace (one run = one lab
hunt; its steps are the hypothesize/act/observe/score timeline + terminal status).
This is *inspection*, not observability — a readable dump so a human can eyeball
what recon found and exactly how a hunt unfolded.

    store ──┬─ endpoints/pages ──▶ attack-surface map (v1)
            └─ runs/steps      ──▶ hunt timeline + verdict (v2)
"""

from __future__ import annotations

import html

from .store import Store


def _exemplar_tags(store: Store, endpoint_id: int) -> str:
    tags = []
    for ex in store.exemplars(endpoint_id):
        status = ex["status"] if ex["status"] is not None else "?"
        tags.append(f"[{ex['slot']} {status}]")
    return " ".join(tags)


def render_text(store: Store) -> str:
    eps = store.endpoints()
    pages = store.pages()
    lines = ["=== ATTACK SURFACE MAP ===", "", f"ENDPOINTS ({len(eps)})"]
    for e in eps:
        lines.append(f"  {e['signature']:<48} {_exemplar_tags(store, e['id'])}")
    lines += ["", f"PAGES ({len(pages)})"]
    for p in pages:
        n = len(store.endpoints_for_page(p["id"]))
        summary = p["summary_status"] or "none"
        lines.append(f"  {p['route']:<28} {p['auth_state']:<7} summary:{summary:<8} endpoints:{n}")
    return "\n".join(lines) + "\n"


def render_html(store: Store) -> str:
    eps = store.endpoints()
    pages = store.pages()
    rows_e = "\n".join(
        f"<tr><td><code>{html.escape(e['signature'])}</code></td>"
        f"<td>{html.escape(_exemplar_tags(store, e['id']))}</td></tr>"
        for e in eps
    )
    rows_p = "\n".join(
        f"<tr><td>{html.escape(p['route'])}</td><td>{p['auth_state']}</td>"
        f"<td>{p['summary_status'] or 'none'}</td>"
        f"<td>{len(store.endpoints_for_page(p['id']))}</td></tr>"
        for p in pages
    )
    return (
        "<!doctype html><meta charset=utf-8><title>recon map</title>"
        "<style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse;margin:1rem 0}"
        "td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}code{font:13px monospace}</style>"
        f"<h1>Attack surface map</h1><h2>Endpoints ({len(eps)})</h2>"
        f"<table><tr><th>signature</th><th>exemplars</th></tr>{rows_e}</table>"
        f"<h2>Pages ({len(pages)})</h2>"
        f"<table><tr><th>route</th><th>auth</th><th>summary</th><th>endpoints</th></tr>{rows_p}</table>"
    )


def _short(text: str | None, n: int = 70) -> str:
    if not text:
        return ""
    text = text.replace("\n", " ")
    return text if len(text) <= n else text[: n - 1] + "…"


def render_runs_text(store: Store) -> str:
    """Hunt trace: each run's verdict + its hypothesize/act/score timeline."""
    runs = store.runs()
    if not runs:
        return ""
    lines = ["", "=== HUNT RUNS ===", ""]
    for r in runs:
        status = r["status"] or "in-progress"
        lines.append(f"RUN {r['id']}  [{status}]  {r['lab_id']}  goal: {_short(r['goal'])}")
        if r["note"]:
            lines.append(f"    note: {_short(r['note'])}")
        for s in store.steps(r["id"]):
            detail = s["score"] or _short(s["action"] or s["observation"], 60)
            lines.append(f"    #{s['idx']:<3} {s['node']:<11} {detail}")
        lines.append("")
    return "\n".join(lines)


def render_runs_html(store: Store) -> str:
    runs = store.runs()
    if not runs:
        return ""
    blocks = ["<h1>Hunt runs</h1>"]
    for r in runs:
        status = r["status"] or "in-progress"
        rows = "\n".join(
            f"<tr><td>{s['idx']}</td><td>{s['node']}</td>"
            f"<td><code>{html.escape(s['score'] or s['action'] or s['observation'] or '')}</code></td></tr>"
            for s in store.steps(r["id"])
        )
        blocks.append(
            f"<h2>Run {r['id']} — <span>{html.escape(status)}</span></h2>"
            f"<p>{html.escape(r['lab_id'])} · goal: {html.escape(r['goal'])}"
            + (f" · note: {html.escape(r['note'])}" if r["note"] else "")
            + "</p>"
            f"<table><tr><th>#</th><th>node</th><th>detail</th></tr>{rows}</table>"
        )
    return "".join(blocks)


def render(db_path: str, html_path: str | None = None) -> None:
    store = Store(db_path)
    try:
        print(render_text(store))
        runs_text = render_runs_text(store)
        if runs_text:
            print(runs_text)
        if html_path:
            with open(html_path, "w") as f:
                f.write(render_html(store) + render_runs_html(store))
            print(f"(html written to {html_path})")
    finally:
        store.close()
