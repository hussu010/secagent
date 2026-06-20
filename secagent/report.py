"""
Report / inspection view (T8).

Renders the attack-surface map from the store as text (and optional HTML). This
is *inspection*, not observability — a readable dump of endpoints, pages, and
their links, so a human can eyeball what the recon run found.
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


def render(db_path: str, html_path: str | None = None) -> None:
    store = Store(db_path)
    try:
        print(render_text(store))
        if html_path:
            with open(html_path, "w") as f:
                f.write(render_html(store))
            print(f"(html written to {html_path})")
    finally:
        store.close()
