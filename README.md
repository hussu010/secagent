# secagent

Probing how good today's AI is at black-box web vuln hunting, against OWASP Juice Shop,
with a built-in answer key (the scoreboard). Staged tiny-first: **v0** recon proof of
concept → **v1** recon map → **v2** hunter. Full plan: design doc in
`~/.gstack/projects/secagent/`.

## Setup (once)

```
docker run -d --rm -p 3000:3000 --name juiceshop bkimminich/juice-shop
uv venv .venv --python 3.13
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/playwright install chromium
```

## v1 — recon companion (current)

Capture a browse of a live target into a deduped attack-surface map (endpoints +
pages, linked), then inspect it. Annotation (page understanding) is optional and
LLM-backed.

```
# 1. capture a manual browse into the map (host allowlist enforced: localhost only)
.venv/bin/python -m secagent.cli capture http://localhost:3000 --db recon.db
#    drive the app by hand (log in, search, basket, admin), then Ctrl-C / close window

# 2. (optional) summarize each page with the LLM — needs the SDK + key
uv pip install --python .venv/bin/python -e '.[llm]'
export ANTHROPIC_API_KEY=...      # required only for this step
.venv/bin/python -m secagent.cli annotate --db recon.db

# 3. inspect the map (text, plus optional HTML)
.venv/bin/python -m secagent.cli report --db recon.db --html recon.html
```

`--allow-host HOST` permits a non-loopback target (use only if you are authorized).

### Architecture

```
headed Chromium ─┬─ requests (context.on response) ─┐
  (you drive)    └─ routes  (poll page.url + settle)─┴─▶ events[] ──▶ replay()
                                                                        │
                          normalize (signature, :id/:uuid) ◀────────────┤
                                                                        ▼
                                                              SQLite map (endpoints,
                                                              pages keyed route+auth,
                                                              page↔endpoint links)
                                                                        │
                          annotate (DOM/a11y-first, optional) ──────────┤
                                                                        ▼
                                                                   report (text/HTML)
```

Live capture records the session as events and `replay()`s them into the store —
the same path tests exercise from recorded fixtures, so capture is tested with no
browser. Tests: `.venv/bin/python -m pytest`.

## v0 — proof of concept (kept for reference)

The original ~50-line capture-and-print script:

```
.venv/bin/python recon_v0.py            # manual browse, prints unique METHOD /path
.venv/bin/python recon_v0.py --smoke    # auto-drive a few routes (verification)
```

Stop the target when finished: `docker stop juiceshop`.
