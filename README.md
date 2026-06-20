# secagent

Probing how good today's AI is at black-box web vuln hunting, against OWASP Juice Shop,
with a built-in answer key (the scoreboard). Staged tiny-first: **v0** recon proof of
concept → **v1** recon map → **v2** hunter. Full plan: design doc in
`~/.gstack/projects/secagent/`.

## Setup

### 1. Start the target (OWASP Juice Shop) with Docker Compose

The target is pinned by digest (v20.0.0) in [docker-compose.yml](docker-compose.yml):

```
docker compose up -d        # start Juice Shop at http://localhost:3000
docker compose ps           # check it's healthy
docker compose down         # stop it when finished
```

### 2. Install the tool

Dependencies live in [pyproject.toml](pyproject.toml) (single source of truth — no
requirements.txt). Using [uv](https://docs.astral.sh/uv/):

```
uv venv .venv --python 3.13
uv pip install --python .venv/bin/python -e '.[dev]'   # runtime + test deps
.venv/bin/playwright install chromium
```

This installs a `secagent` command into the venv (`.venv/bin/secagent`).

## v1 — recon companion (current)

Capture a browse of the live target into a deduped attack-surface map (endpoints +
pages, linked), then inspect it. Page-understanding (annotation) is optional and LLM-backed.

```
# 1. capture a manual browse (host allowlist enforced: localhost only)
.venv/bin/secagent capture http://localhost:3000 --db recon.db
#    drive the app by hand — log in, search, basket, admin — then Ctrl-C / close window

# 2. (optional) summarize each page with the LLM
uv pip install --python .venv/bin/python -e '.[llm]'   # adds the anthropic SDK
export ANTHROPIC_API_KEY=...                            # required only for this step
.venv/bin/secagent annotate --db recon.db

# 3. inspect the map (text, plus optional HTML)
.venv/bin/secagent report --db recon.db --html recon.html
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

Live capture records the session as events and `replay()`s them into the store — the
same path tests exercise from recorded fixtures, so capture is tested with no browser.

Run the tests: `.venv/bin/python -m pytest`.

## v0 — proof of concept (kept for reference)

The original ~50-line capture-and-print script:

```
.venv/bin/python recon_v0.py            # manual browse, prints unique METHOD /path
.venv/bin/python recon_v0.py --smoke    # auto-drive a few routes (verification)
```
