# TODOS

## Deferred (v2)

### Bulletproof off-scope network gate (P2a hardening)
- **What:** Abort every off-scope request (browser nav, redirect hop, subresource)
  at the network layer, so the agent physically cannot reach a non-allowlisted host.
- **Why:** Today's controls (per-action pre-check, `max_redirects=0` on the HTTP
  tool, post-nav `page.url` check → `blocked_by_scope`) catch agent-chosen URLs and
  detect redirect drift, but a *browser* auto-redirect fires one request to the
  off-scope host before the post-check sees it. That single request is the residual
  hole in the "no web tool" guarantee.
- **Blocker:** Playwright's `context.route` (the obvious gate) puts the context into
  request-interception mode, which downgrades off HTTP/2 globally and makes
  PortSwigger return `ERR_HTTP2_PROTOCOL_ERROR` — even with a predicate matcher that
  only targets off-scope URLs. So the gate breaks every lab.
- **Options to explore:** a forward proxy with a host allowlist (launch Chromium with
  `--proxy-server` pointing at a tiny local allowlisting proxy — keeps HTTP/2 to the
  lab, blocks everything else); or CDP `Fetch.enable` with surgical scope; or accept
  the residual for deliberately-vulnerable lab targets only.
- **Severity:** low for the current target set (labs we launch are not hostile
  redirectors); raise priority before pointing the hunter at anything less trusted.
- **Source:** Codex pre-merge review #1/#2, 2026-06-20 (ship).

### Value-sensitive endpoint signatures
- **What:** Optionally distinguish endpoints by a value-derived operation class
  (e.g. search-text present, coupon code, injection-shaped payload) instead of
  ignoring all request values when building the dedupe signature.
- **Why:** The v2 hunter may need to tell a benign search from an injection probe.
  Pure method+path+param-name-set dedupe erases that distinction.
- **Pros:** Richer signal for the hunting step; surfaces operation classes the
  recon map would otherwise flatten.
- **Cons:** Signature explosion; added complexity in a layer that has no consumer
  for the richer data until v2 exists.
- **Context:** v1 deliberately ignores all values (see design doc Premise 4). This
  is a v2-driven refinement — revisit once the LangGraph hunter is real and you can
  see which value-shapes actually change its reasoning.
- **Depends on:** v2 hunter (out of current scope).
- **Source:** Codex outside-voice review, 2026-06-20 (plan-eng-review).

### Recon-map ingestion as hunter state (v2, deferred from Phase 1)
- **What:** Feed the v1 recon map (endpoints/pages) to the hunter as first-class
  LangGraph state, instead of the agent reconning inline from URL + goal.
- **Why:** office-hours chose Approach C (recon-map spine); the v2 Phase-1 eng review
  reversed it to direct-agent because a pre-fed/manual map *leaks the exploit path*
  (a map containing `/admin` hands over the access-control lab) and breaks the
  "solving from URL + goal" claim.
- **Revisit only if:** measured Phase-1 failures show inline recon is the actual
  bottleneck. If so, withhold answer-leaking entries, or the goal-only claim is
  contaminated again.
- **Pros:** reuses the v1 map investment; richer state for harder labs.
- **Cons:** answer leakage; manual recon = human-curated surface, not autonomous.
- **Depends on:** Phase-1 loop shipped + failure data.
- **Source:** Cross-model tension T1 (Codex + Claude), 2026-06-20 (plan-eng-review).

### Harder / non-canonical lab set for the real hunting claim (v2)
- **What:** Graduate beyond the 3 Phase-1 tracer labs (SQLi hidden-data, SQLi
  login-bypass, unprotected-admin) to Practitioner/Expert labs, Mystery Labs, or
  morphed self-hosted clones.
- **Why:** the tracer labs are canonical and fully documented (PortSwigger publishes
  exact solutions), so a Phase-1 solve proves the *loop works*, NOT that the model
  *hunted*. Any reasoning claim must come from less-memorized targets.
- **Pros:** the actual capability measurement; morphed clones close latent recall.
- **Cons:** harder ground-truth + lab lifecycle; morphed clones = self-hosting.
- **Depends on:** Phase-1 loop + Phase-2 measurement layer (canary, tagging).
- **Source:** Codex outside-voice review, 2026-06-20 (plan-eng-review).
