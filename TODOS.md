# TODOS

## Deferred (v2)

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
