# 04 — BMAD SPEC · repofacts

**Status:** pre-code · 2026-08-24 · name locked by the owner 14:04 IST

## B — BUILD

A zero-dependency Python CLI that takes repos an LLM recommended and reports, per repo, whether it is
real, legally usable, alive, and runnable on the host — plus a narrowed diff of the model's stars and
licence claims against GitHub's answer.

Modules: `extract` · `github` (only network) · `rules` (pure) · `claims` (pure) · `render` · `cli`.
Full design in `02`; the outline that must stay in context is `03`.

## M — MEASURE

| metric | target |
|---|---|
| replay of the three real 2026-08-24 recommendation lists | **every failure a human caught by hand is caught by the tool** |
| false `STOP` on a healthy repo | **zero** |
| cold run, 20 repos, authenticated | completes inside the rate budget, < 30 s |
| install | one command, no configuration |
| runtime dependencies | **0** |

The acceptance corpus is not invented: the three lists, and the human verdicts on them, are already
recorded in `the publisher's build log`.

## A — ANALYZE

*(post-code — what worked, what didn't, and what the owner observed that this spec did not anticipate)*

## D — DECIDE

*(post-code — SHIP · ITERATE · KILL. "We'll see" is banned.)*

---

## FALSIFIER — what observable result proves this design wrong

1. **A single false `STOP` on a healthy repo** in the acceptance replay. A verifier that cries wolf is
   worse than no verifier, because it trains the user to skip it. One false STOP ⇒ the verdict rules
   are wrong and get redesigned, not patched.
2. **`--claims` reports "not parsed" on more than half of real LLM star/licence claims.** This is the
   recorded falsifier from the Phase-3 disagreement: the review argued the feature should be cut before
   any code; the maintainer held it, narrowed. If this fires at `06-FILTER`, **the feature is cut** — the
   disagreement is settled by evidence, not by whoever argued last.
3. **A 20-repo authenticated run cannot finish inside the rate budget.** Then calls-per-repo is wrong
   and the README/licence probes need rethinking, not more workers.
4. **The tool reports `OK` on a repo that a human would have rejected**, in the replay. A miss is
   less damaging than a false STOP but still falsifies the ruleset.

## CUT-OVER CRITERION — when the manual flow stops being authoritative

Today, verification is a human running `gh api` by hand — three times on 2026-08-24 alone.

**Cut-over fires when repofacts, unaided, reproduces every failure that manual pass caught across all
three lists, with zero false STOPs.** From that run onward, repofacts' output is the record pasted
into the publisher's build log, and the hand-run `gh api` pass is retired to a spot-check. Until then the manual
pass remains authoritative and repofacts is advisory — it does not get to grade its own homework.

---

## Ship gates (Phase 8) — answered post-code, blank is not an answer

### 8.1 Tests · TDD receipt
*(pending — `tdd_gate.py audit --project <repo root> --changed <every file>`; every
UNTESTED file to be named out loud here)*

### 8.2 Security and data
**Provisional: `N/A` — no personal data, no credentials stored, no client or Office material, no
network surface exposed (outbound HTTPS only, to `api.github.com` and `raw.githubusercontent.com`).**
The one sensitive element is a **GitHub token read from the environment**, which must never be logged,
echoed, or written to any output including `--json`. **A test must prove the token cannot appear in
any rendered output.** To be re-confirmed post-code, not assumed.

### 8.3 Production readiness · 13 layers
*(pending — `deploy_model: LOCAL_LIB`. Most layers legitimately `NA`, to be waived **layer by layer
with reasons**, never left blank.)*

---

## Route

- **BMAD-new**, not a bug fix.
- **Egress: NOT sensitive** — public repo metadata only. Cloud delegates permitted.
- **Codegen:** an independent review (live-probed `PROBE-UP` 2026-08-24 14:05) in a watchable pane.
- **Tests:** authored by the maintainer, per `the model-separation rule`.
- **Independent review:** seat **VACANT** since codex died 2026-08-17. `alibaba/open-code-review` is
  the candidate successor and this is its obvious first real job — **the owner's call, not the router's.**

## BUILD IS NOT PUSH

`SHIP` in D will mean the code is done and the gates are answered. It will **not** mean pushed.
Publishing needs a separate explicit gate from the owner plus the **publication firewall** — cheap here, since
the tool contains no client data, no internal references, and no private identifiers, but **not waived**.
