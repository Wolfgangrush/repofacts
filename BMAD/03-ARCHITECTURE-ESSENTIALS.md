# 03 — ARCHITECTURE ESSENTIALS · repofacts

Outline only. If this stops fitting comfortably in context, it has failed its job.

## One line
Takes repos an AI recommended, asks GitHub the truth, prints a verdict per repo.

## Invariants
1. **No LLM inside.** Deterministic, reproducible, always.
2. **Zero runtime dependencies.** Python 3.11+ stdlib only.
3. **Network only in `github.py`.** `rules.py` and `claims.py` are pure → offline-testable.
4. **Never mutates anything** — no clone, no install, no writes to the user's project.
5. **Never silently drops an input.** Skipped mentions are listed with the reason.
6. **A false STOP is worse than a missed CAUTION.**

## Modules
`extract` (text→refs) · `github` (API, *only* net) · `rules` (pure verdicts) ·
`claims` (pure diff) · `render` (table/json/md) · `cli` (argparse, exit codes)

## Flow
`text → refs → facts (threaded) → assessments → render`

## Verdicts
- `STOP` — does not exist · no licence file at all · archived · hard platform mismatch
- `CAUTION` — dead >1y · AGPL/source-available · tiny star count vs claimed rank · ambiguous platform
- `OK` — none of the above

## Licence classes
`NONE` (no file → no grant, STOP) · `UNRECOGNISED` (NOASSERTION → sniff for BSL/ELv2) ·
`SOURCE_AVAILABLE` · `NETWORK_COPYLEFT` (AGPL) · `COPYLEFT` · `PERMISSIVE`
**`NONE` ≠ `NOASSERTION`.** Conflating them is the headline bug this design prevents.

## Exit codes
`0` all clear · `1` at least one STOP · `2` run failed or partial (rate limit / network)

## Token order
`$GITHUB_TOKEN` → `$GH_TOKEN` → `gh auth token` → unauthenticated (60/hr — warn **before** starting)

---

## Hard-question pass — answers recorded here (Phase 3)

Ran 2026-08-24 14:15 IST · an independent review (live-probed UP) · 12 findings.
**10 accepted · 1 accepted-narrowed · 1 rejected with reason.** the maintainer adjudicated each; the
critique materially improved the design and two findings corrected outright errors of mine.

### ACCEPTED — design changed

| # | finding | change made |
|---|---|---|
| 1 | stdlib `urllib` + 8 threads = no keep-alive, 8 TCP+TLS per call | **Switch to `http.client.HTTPSConnection`, one persistent connection per worker** — still stdlib, still zero-dep, but keep-alive works. Add `Accept-Encoding: gzip`, ETag/`If-None-Match`, and honour `Retry-After`. the review framed it as "pick stdlib OR concurrency" — that is a false choice; stdlib supports pooling, it just isn't in `urllib.request`. |
| 2 | `$GITHUB_TOKEN` first shadows a user PAT in GitHub Actions (1,000/hr vs 5,000/hr) | New order: `$REPOFACTS_TOKEN` → `$GH_TOKEN` → `$GITHUB_TOKEN` → `gh auth token`, and **warn explicitly when the Actions-provisioned token is in use**. |
| 3 | no pre-flight budget check; run dies mid-way | **Budget gate before starting:** compare `X-RateLimit-Remaining` against `len(refs) × calls_per_ref` and refuse to start a run that cannot finish, naming the reset time. Partial-result handling stays as the fallback, not the plan. |
| 4 | `gh auth token` can print help text to stdout and exit 0 → help text sent as a Bearer token | **Validate token shape before use.** *Corrected the review's own regex*: it proposed `^gh[ps]_…`, which misses `gho_` and `ghu_` — and `gho_` is exactly what this machine's `gh` issues. Accept `^gh[posu]_[A-Za-z0-9]{36,}$`. |
| 5 | the real slopsquatting case is a bare *package name* with no URL — invisible to a repo extractor | v1 stays repos-only (banned scope #5), but **bare single-token mentions that look like package names are reported in the skip list with an explicit "looks like a package name, not checked" warning.** Silence here would be the tool failing at its own headline problem. |
| 6 | fork blindness — 8★ repo may be a stale fork of a 50k★ upstream, README copied verbatim | Add **`fork` and `parent.full_name`** to `RepoFacts`. Low-star `fork: true` → **CAUTION**, naming the parent. |
| 8 | `archived` → `STOP` is wrong; a finished, intentionally-archived tool is fine | **Corrected an outright error of mine.** New rule: archived + last push >2y → `CAUTION` (point at `moved_to`/successor); archived + <1y → `OK` with a note. Never a bare `STOP`. |
| 9 | README fetch failure shares a code path with "README fine, nothing found" → silent OK on an ESP32-only project | **Platform check becomes three-state:** `checked_clear` · `checked_conflict` · **`unchecked`**, and `unchecked` is printed in the report. A check that did not happen must never look like a check that passed. |
| 10 | licence can change retroactively; report is a point-in-time claim | Report carries **`licence as of <UTC timestamp>`**. |
| 12 | `confidence` scoring on `RepoRef` is theatre — uncalibratable | **Cut `confidence`.** Extraction emits `{ref | skip, reason}`. `line_no` kept only because it is ~5 lines of stdlib. |

### ACCEPTED, NARROWED

| # | finding | resolution |
|---|---|---|
| 7 | multi-licence repos (MIT code + CC-BY-NC docs) collapse to one verdict | Cannot be solved completely without reading every file. **Stop claiming completeness:** probe for a `LICENSES/` dir or `LICENSE-*` files and, when found, emit `CAUTION: multiple licence files — verify manually`. Documented as a known limitation rather than pretended away. |

### REJECTED — with reason

| # | finding | why not |
|---|---|---|
| 11 | cut `--claims` from v1 entirely | **Held.** The claim-diff is the only thing that makes this more than a nicer `gh api`, and it is the demo that carries the whole tool. the review's real point — that a broad regex grammar mostly emits "not parsed" — is correct, so the feature is **narrowed to the two highest-frequency, highest-signal claims in LLM output: a star count near the mention, and an SPDX-ish licence token.** Everything else reports nothing at all rather than guessing. ~40 lines, not a grammar. If the narrowed version still mostly says "not parsed" on real input, it gets cut at `06-FILTER` — that is now a recorded falsifier, not a hope. |

