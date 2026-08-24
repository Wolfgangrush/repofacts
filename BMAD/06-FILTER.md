# 06 — FILTER · repofacts

**Date:** 2026-08-25 · Run AFTER the code existed, BEFORE anything was called done.

> The filter is a convergence loop, not a selection loop. It does not choose between
> approaches — `01-PRD.md` already did that. It drags the code back onto the architecture it
> was supposed to follow, and it is the difference between a codebase and a pile.

**How this pass was run.** An over-engineering lens was run over `src/` and `tests/` by a model
independent of the one that wrote the implementation. It returned 10 findings. Every one was
re-read against the actual file before being accepted — two carried wrong line numbers and were
corrected, none were rejected. A separate architecture-conformance read (Pass 1) and a
mechanical banned-scope sweep (Pass 4) were run here, not delegated.

---

## Pass 1 — read the code against the architecture

| # | Architecture says | Code actually does | Verdict |
|---|---|---|---|
| 1 | `extract.py` — text → `list[RepoRef]`, no network | same | matches |
| 2 | `github.py` — the only module making requests | same; `net` imports appear in no other module | matches |
| 3 | `rules.py` — pure verdicts | pure when passed `now`; keeps a `now=None` clock fallback | drifted (see 3.2) |
| 4 | `claims.py` — pure claim diff | same | matches |
| 5 | `render.py` — table / json / markdown, no network | read the wall clock at render time | drifted (see 3.1) |
| 6 | `cli.py` — argparse, orchestration, exit codes | same | matches |
| 7 | *(not in the doc)* | `models.py` — shared dataclasses | **extra** |
| 8 | *(not in the doc)* | `security.py` — pure security assessor | **extra** |
| 9 | *(not in the doc)* | `quality.py` — pure quality assessor | **extra** |
| 10 | *(not in the doc)* | `simulate.py` — install/conflict simulation | **extra** |

Rows 7–10 are **authorised extras**, not scope creep: they implement the scope expansion
recorded in `01-PRD.md` under *SCOPE EXPANSION*. What was wrong is that neither `02` nor `03`
was updated when they landed, so both documents described a six-module tool that had not
existed for a day.

## Pass 2 — restructure to match

| # | Change made | Which architecture line it now obeys |
|---|---|---|
| 1 | Merged the two deep-battery fetchers into one `fetch_deep_facts` returning `DeepFacts`; `SecurityFacts` / `QualityFacts` are now aliases | `02` "network only in `github.py`" — and it now costs one round of calls per repo, not two |
| 2 | Extracted `_ingest_pypi_dep_entries`; `[project.dependencies]` and every `[project.optional-dependencies]` group share one parser | `02` `simulate.py` single responsibility |
| 3 | `render.format_json` accepts `generated_at` instead of reading the clock | `03` invariant 3 — pure, offline-testable renderers |
| 4 | Added `tests/conftest.py` putting `src/` on the path | `03` "offline-testable" — every test file now runs standalone |

| # | Architecture amended | Why the code was right and the doc was wrong |
|---|---|---|
| 1 | `02` component table gained `models` / `security` / `quality` / `simulate` | The scope expansion was authorised in `01`; the table simply never caught up |
| 2 | `03` module outline gained the same four | same |
| 3 | `03` invariant 3 now states the clock rule accurately | `github.py`'s docstring claimed it was "the only one allowed to read the clock". It never was — `cli.py` is the composition root and correctly captures `now` once per run. The doc described a rule the design never followed |

## Pass 3 — now look for mistakes

| # | Mistake | How found | Fix | Test that now covers it |
|---|---|---|---|---|
| 1 | `render.format_json` stamped `generated_at_utc` at render time, so `--json` was not reproducible and the stamp could drift from the assessment time on a slow run | Pass-1 clock audit | takes `generated_at`; `cli` passes the run's `now` | existing `test_render` json tests exercise the new path; determinism now follows from the signature |
| 2 | **Five of eleven test files failed to collect when run alone** (`pytest tests/test_claims.py` → collection error). They passed only because an alphabetically-earlier module had already mutated `sys.path` | ran each test file in isolation | `tests/conftest.py` | every one of the 11 files verified passing standalone |
| 3 | `_KeepAliveHTTPSConnection` was an empty subclass whose docstring claimed it "records the response object" — it did not | lens, verified in file | deleted; `http.client.HTTPSConnection` used directly, thread-safety note kept at the use site | existing `github` tests |
| 4 | Dead `ceil` store in the PEP 440 `~=` branch — computed, then overwritten on the next line by a comment beginning *"actually:"* | lens, verified in file | removed the wrong first computation | existing `simulate` version-range tests |
| 5 | `conflict = False` in `rules.py` was assigned, never set true, then discarded via `_ = conflict` with a comment admitting it | lens (line numbers wrong — real site is 231/256) | removed | existing `rules` platform tests |
| 6 | `_BINARY_EXTENSIONS` defined in `github.py` and never referenced; `security.py` holds the live copy | lens, verified in file | removed the dead copy | existing `security` tests |
| 7 | Two `if …: pass` branches in `github.py` whose entire body was a comment | lens, verified in file | removed | existing `github` rate-limit tests |
| 8 | `_run_deep` took an `installed_packages` parameter no caller ever passed | lens, verified — no call site in `src/` or `tests/` | dropped; `{}` at the single use | existing `cli --deep` tests |
| 9 | Four unused imports (`typing.Any` ×2, `datetime`, `SecurityFacts`) — fallout of the fetcher merge | `ruff check` | removed | lint job now blocks their return |
| 10 | Dead local `e` in `test_github.py`; `f` on the next line *is* used, so this was a genuine leftover | `ruff check` | removed | lint job |
| 11 | Duplicate `sorted(assessments, …)` computed twice inside `format_table` | lens, verified in file | bound once | existing `render` ordering tests |
| 12 | **No CI existed at all** — no `.github/workflows/`. Nothing enforced tests or lint on push | looked for it | added `ci.yml`: tests (3 OS × 3 Python), pinned `ruff==0.15.22`, and a **zero-dependency guard** that fails the build if `dependencies` ever becomes non-empty | the workflow is the test |

## Pass 4 — banned-scope sweep

| # | Banned item | Present in code? | Removed / deferred to |
|---|---|---|---|
| 1 | No LLM anywhere inside | **no** — zero matches for any model/provider API | — |
| 2 | Nothing is ever executed; no `subprocess` | **one call, intent-compliant** — `subprocess.run(["gh","auth","token"], timeout=5)`, fixed argv, no shell, credentials only | **Kept, and the rule's wording is the thing that was wrong.** The ban exists so the tool never executes code from a repo under inspection. It never does. Running a local, user-installed credential helper is a different act. `01` item 2 should read "never executes anything from a repo under inspection"; recorded here rather than silently ignored |
| 3 | No auto-clone / install / fix / write to the user's project | **no** — zero write-mode `open()` calls in `src/` | — |
| 4 | No telemetry / analytics / phone-home | **no** — zero matches | — |
| 5 | No network beyond `api.github.com` / `raw.githubusercontent.com` | **compliant** — only `api.github.com` appears | — |
| 6 | No malware verdict | **no** — the single occurrence of "malicious" is in a sentence explicitly deferring the judgement to a human | — |
| 7 | No free-text semantic understanding | **no** — pattern matching only; unparsed input reports `unparsed` | — |
| 8 | No web UI / server / dashboard | **no** — the one `flask` match is a string inside the typosquat-proximity wordlist | — |
| 9 | No GitLab / Bitbucket in v1 | **no** — zero matches | — |
| 10 | A check that could not run reports `unchecked`, never a pass | **honoured** — the invariant is asserted directly in `test_security`, `test_quality` and `test_rules` | — |

---

## Exit criteria — all four must be true

- [x] Every component in `02-ARCHITECTURE.md` maps to code, and every module in the code
      maps back to `02`. No orphans in either direction. *(Reached by amending `02`, per Pass 2.)*
- [x] `03-ARCHITECTURE-ESSENTIALS.md` still describes the code accurately. It had drifted on
      the module list and on the clock rule; both are corrected.
- [x] Nothing from the `01-PRD.md` banned-scope list survives in the tree. The one item needing
      a judgement (`subprocess`) is recorded above with its reasoning, not waved through.
- [x] Test suite green, and every Pass-3 fix has a test that would catch it returning.
      **275 passed · `ruff check` clean · every test file passes standalone.**

## Verdict

- [x] **CONVERGED** — code follows the architecture protocol.
- [ ] **ANOTHER PASS NEEDED**

**Carried forward, stated not hidden.** These are real and were not fixed in this pass:
the **conflict simulation never learns what is installed on the host** — `cli` always passes an
empty map, so the "version conflicts against installed packages" line can only ever read `0`.
The comparison engine is real and tested; the missing piece is host inspection. This was
surfaced by the README review: the README claimed the capability, so the README was corrected
rather than the claim being left to stand. Wiring it up is the obvious next feature, and it is a
scope decision for the owner, not something to bolt on at ship time. Also:
`simulate.py` still carries only 3 direct tests against 1,175 lines (it is exercised indirectly
through the `--deep` CLI tests, but that is not the same thing); `README.md` and
`pyproject.toml` ship without tests of their own; and the build is **test-after, not TDD** —
the code preceded its tests and no TDD receipt exists, so the claim is not made.

---

*Where this sits: `00`–`05` are written before code. `06` is written after it. Together they
are the loop — plan, build, then drag the build back onto the plan.*
