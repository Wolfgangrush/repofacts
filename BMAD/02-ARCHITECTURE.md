# 02 — ARCHITECTURE · repofacts

**Status:** DRAFT · pre-code · 2026-08-24 · full record

## Stack, with reasons

**Python 3.11+, standard library only. Zero runtime dependencies.**

- Zero deps means `uv tool install repofacts` or `pipx install repofacts` works instantly with no
  resolution, no lockfile, no supply chain of its own. **A tool whose subject is dependency risk must
  not itself be a dependency risk.** That is the argument, and it is not decorative.
- Python keeps the contribution barrier low and matches the rest of the owner's tooling.
- `http.client` · `json` · `re` · `argparse` · `concurrent.futures` · `datetime` · `gzip` · `subprocess`
  (token discovery only) are sufficient for every requirement in `01`.
- **`http.client.HTTPSConnection`, not `urllib.request`** — one persistent keep-alive connection per
  worker. `urllib.request` opens a fresh TCP+TLS handshake per call, which makes 8 workers *slower*
  than 1. Raised by the Phase-3 pass; stdlib supports pooling, it just isn't in `urllib`.

**Rejected:** Go/Rust — a single binary is nice but raises the contribution barrier and the release
burden for a tool this small. Node — a dependency tree is exactly the thing this tool warns about.

## Components

| module | responsibility | network? |
|---|---|---|
| `extract.py` | arbitrary text → `list[RepoRef]` | no |
| `github.py` | GitHub REST client: repo metadata, README, rate limits, redirects | **yes, only here** |
| `rules.py` | licence classification · liveness · platform fitness · verdict | no — **pure** |
| `claims.py` | conservative claim extraction + diff against facts | no — **pure** |
| `render.py` | table · summary line · `--json` · `--markdown` | no |
| `cli.py` | argparse, orchestration, exit codes | no |

**All network access is confined to `github.py`.** `rules.py` and `claims.py` are pure functions over
plain data, so the entire decision layer is unit-testable offline with fixtures. This is the single
most important structural decision: it is what makes real tests possible.

## Data model

```
RepoRef      owner · repo · raw_mention · line_no        (no confidence score — cut in Phase 3)
RepoFacts    exists · stars · forks · license_spdx · license_name · pushed_at · created_at
             archived · disabled · language · description · readme_text · moved_to
Assessment   verdict(OK|CAUTION|STOP) · reasons[] · claim_diffs[]
```

## Flow

```
text ──extract──▶ [RepoRef] ──github (threaded)──▶ [RepoFacts] ──rules──▶ [Assessment] ──render──▶ stdout
                                                          └──claims (if --claims)──┘
```

Concurrency: `ThreadPoolExecutor`, default 8 workers, bounded by observed rate-limit headers.

## Token discovery — in order

1. `$REPOFACTS_TOKEN` → 2. `$GH_TOKEN` → 3. `$GITHUB_TOKEN` → 4. `gh auth token` if `gh` exists →
5. unauthenticated.

`$GITHUB_TOKEN` is deliberately **third**: GitHub Actions auto-provisions it at 1,000 req/hr and
repo-scoped, and putting it first would silently shadow a user's 5,000 req/hr PAT. Warn when the
Actions-provisioned token is the one in use.

**Token shape is validated before use** — `^gh[posu]_[A-Za-z0-9]{36,}$`. `gh auth token` on an
unauthenticated `gh` can print help text to stdout and exit 0; without this check that help text
gets sent as a Bearer token and returns a baffling 401.

**Pre-flight budget gate:** before any work, compare `X-RateLimit-Remaining` against
`len(refs) x calls_per_ref` and refuse to start a run that cannot finish, naming the reset time.
Partial-result handling is the fallback, not the plan.

Unauthenticated GitHub is **60 requests/hour**; authenticated is 5,000. Running unauthenticated over a
20-repo list with README fetches will exhaust the quota mid-run. The tool must **say so loudly before
starting**, not fail halfway. `gh` is used opportunistically for a token and is never a hard dependency.

## Licence classification — the subtle part

GitHub's `license.spdx_id` has three failure shapes and they mean different things:

| API value | meaning | our class |
|---|---|---|
| absent / `null` | **no licence file at all** → no grant, legally unusable | `NONE` — **STOP** |
| `NOASSERTION` | a licence file exists but GitHub could not identify it | `UNRECOGNISED` — sniff `LICENSE` for BSL / ELv2 / Commons Clause → `SOURCE_AVAILABLE` |
| `MIT`, `Apache-2.0`, … | recognised SPDX | `PERMISSIVE` / `COPYLEFT` / `NETWORK_COPYLEFT` |

Conflating `NONE` with `NOASSERTION` is the error this section exists to prevent. Grounded in a real
case on 2026-08-24: `mksglu/context-mode` reports `NOASSERTION`; its README badge says **ELv2** —
source-available, not open source, and commercially restrictive. A naive reading called it "unknown
licence"; the correct reading is "source-available, do not embed in anything you sell".

`AGPL-3.0` and `SOURCE_AVAILABLE` are reported as **commercial-poison** — `CAUTION`, not `STOP`,
because running them is fine; embedding them in proprietary work is not. The distinction is stated in
the reason string.

## Platform fitness

Fetch README (`raw.githubusercontent.com`, HEAD branch), scan for hard requirements:
`CUDA` · `NVIDIA` · `TensorRT` · `ROCm` · `Linux only` · `Windows only` · `ESP32` · `Arduino` ·
`Raspberry Pi`, compared against the host (`platform.system()` / `platform.machine()`).

**Known false-positive risk:** a README saying *"no CUDA required"* or *"unlike CUDA-based tools"*.
Mitigation: the match must fall within a requirements/installation context (a Requirements/Install
heading, a table row, or a bulleted prerequisite) — and where context is ambiguous the verdict is
**`CAUTION` with the quoted line**, never `STOP`. **A false `STOP` is worse than a missed `CAUTION`**,
because it makes the tool untrustworthy in the one way it cannot afford.

## Verdict rules (revised after the Phase-3 pass)

- **`archived` is NOT automatically `STOP`.** A finished, intentionally-archived stable tool is a
  feature. archived + last push >2y → `CAUTION` (name the successor if `moved_to` or the README
  gives one); archived + <1y → `OK` with a note.
- **`fork: true` with low stars → `CAUTION`**, naming `parent_full_name`. A stale fork of a famous
  upstream copies the README verbatim and looks legitimate.
- **Platform check is three-state:** `checked_clear` · `checked_conflict` · `unchecked`. `unchecked`
  is always printed. A check that did not run must never render the same as a check that passed.
- Report carries **`licence as of <UTC>`** — licences change retroactively.
- Multiple licence files (`LICENSES/`, `LICENSE-*`) → `CAUTION: verify manually`. Full multi-licence
  resolution is a **stated limitation**, not a claim.

## Failure modes

| failure | behaviour |
|---|---|
| rate limit exhausted mid-run | stop, emit results so far **clearly marked partial**, name the reset time, exit 2. Never silently truncate. |
| network unreachable | fail loudly, exit 2 |
| repo moved / renamed (301) | follow, report `moved_to` — real case 2026-08-24: `ryoppippi/ccusage` → `ccusage/ccusage` |
| repo private but visible to your token | flag: "visible to you, not to your users" |
| README missing / binary | platform check returns `unknown`, never a guess |
| ambiguous bare `owner/repo` in prose | low confidence → skipped unless `--loose`; skipped mentions are **listed**, never silently dropped |

## Input extraction — the hard part

Accepted with high confidence: `https://github.com/owner/repo` (with `.git`, trailing slash,
`/tree/...`, `#anchor`), markdown links, backticked `` `owner/repo` ``, list items.

Bare `owner/repo` in running prose is **low confidence** — English is full of `and/or`,
`input/output`, `24/08`. Rule: bare pairs are accepted only when they satisfy GitHub's naming
grammar **and** sit in a code span, a list item, or a table cell. Otherwise reported as skipped.
Silent dropping is banned: a verifier that quietly ignores an entry is worse than useless.

## Rejected designs

- **Use the `gh` CLI as the API layer.** Rejected: hard dependency most users lack. Kept only as an
  optional token source.
- **Disk cache of API responses.** Rejected for v1: the product's entire value is freshness; a cache
  introduces exactly the staleness class of bug the tool exists to catch.
- **A 0–100 "health score".** Rejected: that is taste dressed as arithmetic, and `01` bans quality
  judgement. Verdicts are categorical with stated reasons a human can argue with.
- **An LLM to parse claims.** Banned by `01` principle #1 — a deterministic verifier cannot contain a
  non-deterministic component.
