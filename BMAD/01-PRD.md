# 01 — PRD · repofacts

**Status:** DRAFT · pre-code · 2026-08-24 14:10 IST
**Owner:** the owner · **Build gate:** BMAD v2 · **Name locked by the owner 2026-08-24 14:04** (`an earlier candidate` rejected)

## What it is

A command-line tool that takes a list of GitHub repositories an AI recommended and reports,
for each one, whether it is **real, legally usable, still alive, and able to run on your machine** —
and where the AI's description of it differs from what GitHub actually says.

## The problem, with evidence

On 2026-08-24 a single day of AI-assisted repo research produced three recommendation lists.
In each, the model's **top-ranked pick** failed basic scrutiny:

| sweep | model's #1 | reality |
|---|---|---|
| 01:30 | `D0NMEGA/donnyclaude` | 8 stars, stale since 2026-07-06 |
| 02:05 | `chuchuyei/SentiCore` | 24 stars, shell repo, stale 3.5 months |
| 13:31 | "Contextium", offered as a community recommendation | best name match has 33 stars |

Also caught by hand in the same day: three repos with **no licence at all**; one that is **ELv2,
not OSI-open**, which would poison a commercial product; a "terminal" app that actually requires an
**ESP32 board**; an OCR engine requiring **Linux + NVIDIA** recommended for a Mac; and repos **dead
since 2023–2024** presented as current.

Every one of those was caught by a human running `gh api` by hand. That manual pass is the product.

## Who it is for

1. Anyone who asks an LLM "what library/tool should I use" and gets a list back — now the default
   way developers discover dependencies.
2. Maintainers of `awesome-*` lists, checking for rot.
3. Anyone reviewing an AI-generated PR that added dependencies.

## What it must do (v1)

1. Accept a list of repos from: pasted LLM output, a markdown file, an awesome-list, or stdin.
2. For each repo, answer six questions against the live GitHub API:
   - **Does it exist?** (404 = fabricated, or slopsquatted)
   - **Is it actually used?** stars, forks
   - **Can it be used legally?** licence, with `NONE` and `NOASSERTION` called out loudly,
     and AGPL / source-available flagged as commercial-poison
   - **Is it alive?** last push age, `archived`, `disabled`
   - **Will it run here?** README scanned for hard platform requirements vs the host platform
   - **Verdict:** `OK` · `CAUTION` · `STOP`, each with a stated reason
3. `--claims` mode, **narrowed after the Phase-3 pass**: diff only the two highest-signal claims that
   actually recur in LLM output — a **star count** near the mention, and an **SPDX-ish licence
   token**. Anything else reports nothing rather than guessing.
4. Emit a human table, a one-line summary receipt, `--json`, and `--markdown`.
5. Exit non-zero when any repo is `STOP`, so it can gate CI.

## Success criteria

- Re-running it over the three real 2026-08-24 lists reproduces every failure a human caught
  by hand, with no false `STOP` on a healthy repo. **This is the acceptance test, and the data
  already exists.**
- Install is one command with no configuration.
- A first-time user gets a useful answer in under 30 seconds without reading docs.

## SCOPE EXPANSION — authorised by the owner 2026-08-24 14:20 IST

> the owner: *"We can add these things — make it larger — add a security auditing layer — add a simulation
> layer — add a quality layer… One product doing everything… How to add it to Claude Code — or — how
> to add it to Codex — all of it, in one."* Then at 14:26: *"Both [simulation (b) and (c)] .. and go
> full throttle."*

**This is the owner deliberately reopening the banned list, not scope creep.** Recorded as a decision
so `06-FILTER` measures against the real target. The reviewer's stated objection at the time — that
"one product doing everything" dilutes the one-command, one-screenshot hook that made it spread —
was heard and **overruled by the owner, which is his call.** The mitigation adopted is a **fast default
with a `--deep` flag**, so the original 5-second path survives intact.

### The product is now four layers

| layer | what it answers | status |
|---|---|---|
| **FACTS** (v1 core) | real · licensed · alive · runs on your machine · claim-vs-reality | **BUILT + TESTED 14:35** |
| **SECURITY** | is this repo safe to depend on | building |
| **QUALITY** | is this repo well-run | building |
| **SIMULATION** | (b) what happens if I install it · (c) will it conflict with my stack | building |
| **INTEGRATION** | fires inside Claude Code / Codex when an agent recommends a repo | designed, not built |

**On not rebuilding OpenSSF Scorecard:** its 20 checks are the canonical security parameter set and we
name our checks after them so users recognise them — but we **implement them ourselves against the
GitHub API**, because a hard dependency on a Go binary would break the zero-dependency rule that is
this tool's own argument. Scorecard/OSV remain *optional enrichment if the binary is present*.
The repo is fully standalone and 100% new code.

## BANNED SCOPE — still binding after the expansion

Reduced but **not** abolished. `06-FILTER` sweeps against this list.

1. **No LLM anywhere inside the tool.** Permanent. A verifier must be deterministic; a tool that
   checks AI output must never itself hallucinate.
2. **Nothing is ever executed.** No `subprocess`, no install, no build, no sandbox, no container.
   The simulation layers are **static analysis of manifest text only**. This is the hard line that
   separates us from a sandbox product and keeps the tool safe to run on any machine.
3. **No auto-clone, auto-install, auto-fix, or any write to the user's project.** Read-only, always.
4. **No telemetry, analytics, or phone-home. Ever.**
5. **No network calls other than `api.github.com` and `raw.githubusercontent.com`.**
6. **No malware detection or claimed malware verdict.** We report *install-time code execution* and
   *typosquat proximity* as facts a human judges. We never say "this is malicious" — that is a claim
   we cannot stand behind and it would be the tool's first false accusation.
7. **No free-text semantic understanding of prose.** Pattern matching only; unparseable input returns
   an explicit `unparsed`, never a guess.
8. **No web UI, no server, no dashboard, no hosted service.**
9. **No GitLab / Bitbucket in v1.**
10. **A check that could not run reports `unchecked`, never a pass.** Structural, and now the most
    load-bearing rule in the codebase given how many checks the expansion adds.

## Open questions for the owner

- **Placement:** the AIO placement map has no row for a general (non-lawtech) developer tool.
  Provisionally at `<repo root>/`, consistent with `onbox-rag` and
  `newsletter-automation` precedent. **Needs ratifying, and the map needs the missing row.**
- **Licence for the repo itself** — MIT is the obvious choice for adoption. the owner's call.
- **Public or private** — BUILD ≠ PUSH. Publishing is a separate gate requiring the publication firewall.
