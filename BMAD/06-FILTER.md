# 06 — FILTER  ·  <project name>

**Date:** YYYY-MM-DD · **Run AFTER the code exists, BEFORE you call anything done.**

> the owner, 2026-08-16, defining it: *"You assess your own work and distill it… Once you have
> built all the 6 files, what happens later? You see the code and restructure it in a way
> that is given in the architecture essentials or architecture.md. Once you do that you
> start to see if there is any mistake in it. If there is, you fix it. Filtering in my
> particular sense meant fixing it in a way that it is following the protocol of
> architecture.md. Once that happens you move on."*

**The filter is a convergence loop, not a selection loop.** It does not choose between
approaches — `01-PRD.md` already did that. It drags the code back onto the architecture it
was supposed to follow, and it is the difference between a codebase and a pile.

Nothing ships with this file unfilled.

---

## Pass 1 — read the code against the architecture

Open `03-ARCHITECTURE-ESSENTIALS.md` and `02-ARCHITECTURE.md`. Then read the code as
written, not as remembered. For every component the architecture names:

| # | Architecture says | Code actually does | Verdict |
|---|---|---|---|
| 1 | | | matches / drifted / missing / extra |

**"Verdict = extra"** is as serious as "missing". Something in the codebase that the
architecture never authorised is scope that arrived without a decision.

## Pass 2 — restructure to match

Move, rename, split and merge until the code's shape IS the architecture's shape. File
layout, module boundaries, type names, direction of dependencies.

| # | Change made | Which architecture line it now obeys |
|---|---|---|

If a restructure turns out to be impossible or plainly wrong, **the architecture was wrong,
not the code** — go and amend `02` and `03`, record it below, and re-run this pass. The
architecture is authoritative but not infallible; what is banned is silent divergence.

| # | Architecture amended | Why the code was right and the doc was wrong |
|---|---|---|

## Pass 3 — now look for mistakes

With the shape correct, defects become visible that were hidden by the mess. Every one gets
fixed here, not filed for later.

| # | Mistake | How found | Fix | Test that now covers it |
|---|---|---|---|---|

## Pass 4 — banned-scope sweep

Re-read the **banned scope** list in `01-PRD.md`. Anything in the code that appears on it
comes out now.

| # | Banned item | Present in code? | Removed / deferred to |
|---|---|---|---|

---

## Exit criteria — all four must be true

- [ ] Every component in `02-ARCHITECTURE.md` maps to code, and every module in the code
      maps back to `02`. No orphans in either direction.
- [ ] `03-ARCHITECTURE-ESSENTIALS.md` still describes the code accurately. If it drifted,
      it has been updated.
- [ ] Nothing from the `01-PRD.md` banned-scope list survives in the tree.
- [ ] Test suite green, and every Pass-3 fix has a test that would catch it returning.

## Verdict

- [ ] **CONVERGED** — code follows the architecture protocol. Move on to `04-BMAD-SPEC.md`
      A and D sections.
- [ ] **ANOTHER PASS NEEDED** — name the one thing still diverging: ______

---

*Where this sits: `00`–`05` are written before code. `06` is written after it. Together they
are the loop — plan, build, then drag the build back onto the plan.*
