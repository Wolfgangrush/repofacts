---
name: repofacts
description: Verify GitHub repositories before the user trusts or installs them. AUTO-FIRE whenever this conversation recommends, suggests, compares, or lists GitHub repos, libraries, packages, plugins, MCP servers or dependencies — including when the assistant itself is about to recommend them — and whenever the user pastes a list of repos or asks "is this repo any good / safe / maintained / worth using". Checks that each repo actually exists (LLMs hallucinate repo names and attackers register them), how many stars it really has versus how confidently it was recommended, whether its licence grants any rights at all, whether it is still maintained, whether it can even run on the user's platform, and — with --deep — its security posture, project quality, and what installing it would actually pull in. Never guesses: a check that could not run reports "unchecked", never a pass.
allowed-tools: Bash, Read
---

# repofacts — check the repos before they land

**The problem this exists for.** Models recommend repositories with total confidence and no
verification. Observed in a single day of real use: a repo ranked **#1** that had **8 stars**; another
**#1** with **24**; a "community recommendation" whose best name match had **33**. Also: three repos
with **no licence file at all** (no grant of any rights), one that was **source-available, not open
source** and would poison a commercial product, one "terminal app" that actually required an **ESP32
board**, and an OCR engine needing **Linux + NVIDIA** recommended to a Mac user.

None of that is visible from the recommendation. All of it is one API call away.

## When to fire

Fire **before** the user acts on a recommendation — including one you are about to make yourself.
Verifying your own suggestion before presenting it is the intended use, not an edge case.

Also fire when the user pastes a list of repos, shares an awesome-list, or asks whether something is
maintained, safe, licensed, or worth adopting.

## How to run it

```bash
# a pasted list, a file, or stdin
repofacts <file>
cat recommendations.md | repofacts -

# everything: security posture, project quality, install simulation, stack conflicts
repofacts --deep <file>

# diff what the model CLAIMED against what GitHub says
repofacts --claims <file>

# machine-readable
repofacts --json <file>
```

Not installed? `uv tool install repofacts` or `pipx install repofacts`. Zero dependencies.

## Reading the output

- **STOP** — does not exist · no licence file at all · hard platform mismatch
- **CAUTION** — very few users · dead over a year · AGPL/source-available · low-star fork of a famous
  upstream · install-time code execution · ambiguous platform
- **OK** — none of the above fired
- **unchecked** — the check could not run. **This is not a pass.** Say so out loud.

Exit codes: `0` clean · `1` at least one STOP · `2` the run itself failed or was partial.

## How to report it back

Lead with anything that is **STOP**, and name the reason in plain words. If you recommended a repo
and it came back STOP or CAUTION, **say so plainly and correct yourself** — that is the entire point
of the tool. Do not bury it.

Never present an `unchecked` result as if it passed. Never soften a `no licence file` finding: it
means there is no legal grant to use the code at all, whatever the README implies.
