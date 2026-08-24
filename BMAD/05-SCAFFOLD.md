# 05 — SCAFFOLD · repofacts

```
repofacts/
  BMAD/                 01..06
  CLAUDE.md             project rules
  AGENTS.md             one line → CLAUDE.md
  README.md             the pitch + the summary-line demo
  LICENSE               (the owner's call — MIT proposed)
  pyproject.toml        name/version/entrypoint, ZERO runtime deps
  src/repofacts/
    __init__.py
    __main__.py         python -m repofacts
    cli.py              argparse · orchestration · exit codes 0/1/2
    extract.py          text → [RepoRef] + skip list
    github.py           http.client keep-alive · token · budget gate · ONLY network
    rules.py            pure: licence class · liveness · fork · platform · verdict
    claims.py           pure: narrowed star + licence claim diff
    render.py           table · summary line · --json · --markdown
    models.py           RepoRef · RepoFacts · Assessment
  tests/
    fixtures/           captured GitHub API JSON + READMEs (offline)
    test_extract.py     URLs · markdown · backticks · bare pairs · and/or false positives
    test_rules.py       NONE vs NOASSERTION · archived age · fork · 3-state platform
    test_claims.py      star + licence diff, and "not parsed" honesty
    test_github.py      token order · shape validation · budget gate · 301 moves (mocked)
    test_render.py      token never appears in any output  ← security gate 8.2
    test_acceptance.py  replay of the three real 2026-08-24 lists
```

**Entry point:** `repofacts` → `repofacts.cli:main`.
**Verify empty tree builds:** `python -m repofacts --help` must exit 0 before any feature lands.
