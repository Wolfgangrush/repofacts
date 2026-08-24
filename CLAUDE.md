# repofacts — agent instructions

**Read `BMAD/03-ARCHITECTURE-ESSENTIALS.md` before touching code.** The full record is
`BMAD/02-ARCHITECTURE.md`; the scope contract is `BMAD/01-PRD.md`.

## Scope
Build only what `01-PRD.md` lists. Anything under its **banned scope** heading is deferred,
not discussed.

## Rules for this codebase
1. **Python 3.11+, standard library only.** `dependencies = []` in `pyproject.toml` is
   load-bearing, not incidental: a tool whose subject is dependency risk must not itself be a
   dependency risk. CI fails the build if that list is ever non-empty. Adding a third-party
   import is a scope decision, not a convenience.
2. **Whoever writes an implementation does not write its tests.** Tests are authored against
   the module's contract, independently of the code that satisfies it. No test may be edited
   to make a failing implementation pass — fix the implementation.
3. **Fetchers touch the network; assessors are pure.** `github.py` is the only module allowed
   to make requests or read the clock. `rules.py`, `security.py`, `quality.py`, `simulate.py`,
   `claims.py` and `render.py` are pure functions of the facts handed to them, so every verdict
   is reproducible from a fixture without a network.

## What must never happen here
- **A check that could not run must never render like a check that passed.** Absent data is
  `unchecked`, never `pass`. This is the single invariant the tool exists to protect: it is
  built to catch AI output that states unverified things confidently, so it may never do that
  itself.
- **A token must never reach output.** Tokens are discovered, used as a Bearer header, and
  never serialised — not in the table, not in `--json`, not in `--markdown`, and not inside a
  dependency spec that happens to embed one.
- **A repo must never be silently dropped.** If an input cannot be parsed, it is reported as
  unparsed. Never omitted.

## Verify
```
python3 -m pytest -q && ruff check .
```
Green means 275 tests pass and lint is clean. Every test file must also pass **on its own**
(`pytest tests/test_claims.py`) — `tests/conftest.py` exists to guarantee that.
