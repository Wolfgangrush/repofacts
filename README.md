# repofacts

An AI recommends ten GitHub repos. One doesn't exist, one has no licence file, one has been dead for two years. `repofacts` reads the recommendation and tells you which is which, before you install anything.

```
$ repofacts recommendations.md
verdict  repo                            stars  licence     platform       reason
-------  ------------------------------  -----  ----------  -------------  -----------------------------------------------
STOP     av/facts                        199    NONE        checked_clear  no licence file at all — no grant of any rights
STOP     someorg/does-not-exist-xyz-123  —      NONE        unchecked      repo not found on GitHub
CAUTION  suno-ai/bark                    39251  PERMISSIVE  checked_clear  last push ~2.0y ago
OK       google/osv-scanner              10912  PERMISSIVE  checked_clear  —
OK       ossf/scorecard                  5649   PERMISSIVE  checked_clear  —
repofacts: 5 checked · 1 missing · 1 dead>1y · 1 no-licence · 2 STOP · 1 CAUTION
```

Exit code 1, because something said STOP. So it works in a shell script or CI job.

## What it does

Give it a file or pipe it text — a chat log, a markdown list, your notes. It pulls out every GitHub repo reference, calls the GitHub API for each, and prints one verdict per repo: `STOP`, `CAUTION`, or `OK`.

Each repo gets checked for:

- **Exists.** Models invent repo names. Attackers register the invented ones.
- **Licence class** — `NONE`, `UNRECOGNISED`, `PERMISSIVE`, `COPYLEFT`, `NETWORK_COPYLEFT`, `SOURCE_AVAILABLE`.
- **Stars and forks.**
- **Last push.** Anything over a year shows up as `dead>1y`.
- **Archived.** If GitHub knows the successor repo, it names it.
- **Fork-of.** A low-star fork gets flagged, because its README is usually copied from upstream and reads better than the fork deserves.
- **Platform fit.** Reads the README for hard requirements — CUDA, NVIDIA, TensorRT, ROCm, ESP32, Arduino, Raspberry Pi, Linux-only, Windows-only, macOS-only — and compares them to your machine. Three states: `checked_clear`, `checked_conflict`, `unchecked`.

A repo with **no licence file at all** is a `STOP`, not a warning. There is no grant of rights, whatever the README implies. That is a different thing from `UNRECOGNISED`, where a licence file exists but GitHub couldn't identify it.

Text that looks like a package name rather than a repo gets listed separately under `skipped:` instead of being silently dropped.

## Checking what the model claimed

`--claims` pulls the star counts and licence names out of the text itself and diffs them against reality:

```
$ cat notes.md
You should use `suno-ai/bark`. It is Apache-2.0 licensed.

For scorecards, `ossf/scorecard` is the standard, around 4.5k stars.

$ repofacts --claims notes.md
verdict  repo            stars  licence     platform       reason
-------  --------------  -----  ----------  -------------  -----------------------------------------------------------------------------------------------------------------
CAUTION  ossf/scorecard  5649   PERMISSIVE  checked_clear  claimed 4500 stars on line 3, actual 5649
CAUTION  suno-ai/bark    39251  PERMISSIVE  checked_clear  last push ~2.0y ago; claimed licence Apache-2.0 on line 1, actual MIT; claimed 4500 stars on line 3, actual 39251

skipped:
  should (line 1): looks like a package name, not checked
  licensed (line 1): looks like a package name, not checked
repofacts: 2 checked · 2 skipped · 1 dead>1y · 0 STOP · 2 CAUTION
```

The licence catch is the useful one: the text said Apache-2.0, GitHub says MIT.

That output also shows both of this feature's rough edges honestly. The `4500 stars` claim from line 3 gets reported against `suno-ai/bark` on line 1 as well, because claims attach to any repo within two lines. And `should` and `licensed` are ordinary English words sitting in the skipped list. Read the line numbers before acting on a claim diff.

## Going deeper

`--deep` adds security, quality, install-simulation and conflict-simulation batteries per repo. It costs a lot more API calls, so it is off by default. Full real output for one repo:

```
$ echo 'check `ossf/scorecard`' | repofacts --deep -
verdict  repo            stars  licence     platform       reason
-------  --------------  -----  ----------  -------------  ------
OK       ossf/scorecard  5649   PERMISSIVE  checked_clear  —     

  SECURITY:
    - BranchProtection  [unchecked]  INFO  no branch-protection payload (404 or no permission)
    - SecurityPolicy  [pass]  INFO  SECURITY.md present
    - SignedReleases  [pass]  INFO  10 of 10 recent releases have signatures/attestations
    - DangerousWorkflow  [FAIL]  HIGH  uses pull_request_target trigger; offenders: .github/workflows/verify.yml
    - TokenPermissions  [pass]  INFO  top-level `permissions:` declared in 13 workflow(s)
    - PinnedDependencies  [FAIL]  MED  floating-tag Actions: .github/workflows/goreleaser.yaml@v2.1.0
    - BinaryArtifacts  [warn]  LOW  committed binary artifacts: checks/testdata/binaryartifacts/jars/aws-java-sdk-core-1.11.571.jar, checks/testdata/binaryartifacts/jars/gradle-wrapper.jar
    - Contributors  [pass]  INFO  top author share 40% across 100 contributor(s)
    - DependencyUpdateTool  [pass]  INFO  Dependabot config found
    - InstallTimeExecution  [pass]  INFO  1 manifest(s) scanned, no install-time execution
    - Maintained  [pass]  INFO  13 commit(s) in trailing 90 days
  QUALITY:
    - TestsPresent  [pass]  test files present; first match: attestor/command/cli_test.go
    - CIConfigured  [pass]  14 workflow file(s) configured
    - CIStatus  [pass]  latest check-run: success
    - Documentation  [pass]  README is 63295 chars; docs/ present; no examples/ dir
    - ReleaseCadence  [pass]  3 releases in trailing 12 months; max gap 160 days
    - SemVerAdherence  [pass]  all 30 tag(s) parse as SemVer
    - Changelog  [warn]  no CHANGELOG found
    - IssueResponsiveness  [pass]  median first-response 0.4 h across 1 issue(s)
    - ContributorConcentration  [warn]  top author share 61% of recent commits
    - DependencyWeight  [warn]  296 direct deps: go.mod=296
  INSTALL SIMULATION:
    - declared dependency count: 296
    - surface: huge surface - 296 declared deps; treat as a supply-chain hot zone
    - install-time execution findings: 0
    - unpinned versions: 0
    - typosquat-proximity hits: 0
  CONFLICTS:
    - version conflicts against installed packages: 0
    - new surface added (296): cloud.google.com/go/bigquery@1.73.1, cloud.google.com/go/monitoring@1.24.3, cloud.google.com/go/pubsub@1.50.1, cloud.google.com/go/trace@1.11.7, contrib.go.opencensus.io/exporter/stackdriver@0.13.14 (+291 more)
repofacts: 1 checked · 0 STOP · 0 CAUTION · 2 security-fail · 1 security-unchecked
```

Two real findings there on a well-run Google-adjacent project: a workflow using the `pull_request_target` trigger, and an Action pinned to a floating tag rather than a SHA. `BranchProtection` says `unchecked` because the API wouldn't return that payload without admin rights — it is not a pass.

Full check list:

- **Security** — BranchProtection, SecurityPolicy, SignedReleases, DangerousWorkflow, TokenPermissions, PinnedDependencies, BinaryArtifacts, Contributors, DependencyUpdateTool, InstallTimeExecution, Maintained
- **Quality** — TestsPresent, CIConfigured, CIStatus, Documentation, ReleaseCadence, SemVerAdherence, Changelog, IssueResponsiveness, ContributorConcentration, DependencyWeight
- **Install simulation** — declared dependency count, surface size, install-time execution, unpinned versions, typosquat proximity
- **Conflict simulation** — how much new transitive surface you'd take on, and duplicate-purpose
  warnings across the declared set

## Install

**Not on PyPI yet.** `uv tool install repofacts` and `pipx install repofacts` will fail — the name is unregistered.

From the project directory:

```
uv tool install .
```

Or run it without installing anything:

```
PYTHONPATH=src python3 -m repofacts recommendations.md
```

Python 3.11+. No runtime dependencies — standard library only. A tool about dependency risk shouldn't add any.

## Use

```
repofacts recommendations.md          # from a file
cat chat.md | repofacts               # from stdin
repofacts --claims chat.md            # diff what the model said against reality
repofacts --deep --workers 4 list.md  # full battery, 4 parallel workers
repofacts --json list.md              # machine-readable
```

| Flag | What it does |
|---|---|
| `path` | File to read. Defaults to stdin; `-` means stdin explicitly. |
| `--json` | JSON instead of a table. |
| `--markdown` | Markdown instead of a table. |
| `--claims` | Diff star-count and SPDX licence claims found in the input. |
| `--loose` | Also accept bare `owner/repo` in prose. Off by default. |
| `--platform` | Override the host platform: `Linux`, `Darwin`, `Windows`. |
| `--workers` | Parallel GitHub workers. Default 8. |
| `--token-env` | Name of an env var to read the token from, tried first. |
| `--no-readme` | Skip README fetches. Faster, but the platform check becomes `unchecked`. |
| `--deep` | Run the security, quality, install and conflict batteries. |
| `--version` | Print the version. |

`--json` and `--markdown` cannot be used together.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing said STOP. |
| `1` | At least one STOP. |
| `2` | The run failed or was incomplete — unreadable input, or not enough GitHub rate-limit budget to finish. |

Exit 2 is never a verdict about a repository. It means the tool couldn't do its job.

## GitHub token

Without a token GitHub gives you 60 requests an hour, and a 20-repo run with READMEs will burn through it. Token lookup order:

`$REPOFACTS_TOKEN` → `$GH_TOKEN` → `$GITHUB_TOKEN` → `gh auth token` → unauthenticated

The token value is never printed. Only the name of where it came from.

## What it does not do

- **It never runs, installs, or builds anything.** The install and conflict simulations are static reads of manifest text — `go.mod`, `package.json`, `setup.py`, `Cargo.toml`. Safe to point at a repo you don't trust. That's the whole idea.
- **No LLM inside.** A tool that checks AI output must not hallucinate. Same input, same output.
- **It never calls a repo malicious.** It reports install-time execution and typosquat proximity as facts. The judgement is yours.
- **A check that couldn't run prints `unchecked`, never a pass.** Missing data is not a green light.
- **`--claims` is narrow.** It parses two shapes only: star counts and SPDX licence tokens. Everything else is left alone rather than guessed at.
- **`--claims` can mis-attribute.** It attaches a claim to any repo mentioned within two lines of it, so in a dense numbered list one star count may be reported against several repos. Check the line number in the reason column before acting on a claim diff.
- **The `skipped:` list is noisy.** It errs toward showing you candidate package names, so common words like `install` and `client` turn up there too.
- **GitHub only.** No GitLab, no Bitbucket, no PyPI or npm registry lookups.
- **Conflict simulation does not yet read your environment.** It reports the new surface a repo
  would add, but it does not know which packages you already have installed, so the
  "version conflicts" line is always `0`. The comparison engine exists and is tested; what is
  missing is the host-inspection step that would feed it. Treat that line as not-yet-implemented
  rather than as a clean bill of health.
- **Bare `owner/repo` in prose is ignored** unless you pass `--loose`, because `and/or` and `24/08` look identical to a repo reference.

## Status

Version 0.1.0. 275 tests pass, lint clean, zero runtime dependencies. On GitHub; not published
to PyPI.
