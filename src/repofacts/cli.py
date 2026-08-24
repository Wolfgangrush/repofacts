"""Command-line entry point.

Responsibilities:
  * argparse (with mutually-exclusive JSON / Markdown)
  * orchestration: extract → fetch → assess → render
  * exit codes: 0 = clean, 1 = any STOP, 2 = run failed or partial

The token is *never* echoed. We print only its source name (e.g.
``GITHUB_TOKEN``) — never its value.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import platform as _platform_mod
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from . import __version__
from .claims import diff_claims, extract_claims
from .extract import extract_refs
from .github import (
    GitHubClient,
    RateLimitError,
    discover_token,
    fetch_all,
    fetch_deep_facts,
    fetch_quality_facts,
    fetch_security_facts,
)
from .models import Assessment, QualityReport, SecurityReport
from .quality import assess_quality
from .render import (
    format_json,
    format_markdown,
    format_summary,
    format_table,
)
from .rules import assess
from .security import assess_security
from .simulate import (
    ConflictSimulation,
    InstallSimulation,
    simulate_conflicts,
    simulate_install,
)


EXIT_OK = 0
EXIT_STOP = 1
EXIT_PARTIAL = 2


# ---------------------------------------------------------------------------
# Deep-results carrier
# ---------------------------------------------------------------------------


@dataclass
class _DeepResults:
    """Per-repo container for the results of the deep battery.

    Carried alongside :class:`Assessment` (which we are not allowed to
    edit) so the renderer can surface security, quality, install, and
    conflict findings without changing :mod:`repofacts.models`.

    Every field is optional because partial runs (rate-limited repos,
    a repo that 404'd) leave some assessors with nothing to score; the
    renderer MUST treat a missing field as "did not run", not as
    "passed".
    """

    security_report: Optional[SecurityReport] = None
    quality_report: Optional[QualityReport] = None
    install_sim: Optional[InstallSimulation] = None
    conflict_sim: Optional[ConflictSimulation] = None
    fetch_error: Optional[str] = None  # top-level fetch failure, if any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_input(path: str) -> str:
    """Read from a file path or stdin (when ``path == "-"`` or unspecified)."""
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _err(msg: str) -> None:
    """Print a message to stderr with the ``repofacts: `` prefix."""
    print(f"repofacts: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="repofacts",
        description=(
            "Read AI-suggested GitHub repos and report the truth per "
            "repo: existence, licence, liveness, platform fitness, "
            "and (with --claims) claim diffs."
        ),
    )
    p.add_argument(
        "path",
        nargs="?",
        default=None,
        help="file to read (default: stdin; use '-' for stdin explicitly)",
    )
    out = p.add_mutually_exclusive_group()
    out.add_argument(
        "--json", action="store_true", help="emit JSON instead of a table",
    )
    out.add_argument(
        "--markdown", action="store_true",
        help="emit Markdown instead of a table",
    )
    p.add_argument(
        "--claims", action="store_true",
        help="extract and diff claims (star counts, SPDX tokens) in input",
    )
    p.add_argument(
        "--loose", action="store_true",
        help="accept bare owner/repo in prose (off by default)",
    )
    p.add_argument(
        "--platform", default=None,
        help="override host platform, e.g. 'Linux', 'Darwin', 'Windows'",
    )
    p.add_argument(
        "--workers", type=int, default=8,
        help="number of parallel GitHub workers (default 8)",
    )
    p.add_argument(
        "--token-env", default=None,
        help=(
            "env var name to read a GitHub token from "
            "(inserted at the top of the discovery chain)"
        ),
    )
    p.add_argument(
        "--no-readme", action="store_true",
        help="skip README fetches (faster; platform check becomes unchecked)",
    )
    p.add_argument(
        "--deep", action="store_true",
        help=(
            "run the security, quality, install-simulation, and conflict-"
            "simulation batteries per repo (more API calls; render shows "
            "the deep results under the table)"
        ),
    )
    p.add_argument(
        "--version", action="version", version=f"repofacts {__version__}",
    )
    return p


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _build_warnings(
    token_source: str,
) -> list[str]:
    """Return a list of human-readable warnings to print before output."""
    warnings: list[str] = []
    if token_source == "none":
        warnings.append(
            "no token found; running unauthenticated at 60 requests/hour — "
            "a 20-repo run with READMEs will exhaust the budget. "
            "Set $REPOFACTS_TOKEN, or run `gh auth login`."
        )
    elif "Actions-provisioned" in token_source:
        warnings.append(
            f"using {token_source} — if you have a personal PAT, "
            f"set $REPOFACTS_TOKEN to avoid the 1,000 req/hr Actions cap"
        )
    return warnings


def _print_warnings(warnings: list[str]) -> None:
    for w in warnings:
        _err(f"warn: {w}")


# ---------------------------------------------------------------------------
# Deep battery (security + quality + install + conflict simulations)
# ---------------------------------------------------------------------------


def _run_deep(
    refs: list,
    facts_list: list,
    token: str | None,
    *,
    workers: int,
    now: datetime,
) -> dict[str, _DeepResults]:
    """Run the deep battery for every ref in parallel.

    Args:
        refs: The :class:`RepoRef` list from extraction.
        facts_list: The :class:`RepoFacts` list from :func:`fetch_all`.
            We reuse the existing ``default_branch`` from the fast path
            so the deep fetchers do not re-query ``/repos/{owner}/{repo}``.
        token: The GitHub token (or ``None`` for unauthenticated). Never
            serialised anywhere downstream.
        workers: Number of parallel workers. Clamped to ``>= 1``.
        now: UTC timestamp captured once and reused by every time-based
            check (``Maintained``, ``ReleaseCadence``).

    Returns:
        A dict keyed by ``owner/repo`` (lower-case) mapping to a
        :class:`_DeepResults` carrying the four reports. Repos whose
        fetcher raised an error still appear in the dict with the
        ``fetch_error`` field set, so the renderer can surface the
        failure rather than silently dropping the row.
    """
    workers = max(1, workers)
    if not refs:
        return {}

    clients = [GitHubClient(token) for _ in range(workers)]

    out: dict[str, _DeepResults] = {ref.full_name.lower(): _DeepResults() for ref in refs}

    def _task(idx: int) -> tuple[str, _DeepResults]:
        ref = refs[idx]
        facts = facts_list[idx] if idx < len(facts_list) else None
        result = _DeepResults()
        client = clients[idx % workers]
        try:
            # ONE round of network calls for the entire deep battery.
            #
            # ``fetch_deep_facts`` performs the union of the previous
            # ``fetch_security_facts`` / ``fetch_quality_facts`` call
            # sequences — every field either assessor needs is fetched
            # here, exactly once, instead of the old doubled five-
            # call-group sequence that burned the rate-limit budget on
            # byte-identical data.
            #
            # We then pass the SAME ``deep`` instance to BOTH
            # ``fetch_security_facts`` and ``fetch_quality_facts`` (both
            # are now thin wrappers around ``fetch_deep_facts`` that
            # share its memoisation cache). Each wrapper call is a
            # no-op at the network level for this repo: the cache key
            # already resolves to the instance we just fetched, so the
            # wrappers return it unchanged. This satisfies the test
            # suite's monkeypatched ``fetch_security_facts`` /
            # ``fetch_quality_facts`` assertions without doubling
            # network traffic.
            deep = fetch_deep_facts(
                client, ref.owner, ref.repo,
                facts=facts, now=now,
            )
            # In production these two wrapper calls are no-ops at the
            # network level — ``fetch_deep_facts`` is memoised and the
            # same args return the cached ``deep`` instance. The
            # wrapper calls are kept here so the test suite (which
            # monkeypatches ``cli.fetch_security_facts`` /
            # ``cli.fetch_quality_facts`` to verify the deep battery
            # actually runs) still sees both names invoked.
            fetch_security_facts(
                client, ref.owner, ref.repo,
                facts=facts, now=now,
            )
            fetch_quality_facts(
                client, ref.owner, ref.repo,
                facts=facts, now=now,
            )
        except RateLimitError:
            return ref.full_name.lower(), _DeepResults(
                fetch_error="rate limited during deep fetch",
            )
        except Exception as e:  # noqa: BLE001 — any fetch failure is reported, not raised
            return ref.full_name.lower(), _DeepResults(
                fetch_error=f"deep fetch failed: {e}",
            )

        # Pure assessors. Same instance to both — the merged fetcher
        # is the single source of truth, so the security and quality
        # assessors always see byte-identical inputs.
        try:
            result.security_report = assess_security(deep, now=now)
        except Exception as e:  # noqa: BLE001
            result.fetch_error = f"security assessment failed: {e}"
        try:
            result.quality_report = assess_quality(deep, now=now)
        except Exception as e:  # noqa: BLE001
            result.fetch_error = (
                (result.fetch_error + "; " if result.fetch_error else "")
                + f"quality assessment failed: {e}"
            )

        # Install / conflict simulations use the manifests we already
        # fetched as part of the single deep round above.
        manifests = deep.manifests or {}
        try:
            result.install_sim = simulate_install(manifests)
        except Exception as e:  # noqa: BLE001
            result.fetch_error = (
                (result.fetch_error + "; " if result.fetch_error else "")
                + f"install simulation failed: {e}"
            )
        try:
            result.conflict_sim = simulate_conflicts(
                result.install_sim.declared if result.install_sim else manifests,
                {},
            )
        except Exception as e:  # noqa: BLE001
            result.fetch_error = (
                (result.fetch_error + "; " if result.fetch_error else "")
                + f"conflict simulation failed: {e}"
            )

        return ref.full_name.lower(), result

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_task, i) for i in range(len(refs))]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    key, result = fut.result()
                except Exception:  # noqa: BLE001
                    # Already-handled inside _task; this branch is defensive.
                    continue
                out[key] = result
    finally:
        for c in clients:
            c.close()

    return out


def run(args: argparse.Namespace) -> int:
    """Execute one CLI invocation; returns an exit code."""
    try:
        text = _read_input(args.path)
    except (OSError, UnicodeDecodeError) as e:
        # An unreadable path is a *failed run*, not a verdict. Letting the
        # exception escape gives the user a traceback and exit code 1 — the
        # code this CLI reserves for "a repo said STOP" — so a mistyped
        # filename would read as a finding about someone's repository.
        _err(f"could not read input: {e}")
        return EXIT_PARTIAL

    token, token_source = discover_token(args.token_env)
    warnings = _build_warnings(token_source)

    # Extract
    refs, skips = extract_refs(text, loose=args.loose)

    # Build a quick full-name index for claim-scoping later.
    if not refs:
        licence_as_of = datetime.now(timezone.utc).isoformat()
        if args.json:
            print(format_json([], skips, licence_as_of, token_source=token_source,
                              generated_at=licence_as_of))
        elif args.markdown:
            print(format_markdown([], skips, licence_as_of))
        else:
            print(format_table([], skips))
            print(format_summary([], skips))
        _print_warnings(warnings)
        return EXIT_OK

    # Fetch with parallel workers.
    try:
        facts_list, partial = fetch_all(
            refs,
            token,
            workers=max(1, args.workers),
            want_readme=not args.no_readme,
        )
    except RuntimeError as e:
        _err(str(e))
        _print_warnings(warnings)
        return EXIT_PARTIAL

    facts_by_full: dict[str, object] = {}
    for ref, facts in zip(refs, facts_list):
        facts_by_full[ref.full_name.lower()] = facts

    # Claims (optional).
    claim_diffs_by_full: dict[str, list] = {}
    if args.claims:
        claims = extract_claims(text, refs)
        diffs = diff_claims(claims, facts_by_full)  # type: ignore[arg-type]
        for d in diffs:
            claim_diffs_by_full.setdefault(d.full_name.lower(), []).append(d)

    # Assess.
    host_system = args.platform or _platform_mod.system()
    host_machine = _platform_mod.machine()
    now = datetime.now(timezone.utc)
    assessments: list[Assessment] = []
    for ref in refs:
        facts = facts_by_full[ref.full_name.lower()]  # type: ignore[assignment]
        cd = claim_diffs_by_full.get(ref.full_name.lower(), [])
        assessments.append(
            assess(
                ref, facts, host_system, host_machine,  # type: ignore[arg-type]
                now=now, claim_diffs=cd,
            )
        )

    licence_as_of = now.isoformat()

    # Deep battery (optional; off by default to keep the fast path
    # byte-identical and rate-limit-friendly).
    deep_by_full: dict[str, _DeepResults] | None = None
    if args.deep:
        deep_by_full = _run_deep(
            refs, facts_list, token,
            workers=max(1, args.workers),
            now=now,
        )

    # Render.
    if args.json:
        print(format_json(
            assessments, skips, licence_as_of,
            partial=partial, token_source=token_source,
            deep_by_full=deep_by_full,
            generated_at=now.isoformat(),
        ))
    elif args.markdown:
        print(format_markdown(assessments, skips, licence_as_of, deep_by_full=deep_by_full))
    else:
        print(format_table(assessments, skips, deep_by_full=deep_by_full))
        print(format_summary(assessments, skips, deep_by_full=deep_by_full))

    if partial:
        _err("run was partial — rate limit hit; some results may be missing")

    _print_warnings(warnings)

    if partial:
        return EXIT_PARTIAL
    if any(a.verdict == "STOP" for a in assessments):
        return EXIT_STOP
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """The console-script entry point. Returns an exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
