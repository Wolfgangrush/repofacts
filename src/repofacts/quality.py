"""Pure quality checks.

This module is **deliberately pure**: it takes a :class:`QualityFacts`
dataclass in, runs a fixed battery of checks, and returns a
:class:`QualityReport`. No network calls, no file I/O, no clock reads
except via a ``now`` argument. All fetching happens in
:mod:`repofacts.github`.

Same non-negotiable invariant as :mod:`repofacts.security`:

    a check that did not run must NEVER render like a check that passed.

Every check therefore returns ``status="unchecked"`` whenever its
required data is ``None`` / empty. ``"unchecked"`` is the explicit
default and is distinct from every other status.

Status values: pass, fail, warn, info, unchecked. Severity: HIGH, MED,
LOW, INFO.
"""

from __future__ import annotations

import json
import re
import statistics
from datetime import datetime, timezone

from .models import (
    Finding,
    QualityReport,
    SEV_INFO,
    SEV_LOW,
    SEV_MED,
    STATUS_FAIL,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_UNCHECKED,
    STATUS_WARN,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _f(name, status, severity, reason):
    """Construct a :class:`Finding`. Centralised so names map 1:1."""
    return Finding(name=name, status=status, severity=severity, reason=reason)


def _resolve_now(q, now):
    """Return ``now`` if supplied, else ``q.fetched_at``."""
    return now if now is not None else q.fetched_at


# 1. TestsPresent
# ---------------------------------------------------------------------------

# Path patterns indicating test files. Each pattern is tested as a
# substring match against the file path, lowercase. We deliberately
# include common conventions across Python, Go, JS/TS, Rust, and Ruby.
_TEST_PATH_PATTERNS = (
    "/tests/",
    "/test/",
    "/__tests__/",
    "/spec/",
)
_TEST_FILENAME_PATTERNS = (
    re.compile(r"^test_[A-Za-z0-9_].*\.py$"),
    re.compile(r".*_test\.go$"),
    re.compile(r".*\.test\.(?:js|ts|jsx|tsx|mjs|cjs)$"),
    re.compile(r".*\.spec\.(?:js|ts|jsx|tsx|mjs|cjs)$"),
    re.compile(r"^test_[A-Za-z0-9_]+\.[A-Za-z]+$"),
    re.compile(r"^Test[A-Z][A-Za-z0-9_]*\.[A-Za-z]+$"),  # Java/Kotlin/C#
)


def _looks_like_test_path(path):
    """Return True if ``path`` looks like a test file."""
    if not isinstance(path, str):
        return False
    lower = path.lower()
    # Anchor a leading slash before the directory match. The patterns are
    # written as "/tests/" etc., so without this a TOP-LEVEL "tests/" —
    # the single most common layout there is — never matched, while the
    # identical nested "pkg/tests/" did. Detection must not depend on
    # nesting depth.
    anchored = lower if lower.startswith("/") else "/" + lower
    for pat in _TEST_PATH_PATTERNS:
        if pat in anchored:
            return True
    base = lower.rsplit("/", 1)[-1]
    for rx in _TEST_FILENAME_PATTERNS:
        if rx.match(base):
            return True
    return False


def _check_tests_present(q):
    """Are there any test files in the tree?"""
    if not q.tree_entries:
        return _f("TestsPresent", STATUS_UNCHECKED, SEV_INFO,
                  "no tree fetched")
    found = [e.get("path", "") for e in q.tree_entries
             if isinstance(e, dict) and _looks_like_test_path(e.get("path"))]
    if found:
        sample = found[0] if found else ""
        return _f("TestsPresent", STATUS_PASS, SEV_INFO,
                  "test files present; first match: " + sample)
    return _f("TestsPresent", STATUS_FAIL, SEV_MED, "no test files found in tree")


# 2. CIConfigured
# ---------------------------------------------------------------------------


def _check_ci_configured(q):
    """Is there at least one GitHub Actions workflow?"""
    if not q.workflow_paths and not q.workflow_files:
        return _f("CIConfigured", STATUS_UNCHECKED, SEV_INFO,
                  "no workflow list fetched")
    count = max(len(q.workflow_paths), len(q.workflow_files))
    if count == 0:
        return _f("CIConfigured", STATUS_FAIL, SEV_LOW,
                  "no .github/workflows present")
    if not q.workflow_files:
        # github.py omits any workflow path whose CONTENT it could not
        # read, precisely so "exists but empty" stays distinguishable
        # from "content not fetched". Paths listed with no contents is the
        # latter: the workflows demonstrably exist, we just cannot judge
        # what is in them. Reporting that as "all empty" asserts a fact we
        # never observed.
        return _f("CIConfigured", STATUS_PASS, SEV_INFO,
                  str(count) + " workflow file(s) present; contents not fetched")
    non_empty = 0
    for text in q.workflow_files.values():
        if text and text.strip():
            non_empty += 1
    if non_empty == 0:
        return _f("CIConfigured", STATUS_FAIL, SEV_LOW,
                  str(count) + " workflow file(s) found but all empty")
    return _f("CIConfigured", STATUS_PASS, SEV_INFO,
              str(non_empty) + " workflow file(s) configured")


# 3. CIStatus
# ---------------------------------------------------------------------------

_PASSING_CONCLUSIONS = {"success", "neutral", "skipped"}
_FAILING_CONCLUSIONS = {"failure", "cancelled", "timed_out", "action_required"}


def _check_ci_status(q):
    """What did the latest check-run on the default branch conclude?"""
    conclusion = q.latest_check_conclusion
    if conclusion is None:
        return _f("CIStatus", STATUS_UNCHECKED, SEV_INFO,
                  "no check-runs (or none fetched)")
    if conclusion in _FAILING_CONCLUSIONS:
        return _f("CIStatus", STATUS_FAIL, SEV_MED,
                  "latest check-run conclusion: " + conclusion)
    if conclusion in _PASSING_CONCLUSIONS:
        return _f("CIStatus", STATUS_PASS, SEV_INFO,
                  "latest check-run: " + conclusion)
    return _f("CIStatus", STATUS_WARN, SEV_LOW,
              "latest check-run has unknown conclusion: " + conclusion)


# 4. Documentation
# ---------------------------------------------------------------------------

_DOC_DIR_NAMES = ("docs", "documentation", "doc")
_EXAMPLE_DIR_NAMES = ("examples", "example", "demo", "samples")


def _has_dir_with_name(q, names):
    """Return True if the tree contains a top-level dir matching any of ``names``."""
    if not q.tree_entries:
        return False
    for entry in q.tree_entries:
        if entry.get("type") != "tree":
            continue
        path = entry.get("path") or ""
        if not isinstance(path, str):
            continue
        first = path.split("/", 1)[0]
        if first.lower() in names:
            return True
    return False


def _check_documentation(q):
    """README length, docs/ dir, examples/ dir."""
    if q.readme_length is None and not q.tree_entries:
        return _f("Documentation", STATUS_UNCHECKED, SEV_INFO,
                  "no README or tree fetched")
    parts: list[str] = []
    if q.readme_length is None:
        # ``readme_length is None`` means the README was NEVER FETCHED
        # (``0`` is the fetched-and-empty case). Collapsing the two with
        # ``or 0`` made an unfetched README render as the hard finding
        # "no README" — an absence asserted from absent data. The
        # dominant input is missing, so the check did not run.
        parts.append("README not fetched")
        parts.append("docs/ present" if _has_dir_with_name(q, _DOC_DIR_NAMES)
                     else "no docs/ dir")
        parts.append("examples/ present"
                     if _has_dir_with_name(q, _EXAMPLE_DIR_NAMES)
                     else "no examples/ dir")
        return _f("Documentation", STATUS_UNCHECKED, SEV_INFO, "; ".join(parts))
    readme_len = q.readme_length
    if readme_len >= 1000:
        parts.append("README is " + str(readme_len) + " chars")
    elif readme_len > 0:
        parts.append("README is short (" + str(readme_len) + " chars)")
    else:
        parts.append("no README")
    if _has_dir_with_name(q, _DOC_DIR_NAMES):
        parts.append("docs/ present")
    else:
        parts.append("no docs/ dir")
    if _has_dir_with_name(q, _EXAMPLE_DIR_NAMES):
        parts.append("examples/ present")
    else:
        parts.append("no examples/ dir")
    if readme_len >= 1000 and _has_dir_with_name(q, _DOC_DIR_NAMES):
        return _f("Documentation", STATUS_PASS, SEV_INFO, "; ".join(parts))
    if readme_len == 0:
        return _f("Documentation", STATUS_FAIL, SEV_LOW, "; ".join(parts))
    return _f("Documentation", STATUS_WARN, SEV_LOW, "; ".join(parts))


# 5. ReleaseCadence
# ---------------------------------------------------------------------------


def _parse_iso_date(s):
    """Return a datetime for ``s`` (ISO-8601 with optional Z), or ``None``."""
    if not isinstance(s, str) or not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _check_release_cadence(q, now):
    """Releases in the trailing 12 months; gaps between releases."""
    if not q.releases:
        return _f("ReleaseCadence", STATUS_UNCHECKED, SEV_INFO,
                  "no release data fetched")
    if now is None:
        return _f("ReleaseCadence", STATUS_UNCHECKED, SEV_INFO,
                  "no `now` available; cannot measure cadence")
    dated = []
    for r in q.releases:
        if not isinstance(r, dict):
            continue
        dt = _parse_iso_date(r.get("published_at"))
        if dt is not None:
            if dt.tzinfo is None:
                # A timestamp without an offset (GitHub normally sends Z,
                # but a mirror/GHES payload may not) used to reach the
                # ``now - d`` subtraction naive while ``now`` had been
                # forced aware, raising TypeError straight out of a pure
                # assessor. Assume UTC, which is what GitHub means.
                dt = dt.replace(tzinfo=timezone.utc)
            dated.append(dt)
    if not dated:
        return _f("ReleaseCadence", STATUS_UNCHECKED, SEV_INFO,
                  "no releases have parseable timestamps")
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    dated.sort()
    recent = [d for d in dated if (now - d).days <= 365]
    if not recent:
        return _f("ReleaseCadence", STATUS_FAIL, SEV_LOW,
                  "no releases in the trailing 12 months")
    # Gaps: max gap in days between consecutive recent releases.
    max_gap = 0
    for prev, nxt in zip(recent, recent[1:]):
        gap = (nxt - prev).days
        if gap > max_gap:
            max_gap = gap
    if len(recent) == 1:
        return _f("ReleaseCadence", STATUS_PASS, SEV_INFO,
                  "1 release in trailing 12 months")
    return _f("ReleaseCadence", STATUS_PASS, SEV_INFO,
              str(len(recent)) + " releases in trailing 12 months; max gap "
              + str(max_gap) + " days")


# 6. SemVerAdherence
# ---------------------------------------------------------------------------

# Captures three numeric components with optional pre-release / build.
_RE_SEMVER = re.compile(
    r"^[vV]?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
)


def _tag_is_semver(tag):
    """Return True if ``tag`` parses as SemVer 2.0.0 (with optional 'v')."""
    return bool(_RE_SEMVER.match(tag.strip())) if isinstance(tag, str) else False


def _check_semver_adherence(q):
    """Do tags parse as SemVer?"""
    if not q.tags:
        return _f("SemVerAdherence", STATUS_UNCHECKED, SEV_INFO,
                  "no tags fetched")
    valid = sum(1 for t in q.tags if _tag_is_semver(t))
    if valid == len(q.tags):
        return _f("SemVerAdherence", STATUS_PASS, SEV_INFO,
                  "all " + str(valid) + " tag(s) parse as SemVer")
    if valid == 0:
        return _f("SemVerAdherence", STATUS_FAIL, SEV_LOW,
                  "no tags parse as SemVer (e.g. " + q.tags[0] + ")")
    return _f("SemVerAdherence", STATUS_WARN, SEV_LOW,
              str(valid) + " of " + str(len(q.tags))
              + " tag(s) parse as SemVer")


# 7. Changelog
# ---------------------------------------------------------------------------


def _check_changelog(q):
    """Is a CHANGELOG (or analogue) present?"""
    v = q.has_changelog
    if v is None:
        return _f("Changelog", STATUS_UNCHECKED, SEV_INFO,
                  "CHANGELOG lookup did not complete")
    if v:
        return _f("Changelog", STATUS_PASS, SEV_INFO, "CHANGELOG present")
    return _f("Changelog", STATUS_WARN, SEV_LOW, "no CHANGELOG found")


# 8. IssueResponsiveness
# ---------------------------------------------------------------------------


def _check_issue_responsiveness(q):
    """Median hours-to-first-response on recent issues."""
    if not q.issue_response_hours:
        return _f("IssueResponsiveness", STATUS_UNCHECKED, SEV_INFO,
                  "no issue-response data fetched")
    median = statistics.median(q.issue_response_hours)
    if median <= 24:
        return _f("IssueResponsiveness", STATUS_PASS, SEV_INFO,
                  "median first-response " + f"{median:.1f}" + " h across "
                  + str(len(q.issue_response_hours)) + " issue(s)")
    if median <= 168:  # 1 week
        return _f("IssueResponsiveness", STATUS_WARN, SEV_LOW,
                  "median first-response " + f"{median:.1f}" + " h across "
                  + str(len(q.issue_response_hours)) + " issue(s)")
    return _f("IssueResponsiveness", STATUS_WARN, SEV_LOW,
              "median first-response " + f"{median:.1f}" + " h across "
              + str(len(q.issue_response_hours)) + " issue(s)")


# 9. ContributorConcentration
# ---------------------------------------------------------------------------


def _check_contributor_concentration(q):
    """Top-1 author share of recent commits."""
    # Prefer recent commits (default branch HEAD); fall back to
    # ``/contributors`` aggregate if no recent commits were fetched.
    if q.recent_commits:
        counts: dict[str, int] = {}
        for c in q.recent_commits:
            if not isinstance(c, dict):
                continue
            author = (c.get("author") or {}).get("login") if isinstance(c.get("author"), dict) else None
            if not author:
                continue
            counts[author] = counts.get(author, 0) + 1
        total = sum(counts.values())
        if total == 0:
            return _f("ContributorConcentration", STATUS_UNCHECKED, SEV_INFO,
                      "recent commits had no parseable authors")
        top = max(counts.values())
        share = top / total
    elif q.contributors:
        agg_counts = [
            int(c.get("contributions", 0))
            for c in q.contributors
            if isinstance(c, dict) and c.get("contributions") is not None
        ]
        total = sum(agg_counts)
        if total == 0:
            return _f("ContributorConcentration", STATUS_UNCHECKED, SEV_INFO,
                      "contributor totals are zero")
        top = max(agg_counts)
        share = top / total
    else:
        return _f("ContributorConcentration", STATUS_UNCHECKED, SEV_INFO,
                  "no recent commits and no contributor data fetched")
    if share > 0.50:
        return _f("ContributorConcentration", STATUS_WARN, SEV_LOW,
                  "top author share " + f"{share:.0%}" + " of recent commits")
    return _f("ContributorConcentration", STATUS_PASS, SEV_INFO,
              "top author share " + f"{share:.0%}" + " of recent commits")


# 10. DependencyWeight
# ---------------------------------------------------------------------------

# Strip comments and strings crudely so regex counts don't include them.
def _strip_comments_and_strings(text):
    """Return ``text`` with // and # line-comments and quoted strings stripped.

    This is a best-effort scrubber for *counting* dependencies. It is not
    a parser; it only needs to ignore comments and string literals.
    """
    # Remove block comments.
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Remove double-quoted strings (handles escaped quotes).
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    # Remove // line comments (JS/TS/Rust).
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    # Remove # line comments (Python/TOML/YAML).
    text = re.sub(r"#.*?$", "", text, flags=re.MULTILINE)
    return text


def _count_python_deps(text):
    """Count direct deps in a Python manifest (pyproject/setup/requirements)."""
    scrubbed = _strip_comments_and_strings(text)
    n = 0
    # pyproject.toml: [tool.poetry.dependencies] or [project] dependencies.
    # Each non-section entry is a name = "version" (poetry) or "name>=1.0"
    # (PEP 621).
    for block in re.findall(
        r"\[tool\.poetry\.dependencies\](.*?)(?=\n\[|$)",
        scrubbed, flags=re.DOTALL):
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                n += 1
    for block in re.findall(
        r"\[project\](.*?)(?=\n\[|$)",
        scrubbed, flags=re.DOTALL):
        # PEP 621 ``dependencies = [...]`` — the array may be on one line
        # or spread over many. The old one-line-only regex silently
        # counted a multi-line array as zero deps, which is a false
        # all-clear on a real manifest.
        m = re.search(r"^[ \t]*dependencies\s*=\s*\[(.*?)\]",
                      block, flags=re.DOTALL | re.MULTILINE)
        if m:
            inner = m.group(1).strip()
            if inner:
                n += len([p for p in inner.split(",") if p.strip()])
    # requirements.txt: one package per line. Only ever apply this to a
    # file that is NOT TOML — a section header at the start of a line is
    # the tell. Keying off "[tool" alone meant a PEP-621-only
    # pyproject.toml (no [tool.*] table at all) fell through to
    # line-counting and reported every line of the file as a dependency.
    is_toml = re.search(r"^[ \t]*\[", scrubbed, flags=re.MULTILINE) is not None
    if not is_toml:
        for line in scrubbed.splitlines():
            line = line.strip()
            if not line or line.startswith("-"):
                continue
            n += 1
    return n


def _count_node_deps(text):
    """Count direct deps in a package.json's dependencies / devDependencies.

    Returns ``None`` if the JSON could not be parsed — a manifest we could
    not read must never be reported as a manifest with zero dependencies.
    """
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    n = 0
    for key in ("dependencies", "optionalDependencies", "peerDependencies"):
        v = data.get(key)
        if isinstance(v, dict):
            n += len(v)
    return n


def _count_cargo_deps(text):
    """Count [dependencies] entries in Cargo.toml."""
    scrubbed = _strip_comments_and_strings(text)
    n = 0
    in_deps = False
    for line in scrubbed.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("["):
            in_deps = s in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]")
            continue
        if in_deps and "=" in s:
            n += 1
    return n


def _count_go_deps(text):
    """Count direct deps in go.mod (``require`` lines)."""
    scrubbed = _strip_comments_and_strings(text)
    n = 0
    in_require = False
    for line in scrubbed.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("require ("):
            in_require = True
            continue
        if s == ")" and in_require:
            in_require = False
            continue
        if s.startswith("require ") or in_require:
            # ``require foo v1.2.3`` or single-line ``require foo v1.2.3``
            parts = s.split()
            if in_require and parts and parts[0] != "require":
                n += 1
            elif s.startswith("require ") and len(parts) >= 3:
                n += 1
    return n


def _check_dependency_weight(q):
    """Total direct deps across all manifests."""
    if not q.manifests:
        return _f("DependencyWeight", STATUS_UNCHECKED, SEV_INFO,
                  "no manifests fetched")
    total = 0
    parsed = 0
    by_manifest: list[str] = []
    unparsed: list[str] = []
    for path, text in q.manifests.items():
        lower = path.lower()
        n = None
        try:
            if lower.endswith("package.json"):
                n = _count_node_deps(text)
            elif lower.endswith("pyproject.toml") or lower.endswith("requirements.txt"):
                n = _count_python_deps(text)
            elif lower.endswith("setup.py"):
                # setup.py install_requires is hard to parse without
                # executing; treat as unknown.
                n = None
            elif lower.endswith("cargo.toml"):
                n = _count_cargo_deps(text)
            elif lower.endswith("go.mod"):
                n = _count_go_deps(text)
        except Exception:
            n = None
        if n is None:
            # Unknown manifest type, or a parser that could not run.
            # Folding this in as a zero is a silent false all-clear.
            unparsed.append(path)
            continue
        parsed += 1
        total += n
        by_manifest.append(path + "=" + str(n))
    if parsed == 0:
        return _f("DependencyWeight", STATUS_UNCHECKED, SEV_INFO,
                  "no parseable manifest among " + str(len(q.manifests))
                  + " fetched (" + ", ".join(sorted(unparsed)) + ")")
    if total == 0:
        return _f("DependencyWeight", STATUS_INFO, SEV_INFO,
                  "0 direct declared dependencies across "
                  + str(parsed) + " parsed manifest(s)")
    if total > 50:
        return _f("DependencyWeight", STATUS_WARN, SEV_LOW,
                  str(total) + " direct deps: " + ", ".join(by_manifest))
    return _f("DependencyWeight", STATUS_PASS, SEV_INFO,
              str(total) + " direct deps: " + ", ".join(by_manifest))


# Top-level entry point
# ---------------------------------------------------------------------------

_CHECK_ORDER = (
    "TestsPresent",
    "CIConfigured",
    "CIStatus",
    "Documentation",
    "ReleaseCadence",
    "SemVerAdherence",
    "Changelog",
    "IssueResponsiveness",
    "ContributorConcentration",
    "DependencyWeight",
)


def assess_quality(q, *, now=None):
    """Run the full battery of quality checks against ``q``.

    Args:
        q: A :class:`QualityFacts` populated by
            :func:`repofacts.github.fetch_quality_facts`.
        now: Optional UTC timestamp for time-based checks (currently
            :func:`_check_release_cadence`). If omitted, ``q.fetched_at``
            is used. The pure module never reads the wall clock; if
            neither ``now`` nor ``q.fetched_at`` is supplied, the
            time-based check returns ``unchecked``.

    Returns:
        A :class:`QualityReport` with one :class:`Finding` per check,
        in declaration order. ``findings`` always contains 10 entries -
        one per check - even when every check was ``unchecked``.
    """
    resolved_now = _resolve_now(q, now)
    checks = [
        _check_tests_present(q),
        _check_ci_configured(q),
        _check_ci_status(q),
        _check_documentation(q),
        _check_release_cadence(q, resolved_now),
        _check_semver_adherence(q),
        _check_changelog(q),
        _check_issue_responsiveness(q),
        _check_contributor_concentration(q),
        _check_dependency_weight(q),
    ]
    if len(checks) != len(_CHECK_ORDER):
        raise AssertionError(
            "quality check count drifted: " + str(len(checks))
            + " vs " + str(_CHECK_ORDER))
    return QualityReport(owner=q.owner, repo=q.repo, findings=checks)
