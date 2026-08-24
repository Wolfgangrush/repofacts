"""Pure security checks.

This module is **deliberately pure**: it takes a :class:`SecurityFacts`
dataclass in, runs a fixed battery of checks, and returns a
:class:`SecurityReport`. No network calls, no file I/O, no clock reads
except via a ``now`` argument. All fetching happens in
:mod:`repofacts.github`.

The non-negotiable invariant, same as :mod:`repofacts.rules` for
``platform_check``: a check that did not run must NEVER render like a
check that passed. Every check therefore returns ``status="unchecked"``
whenever its required data is ``None`` / empty.

Status values: pass, fail, warn, info, unchecked. Severity: HIGH, MED,
LOW, INFO.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .models import (
    Finding,
    SecurityFacts,
    SecurityReport,
    SEV_HIGH,
    SEV_INFO,
    SEV_LOW,
    SEV_MED,
    STATUS_FAIL,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_UNCHECKED,
    STATUS_WARN,
)


def _f(name, status, severity, reason):
    """Construct a :class:`Finding`. Centralised so names map 1:1."""
    return Finding(name=name, status=status, severity=severity, reason=reason)


def _resolve_now(sec, now):
    """Return ``now`` if supplied, else ``sec.fetched_at``.

    The pure module never reads the wall clock. If both are ``None``,
    time-based checks return ``unchecked``.
    """
    return now if now is not None else sec.fetched_at


# 1. BranchProtection
# ---------------------------------------------------------------------------


def _check_branch_protection(sec):
    """Score the default branch's branch-protection state.

    Returns one of:
        * ``unchecked`` -- no protection payload available.
        * ``fail`` / HIGH -- object exists but disabled, or zero required reviews.
        * ``warn`` / MED -- protected but no required reviewers block.
        * ``pass`` / INFO -- protected with required reviewers.
    """
    prot = sec.branch_protection
    if prot is None:
        return _f("BranchProtection", STATUS_UNCHECKED, SEV_INFO,
                  "no branch-protection payload (404 or no permission)")
    enabled = bool(prot.get("enabled", True))
    if not enabled:
        return _f("BranchProtection", STATUS_FAIL, SEV_HIGH,
                  "branch protection object exists but is not enabled")
    reviews = prot.get("required_pull_request_reviews") or {}
    required = reviews.get("required_approving_review_count")
    if required is None:
        return _f("BranchProtection", STATUS_WARN, SEV_MED,
                  "default branch protected but no required reviewers")
    if isinstance(required, int) and required <= 0:
        return _f("BranchProtection", STATUS_FAIL, SEV_HIGH,
                  "branch protection present but zero required reviews")
    return _f("BranchProtection", STATUS_PASS, SEV_INFO,
              "default branch protected; requires " + str(required) + " review(s)")


# 2. SecurityPolicy
# ---------------------------------------------------------------------------


def _check_security_policy(sec):
    """Did we find a ``SECURITY.md``?"""
    v = sec.has_security_policy
    if v is None:
        return _f("SecurityPolicy", STATUS_UNCHECKED, SEV_INFO,
                  "SECURITY.md lookup did not complete")
    if not v:
        return _f("SecurityPolicy", STATUS_FAIL, SEV_MED,
                  "no SECURITY.md (no vulnerability disclosure path)")
    return _f("SecurityPolicy", STATUS_PASS, SEV_INFO, "SECURITY.md present")


# 3. SignedReleases
# ---------------------------------------------------------------------------

_SIGNATURE_FILENAME_PATTERNS = (
    re.compile(r"\.(sig|asc|intoto\.jsonl|pem|bundle)$", re.IGNORECASE),
    re.compile(r"\.sigstore\.json$", re.IGNORECASE),
)
_SIGNATURE_CONTENT_TYPES = (
    "application/pgp-signature",
    "application/vnd.in-toto+json",
    "application/vnd.dev.sigstore.bundle",
)


def _release_has_signature(rel):
    """Return True if ``rel`` looks like a signed release."""
    assets = rel.get("assets") or []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name") or ""
        ctype = (asset.get("content_type") or "").lower()
        for pat in _SIGNATURE_FILENAME_PATTERNS:
            if pat.search(name):
                return True
        if any(t in ctype for t in _SIGNATURE_CONTENT_TYPES):
            return True
    return False


def _check_signed_releases(sec):
    """Did recent releases carry signature or attestation assets?"""
    if not sec.releases:
        return _f("SignedReleases", STATUS_INFO, SEV_INFO, "no releases to check")
    signed = sum(1 for r in sec.releases if _release_has_signature(r))
    if signed > 0:
        return _f("SignedReleases", STATUS_PASS, SEV_INFO,
                  str(signed) + " of " + str(len(sec.releases))
                  + " recent releases have signatures/attestations")
    return _f("SignedReleases", STATUS_WARN, SEV_MED,
              str(len(sec.releases)) + " recent releases lack signatures/attestations")


# 4. DangerousWorkflow
# ---------------------------------------------------------------------------

#: Mapping form -- ``on:\n  pull_request_target:\n    types: [...]``.
_RE_PR_TARGET = re.compile(r"(?m)^\s*pull_request_target\s*:")
#: Scalar and flow-list forms -- ``on: pull_request_target`` and
#: ``on: [push, pull_request_target]``. Neither ends in a colon, so
#: ``_RE_PR_TARGET`` alone misses both and the check would report a
#: genuinely dangerous workflow as ``pass``. The ``^\s*on\s*:`` anchor
#: keeps this off ``run:``/``name:`` lines that merely mention the string.
_RE_PR_TARGET_ON_VALUE = re.compile(
    r"(?m)^\s*on\s*:[^\n]*\bpull_request_target\b")
#: Block-list form -- ``on:\n  - push\n  - pull_request_target``.
_RE_PR_TARGET_LIST_ITEM = re.compile(
    r"(?m)^\s*-\s*pull_request_target\s*(?:#.*)?$")
_RE_EVENT_INTERP = re.compile(r"\$\{\{\s*github\.event\.")
# Match both ``run:`` and the YAML list form ``- run:``.
_RE_RUN_KEY = re.compile(r"^\s*(?:-\s+)?run\s*:")
_RE_INDENT = re.compile(r"^(\s*)")


def _workflow_has_dangerous(text):
    """Return a human-readable reason if ``text`` looks dangerous.

    Two checks:

      * ``pull_request_target`` as a trigger, in any of the four spellings
        GitHub accepts (mapping, scalar, flow list, block list).
      * ``${{ github.event.* }}`` interpolated into a ``run:`` block.
    """
    if (_RE_PR_TARGET.search(text)
            or _RE_PR_TARGET_ON_VALUE.search(text)
            or _RE_PR_TARGET_LIST_ITEM.search(text)):
        return "uses pull_request_target trigger"
    in_run = False
    run_indent = None
    for line in text.splitlines():
        m_indent = _RE_INDENT.match(line)
        indent = len(m_indent.group(1)) if m_indent else 0
        stripped = line.strip()
        if in_run:
            if run_indent is not None and indent <= run_indent and stripped:
                in_run = False
                run_indent = None
        if _RE_RUN_KEY.match(line):
            in_run = True
            run_indent = indent
            # Inline ``run: echo ${{ github.event.x }}`` form.
            if _RE_EVENT_INTERP.search(line):
                return "uses ${{ github.event.* }} inside a run: block (script injection)"
            continue
        if in_run and _RE_EVENT_INTERP.search(line):
            return "uses ${{ github.event.* }} inside a run: block (script injection)"
    return None


def _check_dangerous_workflow(sec):
    """Any workflow using dangerous patterns?"""
    if not sec.workflow_files:
        return _f("DangerousWorkflow", STATUS_UNCHECKED, SEV_INFO, "no workflows fetched")
    bad_files = []
    reasons = []
    for path, text in sec.workflow_files.items():
        reason = _workflow_has_dangerous(text)
        if reason:
            bad_files.append(path)
            reasons.append(reason)
    if bad_files:
        return _f("DangerousWorkflow", STATUS_FAIL, SEV_HIGH,
                  reasons[0] + "; offenders: " + ", ".join(bad_files))
    return _f("DangerousWorkflow", STATUS_PASS, SEV_INFO,
              str(len(sec.workflow_files)) + " workflow(s) scanned, no dangerous patterns")


# 5. TokenPermissions
# ---------------------------------------------------------------------------

_RE_TOP_PERMS = re.compile(r"(?m)^\s*permissions\s*:")


def _workflow_has_top_level_permissions(text):
    """Return True if ``text`` declares a top-level ``permissions:`` block.

    Job-level ``permissions:`` blocks (indented under a ``jobs.<name>``
    key) do NOT count: only the file-level one scopes the implicit
    ``GITHUB_TOKEN`` to least-privilege for every step.
    """
    lines = text.splitlines()
    jobs_indent = None
    for line in lines:
        s = line.lstrip()
        if s.startswith("jobs:") or s.startswith("jobs "):
            m_indent = _RE_INDENT.match(line)
            jobs_indent = len(m_indent.group(1)) if m_indent else 0
            break
    for line in lines:
        if not _RE_TOP_PERMS.match(line):
            continue
        m_indent = _RE_INDENT.match(line)
        perms_indent = len(m_indent.group(1)) if m_indent else 0
        # Top-level means at the same indent as ``jobs:`` (or shallower,
        # which doesn't normally happen but we accept it).
        if jobs_indent is None or perms_indent <= jobs_indent:
            return True
    return False


def _check_token_permissions(sec):
    """Do any workflows declare a top-level ``permissions:`` block?

    The GitHub Actions default for ``GITHUB_TOKEN`` is *write-all* on
    every scope. A single ``permissions:`` line at the top of the file
    downgrades the token to whatever scopes the workflow asks for.
    """
    if not sec.workflow_files:
        return _f("TokenPermissions", STATUS_UNCHECKED, SEV_INFO, "no workflows fetched")
    declared = [
        path for path, text in sec.workflow_files.items()
        if _workflow_has_top_level_permissions(text)
    ]
    if declared:
        return _f("TokenPermissions", STATUS_PASS, SEV_INFO,
                  "top-level `permissions:` declared in "
                  + str(len(declared)) + " workflow(s)")
    return _f("TokenPermissions", STATUS_WARN, SEV_MED,
              "no workflow declares a top-level `permissions:` block (default is write-all)")


# 6. PinnedDependencies
# ---------------------------------------------------------------------------

_RE_USES = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*([^@\s]+)@([^\s#]+)")
_RE_SHA = re.compile(r"^[0-9a-f]{40}$")


def _uses_pinned_sha(uses_line):
    """Return ``(is_pinned, ref)`` for a single ``uses:`` line.

    Local actions (``./foo``) are considered "not a dependency" and we
    return ``(True, ref)`` so they do not drag the score down.
    """
    m = _RE_USES.match(uses_line)
    if not m:
        return True, ""
    name, ref = m.group(1), m.group(2)
    if name.startswith("./") or name.startswith("docker://"):
        return True, ref
    if _RE_SHA.match(ref):
        return True, ref
    return False, ref


def _check_pinned_dependencies(sec):
    """Are third-party GitHub Actions pinned to a full commit SHA?"""
    if not sec.workflow_files:
        return _f("PinnedDependencies", STATUS_UNCHECKED, SEV_INFO, "no workflows fetched")
    floating = []
    for path, text in sec.workflow_files.items():
        for raw in text.splitlines():
            if "uses:" not in raw:
                continue
            ok, ref = _uses_pinned_sha(raw)
            if not ok:
                floating.append(path + "@" + ref)
    if floating:
        sample = ", ".join(floating[:3])
        more = "" if len(floating) <= 3 else " (+" + str(len(floating) - 3) + " more)"
        return _f("PinnedDependencies", STATUS_FAIL, SEV_MED,
                  "floating-tag Actions: " + sample + more)
    uses_count = 0
    for text in sec.workflow_files.values():
        uses_count += sum(1 for line in text.splitlines() if "uses:" in line)
    if uses_count == 0:
        return _f("PinnedDependencies", STATUS_PASS, SEV_INFO, "no third-party Actions referenced")
    return _f("PinnedDependencies", STATUS_PASS, SEV_INFO,
              "all " + str(uses_count) + " third-party Actions pinned to SHA")


# 7. BinaryArtifacts
# ---------------------------------------------------------------------------

_BINARY_EXTENSIONS = (".exe", ".dll", ".so", ".dylib", ".jar", ".whl")


def _check_binary_artifacts(sec):
    """Are executable / binary artifacts committed to the tree?"""
    if not sec.tree_entries:
        return _f("BinaryArtifacts", STATUS_UNCHECKED, SEV_INFO, "no tree fetched")
    found = []
    for entry in sec.tree_entries:
        if entry.get("type") != "blob":
            continue
        path = entry.get("path") or ""
        if not isinstance(path, str):
            continue
        lower = path.lower()
        for ext in _BINARY_EXTENSIONS:
            if lower.endswith(ext):
                found.append(path)
                break
    if found:
        sample = ", ".join(found[:3])
        more = "" if len(found) <= 3 else " (+" + str(len(found) - 3) + " more)"
        return _f("BinaryArtifacts", STATUS_WARN, SEV_LOW,
                  "committed binary artifacts: " + sample + more)
    return _f("BinaryArtifacts", STATUS_PASS, SEV_INFO,
              "no committed " + ", ".join(_BINARY_EXTENSIONS) + " files in tree")


# 8. Contributors (bus factor)
# ---------------------------------------------------------------------------


def _check_contributors(sec):
    """Bus factor: how concentrated are commits among top authors?"""
    if not sec.contributors:
        return _f("Contributors", STATUS_UNCHECKED, SEV_INFO, "no contributor data fetched")
    counts = [
        int(c.get("contributions", 0))
        for c in sec.contributors
        if isinstance(c, dict) and c.get("contributions") is not None
    ]
    total = sum(counts)
    if total <= 0:
        return _f("Contributors", STATUS_UNCHECKED, SEV_INFO,
                  "contributor totals are zero (no usable signal)")
    top = max(counts) if counts else 0
    share = top / total if total else 0.0
    if share > 0.70:
        return _f("Contributors", STATUS_WARN, SEV_MED,
                  "bus factor: top author has " + f"{share:.0%}" + " of commits ("
                  + str(top) + "/" + str(total) + " across "
                  + str(len(counts)) + " contributor(s))")
    if len(counts) <= 1:
        return _f("Contributors", STATUS_WARN, SEV_MED,
                  "single contributor with " + str(total) + " commit(s); bus factor = 1")
    return _f("Contributors", STATUS_PASS, SEV_INFO,
              "top author share " + f"{share:.0%}" + " across "
              + str(len(counts)) + " contributor(s)")


# 9. DependencyUpdateTool
# ---------------------------------------------------------------------------


def _check_dependency_update_tool(sec):
    """Does the repo run Dependabot or Renovate?"""
    if sec.has_dependabot_config is None and sec.has_renovate_config is None:
        return _f("DependencyUpdateTool", STATUS_UNCHECKED, SEV_INFO,
                  "dependabot/renovate lookups did not complete")
    has_dep = bool(sec.has_dependabot_config)
    has_ren = bool(sec.has_renovate_config)
    if has_dep or has_ren:
        tools = []
        if has_dep:
            tools.append("Dependabot")
        if has_ren:
            tools.append("Renovate")
        return _f("DependencyUpdateTool", STATUS_PASS, SEV_INFO,
                  " + ".join(tools) + " config found")
    return _f("DependencyUpdateTool", STATUS_WARN, SEV_LOW,
              "no Dependabot or Renovate config")


# 10. InstallTimeExecution
# ---------------------------------------------------------------------------

_RE_PACKAGE_INSTALL_SCRIPTS = re.compile(
    r"\"(?:postinstall|preinstall|install|prepare)\"\s*:\s*\"")


def _package_json_has_install_script(text):
    """Return True if a package.json declares an install-time script."""
    return bool(_RE_PACKAGE_INSTALL_SCRIPTS.search(text))


_RE_SETUP_PY_CMDCLASS = re.compile(
    r"cmdclass\s*=\s*\{[^}]*\"install\"", re.DOTALL)
_RE_SETUP_PY_DANGEROUS = re.compile(
    r"(?:^|\n)\s*(?:os\.system\s*\(|subprocess\.[A-Za-z_]+\s*\(|"
    r"exec\s*\(|eval\s*\()")


def _setup_py_is_dangerous(text):
    """Return True if a setup.py has install-time execution primitives."""
    if _RE_SETUP_PY_CMDCLASS.search(text):
        return True
    if _RE_SETUP_PY_DANGEROUS.search(text):
        return True
    return False


_RE_CARGO_BUILD_RS = re.compile(
    r"(?:build\s*=\s*\"build\.rs\"|\[build-dependencies\])")


def _cargo_toml_uses_build_rs(text):
    """Return True if Cargo.toml mentions a build.rs script."""
    return bool(_RE_CARGO_BUILD_RS.search(text))


def _check_install_time_execution(sec):
    """Do any manifests trigger install-time code execution?"""
    if not sec.manifests:
        return _f("InstallTimeExecution", STATUS_UNCHECKED, SEV_INFO,
                  "no manifests fetched")
    bad = []
    cargo = []
    for path, text in sec.manifests.items():
        lower = path.lower()
        try:
            if lower.endswith("package.json"):
                if _package_json_has_install_script(text):
                    bad.append(path)
            elif lower.endswith("setup.py"):
                if _setup_py_is_dangerous(text):
                    bad.append(path)
            elif lower.endswith("cargo.toml"):
                if _cargo_toml_uses_build_rs(text):
                    cargo.append(path)
        except Exception:
            # Malformed manifest should not crash the assessor.
            continue
    if bad:
        return _f("InstallTimeExecution", STATUS_FAIL, SEV_HIGH,
                  "install-time scripts in: " + ", ".join(bad))
    if cargo:
        return _f("InstallTimeExecution", STATUS_INFO, SEV_LOW,
                  "Cargo build.rs in: " + ", ".join(cargo) + " (standard practice)")
    return _f("InstallTimeExecution", STATUS_PASS, SEV_INFO,
              str(len(sec.manifests)) + " manifest(s) scanned, no install-time execution")


# 11. Maintained
# ---------------------------------------------------------------------------


def _check_maintained(sec, now):
    """Commit frequency over trailing 90 days (last 13 weeks).

    Returns ``unchecked`` if no ``now`` is supplied and the dataclass
    has no ``fetched_at`` either; never falls back to wall-clock reads.
    """
    if now is None:
        return _f("Maintained", STATUS_UNCHECKED, SEV_INFO,
                  "no `now` available; cannot measure trailing 90 days")
    if not sec.commit_activity_weeks:
        return _f("Maintained", STATUS_UNCHECKED, SEV_INFO,
                  "no commit-activity data fetched")
    # Sum the last 13 weeks. ``stats/commit_activity`` is reverse-
    # chronological in GitHub payload; the last 13 entries cover ~90 days.
    weeks = sec.commit_activity_weeks[-13:]
    total = 0
    for w in weeks:
        if not isinstance(w, dict):
            continue
        total += int(w.get("total", 0) or 0)
    if total <= 0:
        return _f("Maintained", STATUS_WARN, SEV_MED, "no commits in trailing 90 days")
    return _f("Maintained", STATUS_PASS, SEV_INFO,
              str(total) + " commit(s) in trailing 90 days")


# Top-level entry point
# ---------------------------------------------------------------------------

_CHECK_ORDER = (
    "BranchProtection",
    "SecurityPolicy",
    "SignedReleases",
    "DangerousWorkflow",
    "TokenPermissions",
    "PinnedDependencies",
    "BinaryArtifacts",
    "Contributors",
    "DependencyUpdateTool",
    "InstallTimeExecution",
    "Maintained",
)


def assess_security(sec, *, now=None):
    """Run the full battery of security checks against ``sec``.

    Args:
        sec: A :class:`SecurityFacts` populated by
            :func:`repofacts.github.fetch_security_facts`.
        now: Optional UTC timestamp for time-based checks (currently
            :func:`_check_maintained`). If omitted, ``sec.fetched_at``
            is used. The pure module never reads the wall clock; if
            neither ``now`` nor ``sec.fetched_at`` is supplied, the
            time-based check returns ``unchecked``.

    Returns:
        A :class:`SecurityReport` with one :class:`Finding` per check,
        in declaration order. ``findings`` always contains 11 entries -
        one per check - even when every check was ``unchecked``.
    """
    resolved_now = _resolve_now(sec, now)
    checks = [
        _check_branch_protection(sec),
        _check_security_policy(sec),
        _check_signed_releases(sec),
        _check_dangerous_workflow(sec),
        _check_token_permissions(sec),
        _check_pinned_dependencies(sec),
        _check_binary_artifacts(sec),
        _check_contributors(sec),
        _check_dependency_update_tool(sec),
        _check_install_time_execution(sec),
        _check_maintained(sec, resolved_now),
    ]
    if len(checks) != len(_CHECK_ORDER):
        raise AssertionError(
            "security check count drifted: " + str(len(checks))
            + " vs " + str(_CHECK_ORDER))
    return SecurityReport(owner=sec.owner, repo=sec.repo, findings=checks)
