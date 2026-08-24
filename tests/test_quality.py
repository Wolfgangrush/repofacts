"""Tests for repofacts.quality — pure check module.

Pins the behavioural contract of the quality battery, including the
load-bearing invariant that absent data must report "unchecked",
never "pass".
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone

import pytest

from repofacts import quality
from repofacts.models import (
    QualityFacts,
    QualityReport,
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
from repofacts.quality import (
    _CHECK_ORDER,
    _check_changelog,
    _check_ci_configured,
    _check_ci_status,
    _check_contributor_concentration,
    _check_dependency_weight,
    _check_documentation,
    _check_issue_responsiveness,
    _check_release_cadence,
    _check_semver_adherence,
    _check_tests_present,
    _count_python_deps,
    _looks_like_test_path,
    _tag_is_semver,
    assess_quality,
)


_LEGAL_STATUSES = frozenset(
    {STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO, STATUS_UNCHECKED}
)
_LEGAL_SEVERITIES = frozenset({SEV_HIGH, SEV_MED, SEV_LOW, SEV_INFO})


def facts(**kw) -> QualityFacts:
    """Build a QualityFacts with default owner/repo; kwargs override fields."""
    return QualityFacts(owner="o", repo="r", **kw)


# ---------------------------------------------------------------------------
# 1. assess_quality top-level: empty input never renders as a pass.
# ---------------------------------------------------------------------------


def test_assess_quality_fully_empty_yields_ten_unchecked_in_order():
    """An empty QualityFacts yields exactly 10 findings, in _CHECK_ORDER,
    every one unchecked, no false passes, owner/repo carry through."""
    report = assess_quality(facts())
    assert isinstance(report, QualityReport)
    assert report.owner == "o"
    assert report.repo == "r"
    assert len(report.findings) == 10
    assert [f.name for f in report.findings] == list(_CHECK_ORDER)
    assert all(f.status == STATUS_UNCHECKED for f in report.findings)
    assert not any(f.status == STATUS_PASS for f in report.findings)
    assert {f.severity for f in report.findings} <= _LEGAL_SEVERITIES


# ---------------------------------------------------------------------------
# 2. TestsPresent + _looks_like_test_path
# ---------------------------------------------------------------------------


def test_tests_present_pass_when_tree_has_test_file():
    """A tree entry matching a test pattern -> pass."""
    q = facts(tree_entries=[
        {"path": "src/foo.py", "type": "blob"},
        {"path": "tests/test_foo.py", "type": "blob"},
    ])
    assert _check_tests_present(q).status == STATUS_PASS


def test_tests_present_fail_when_tree_has_only_non_tests():
    """Tree present but no test-shaped path -> fail."""
    q = facts(tree_entries=[
        {"path": "src/foo.py", "type": "blob"},
        {"path": "README.md", "type": "blob"},
    ])
    assert _check_tests_present(q).status == STATUS_FAIL


def test_tests_present_unchecked_when_tree_empty():
    """Empty tree means the fetcher didn't get it -> unchecked."""
    assert _check_tests_present(facts()).status == STATUS_UNCHECKED


@pytest.mark.parametrize("path,expected", [
    ("src/test_foo.py", True),
    ("pkg/tests/helper.py", True),
    ("web/app.test.ts", True),
    ("web/app.spec.ts", True),
    ("cmd/main_test.go", True),
    ("src/foo/__tests__/bar.js", True),
    ("test/render.py", True),
    ("src/latest_thing.py", False),     # "test" is a substring, not a path component
    ("contest.py", False),              # filename with "test" substring
    ("src/foo.py", False),
])
def test_looks_like_test_path_positives_and_negatives(path, expected):
    """Path-component match AND filename regex match; never raw substring."""
    assert _looks_like_test_path(path) is expected


# ---------------------------------------------------------------------------
# 3. CIConfigured: presence vs fetched-contents vs all-empty
# ---------------------------------------------------------------------------


def test_ci_configured_pass_when_workflow_files_have_real_content():
    """Non-empty workflow YAML -> pass."""
    q = facts(
        workflow_paths=[".github/workflows/ci.yml"],
        workflow_files={".github/workflows/ci.yml": "name: CI\non: [push]\n"},
    )
    assert _check_ci_configured(q).status == STATUS_PASS


def test_ci_configured_fail_when_workflow_files_are_all_empty():
    """Real workflow path but every fetched file is whitespace -> fail."""
    q = facts(
        workflow_paths=[".github/workflows/ci.yml"],
        workflow_files={".github/workflows/ci.yml": "   \n\t\n"},
    )
    assert _check_ci_configured(q).status == STATUS_FAIL


def test_ci_configured_unchecked_when_paths_and_files_both_empty():
    """No paths, no files -> fetcher couldn't get them -> unchecked."""
    assert _check_ci_configured(facts()).status == STATUS_UNCHECKED


def test_ci_configured_paths_present_but_contents_not_fetched():
    """workflow_paths non-empty and workflow_files empty means CONTENTS WERE
    NOT FETCHED. MUST NOT render as 'workflows are empty' (a false fail).
    Must be a pass; reason must mention contents weren't fetched.
    """
    q = facts(
        workflow_paths=[".github/workflows/ci.yml"],
        workflow_files={},
    )
    f = _check_ci_configured(q)
    assert f.status == STATUS_PASS
    assert "empty" not in f.reason.lower()


# ---------------------------------------------------------------------------
# 4. CIStatus
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("conclusion,expected", [
    ("success", STATUS_PASS),
    ("neutral", STATUS_PASS),
    ("skipped", STATUS_PASS),
    ("failure", STATUS_FAIL),
    ("cancelled", STATUS_FAIL),
    ("timed_out", STATUS_FAIL),
    ("action_required", STATUS_FAIL),
    ("stale", STATUS_WARN),       # not in either known bucket
])
def test_ci_status_dispatch(conclusion, expected):
    """Pass/fail buckets are exhaustive; unknowns are warn."""
    assert _check_ci_status(
        facts(latest_check_conclusion=conclusion)
    ).status == expected


def test_ci_status_unchecked_when_conclusion_none():
    """None means no check-runs or none were fetched -> unchecked."""
    assert _check_ci_status(facts()).status == STATUS_UNCHECKED


# ---------------------------------------------------------------------------
# 5. Documentation: presence vs fetched vs not-fetched
# ---------------------------------------------------------------------------


def test_documentation_pass_with_long_readme_and_docs_dir():
    """README >= 1000 chars + a top-level docs/ tree -> pass."""
    q = facts(
        readme_length=2000,
        tree_entries=[{"path": "docs", "type": "tree"}],
    )
    assert _check_documentation(q).status == STATUS_PASS


def test_documentation_warn_with_short_but_present_readme():
    """A short but non-empty README -> warn."""
    assert _check_documentation(facts(readme_length=120)).status == STATUS_WARN


def test_documentation_fail_when_readme_fetched_empty():
    """readme_length == 0 means it was fetched but empty -> fail."""
    q = facts(readme_length=0, tree_entries=[{"path": "src", "type": "tree"}])
    assert _check_documentation(q).status == STATUS_FAIL


def test_documentation_not_fetched_remains_unchecked():
    """readme_length is None (NOT FETCHED) while a tree exists MUST NOT
    render as 'no README'. Absent data must not be asserted as fact.
    """
    q = facts(
        readme_length=None,
        tree_entries=[{"path": "src", "type": "tree"}],
    )
    f = _check_documentation(q)
    assert f.status == STATUS_UNCHECKED
    assert "no README" not in f.reason


# ---------------------------------------------------------------------------
# 6. ReleaseCadence
# ---------------------------------------------------------------------------


def test_release_cadence_pass_with_recent_release():
    """Release within 365 days of an explicit now -> pass."""
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    q = facts(releases=[{"published_at": "2026-07-01T00:00:00Z", "tag_name": "v1"}])
    assert _check_release_cadence(q, now).status == STATUS_PASS


def test_release_cadence_fail_when_no_recent_releases():
    """All releases older than 365 days -> fail."""
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    q = facts(releases=[{"published_at": "2024-01-01T00:00:00Z", "tag_name": "v0"}])
    assert _check_release_cadence(q, now).status == STATUS_FAIL


def test_release_cadence_unchecked_with_releases_but_no_now():
    """Releases exist but now=None and fetched_at=None -> unchecked."""
    q = facts(
        releases=[{"published_at": "2026-07-01T00:00:00Z", "tag_name": "v1"}],
        fetched_at=None,
    )
    assert _check_release_cadence(q, None).status == STATUS_UNCHECKED


def test_release_cadence_unchecked_when_published_at_unparseable():
    """Unparseable timestamps mean cadence cannot be measured -> unchecked."""
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    q = facts(releases=[{"published_at": "not-a-date", "tag_name": "v1"}])
    assert _check_release_cadence(q, now).status == STATUS_UNCHECKED


def test_release_cadence_naive_published_at_does_not_raise():
    """A release whose published_at lacks a tz suffix, given an aware now,
    MUST NOT raise. Absent tz on the data side must not crash the check.
    """
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    q = facts(releases=[{"published_at": "2026-08-01T00:00:00", "tag_name": "v1"}])
    f = _check_release_cadence(q, now)
    # The above must not raise. Status is pass when recent.
    assert f.status == STATUS_PASS


def _cadence(report):
    """Return the ReleaseCadence finding out of a QualityReport."""
    return next(f for f in report.findings if f.name == "ReleaseCadence")


def test_release_cadence_now_overrides_fetched_at():
    """assess_quality's explicit now= wins over q.fetched_at.

    fetched_at is far enough past the release that the trailing-12-months
    window would miss it (fail); the supplied now is inside the window
    (pass). The two must therefore disagree, which is what proves the
    precedence rather than a tautology.
    """
    q = facts(
        releases=[{"published_at": "2026-07-01T00:00:00Z", "tag_name": "v1"}],
        fetched_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    assert _cadence(assess_quality(q)).status == STATUS_FAIL
    assert _cadence(
        assess_quality(q, now=datetime(2026, 8, 24, tzinfo=timezone.utc))
    ).status == STATUS_PASS


def test_release_cadence_falls_back_to_fetched_at_when_now_omitted():
    """With no now=, the check uses q.fetched_at — never the wall clock."""
    q = facts(
        releases=[{"published_at": "2026-07-01T00:00:00Z", "tag_name": "v1"}],
        fetched_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
    )
    assert _cadence(assess_quality(q)).status == STATUS_PASS


# ---------------------------------------------------------------------------
# 7. SemVerAdherence + _tag_is_semver
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tag,valid", [
    ("v1.2.3", True),
    ("1.0.0", True),
    ("1.0.0-rc.1", True),
    ("1.0.0-rc.1+build.5", True),
    ("2.0.0-alpha", True),
    ("1.2", False),
    ("v1.2.3.4", False),
    ("abc", False),
    ("release-2026", False),
    ("latest", False),
])
def test_tag_is_semver(tag, valid):
    """_tag_is_semver accepts SemVer 2.0.0 with optional 'v' and rejects the rest."""
    assert _tag_is_semver(tag) is valid


def test_semver_adherence_all_valid_pass():
    """All tags valid -> pass."""
    assert _check_semver_adherence(
        facts(tags=["v1.2.3", "1.0.0-rc.1+build.5"])
    ).status == STATUS_PASS


def test_semver_adherence_no_valid_tags_fail():
    """Zero valid tags -> fail."""
    assert _check_semver_adherence(
        facts(tags=["release-2026", "latest"])
    ).status == STATUS_FAIL


def test_semver_adherence_mixed_warn():
    """Some valid, some not -> warn."""
    assert _check_semver_adherence(
        facts(tags=["v1.2.3", "release-2026"])
    ).status == STATUS_WARN


def test_semver_adherence_empty_unchecked():
    """No tags fetched -> unchecked."""
    assert _check_semver_adherence(facts()).status == STATUS_UNCHECKED


# ---------------------------------------------------------------------------
# 8. Changelog: True/False/None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("has,expected", [
    (True, STATUS_PASS),
    (False, STATUS_WARN),
    (None, STATUS_UNCHECKED),
])
def test_changelog_dispatch(has, expected):
    """True/False/None dispatch to pass/warn/unchecked."""
    assert _check_changelog(facts(has_changelog=has)).status == expected


def test_changelog_unchecked_reason_does_not_claim_absence():
    """When has_changelog is None, reason must not assert 'no CHANGELOG found'."""
    f = _check_changelog(facts(has_changelog=None))
    assert f.status == STATUS_UNCHECKED
    assert "no CHANGELOG" not in f.reason


# ---------------------------------------------------------------------------
# 9. IssueResponsiveness
# ---------------------------------------------------------------------------


def test_issue_responsiveness_pass_for_fast_median():
    """Median <= 24h -> pass."""
    assert _check_issue_responsiveness(
        facts(issue_response_hours=[2.0, 4.0, 6.0])
    ).status == STATUS_PASS


def test_issue_responsiveness_above_24h_is_not_pass():
    """A median above 24h must NEVER be a pass."""
    f = _check_issue_responsiveness(facts(issue_response_hours=[48.0, 72.0, 96.0]))
    assert f.status != STATUS_PASS


def test_issue_responsiveness_empty_unchecked():
    """Empty list -> unchecked."""
    assert _check_issue_responsiveness(facts()).status == STATUS_UNCHECKED


# ---------------------------------------------------------------------------
# 10. ContributorConcentration
# ---------------------------------------------------------------------------


def test_contributor_concentration_dominated_warns():
    """Top author > 50% of recent commits -> warn."""
    commits = [{"author": {"login": "alice"}} for _ in range(9)]
    commits.append({"author": {"login": "bob"}})
    assert _check_contributor_concentration(
        facts(recent_commits=commits)
    ).status == STATUS_WARN


def test_contributor_concentration_even_passes():
    """5/5 split (top share == 50%) -> pass (boundary, not strictly > 50%)."""
    commits = [{"author": {"login": "alice"}} for _ in range(5)]
    commits += [{"author": {"login": "bob"}} for _ in range(5)]
    assert _check_contributor_concentration(
        facts(recent_commits=commits)
    ).status == STATUS_PASS


def test_contributor_concentration_no_parseable_authors_unchecked():
    """Recent commits present but none has a parseable author -> unchecked."""
    assert _check_contributor_concentration(
        facts(recent_commits=[{"sha": "abc"}, {"sha": "def"}])
    ).status == STATUS_UNCHECKED


def test_contributor_concentration_falls_back_to_contributors_aggregate():
    """No recent commits but contributor totals exist -> uses the fallback
    and returns a real verdict, not unchecked."""
    q = facts(
        recent_commits=[],
        contributors=[
            {"login": "alice", "contributions": 5},
            {"login": "bob", "contributions": 5},
        ],
    )
    assert _check_contributor_concentration(q).status == STATUS_PASS


def test_contributor_concentration_neither_data_source_unchecked():
    """No recent commits and no contributors -> unchecked."""
    assert _check_contributor_concentration(facts()).status == STATUS_UNCHECKED


# ---------------------------------------------------------------------------
# 11. DependencyWeight + the Python dep counter
# ---------------------------------------------------------------------------


def test_dependency_weight_pass_for_small_package_json():
    """package.json with 3 dependencies -> pass and reason contains '3'."""
    pkg = '{"name":"x","dependencies":{"a":"1","b":"1","c":"1"}}'
    f = _check_dependency_weight(facts(manifests={"package.json": pkg}))
    assert f.status == STATUS_PASS
    assert "3" in f.reason


def test_dependency_weight_warn_for_too_many_deps():
    """More than 50 direct deps -> warn."""
    deps = ",".join(f'"d{i}":"1"' for i in range(60))
    pkg = '{"name":"x","dependencies":{' + deps + "}}"
    assert _check_dependency_weight(
        facts(manifests={"package.json": pkg})
    ).status == STATUS_WARN


def test_dependency_weight_no_manifests_unchecked():
    """No manifests -> unchecked."""
    assert _check_dependency_weight(facts()).status == STATUS_UNCHECKED


def test_dependency_weight_unparseable_only_manifest_is_unchecked():
    """A manifests dict whose ONLY entry the parser cannot run on
    (e.g. setup.py or Gemfile) MUST be unchecked, NOT a clean-zero info.
    A false all-clear on a supply-chain check is the worst outcome.
    """
    f = _check_dependency_weight(
        facts(manifests={"setup.py": "from setuptools import setup\n"})
    )
    assert f.status == STATUS_UNCHECKED


def test_count_python_deps_pep621_returns_exactly_two():
    """A PEP-621 pyproject.toml with two deps in a one-line list
    MUST count 2, not one-per-file-line."""
    text = (
        '[project]\n'
        'name = "demo"\n'
        'version = "0.1.0"\n'
        'dependencies = ["requests>=2.0", "click"]\n'
    )
    assert _count_python_deps(text) == 2


def test_count_python_deps_pep621_multiline_list():
    """A PEP-621 dependency array spread over several lines must still be
    counted (a real manifest silently counted as 0 deps is a false
    all-clear, the worst outcome for a supply-chain check)."""
    text = (
        '[project]\n'
        'name = "demo"\n'
        'dependencies = [\n'
        '    "requests>=2.0",\n'
        '    "click",\n'
        '    "rich",\n'
        ']\n'
    )
    assert _count_python_deps(text) == 3


def test_dependency_weight_reports_real_count_for_pep621_pyproject():
    """End-to-end: a 2-dep pyproject.toml reports 2, not one-per-line."""
    text = (
        '[project]\n'
        'name = "demo"\n'
        'version = "0.1.0"\n'
        'dependencies = ["requests>=2.0", "click"]\n'
    )
    f = _check_dependency_weight(facts(manifests={"pyproject.toml": text}))
    assert f.status == STATUS_PASS
    assert "pyproject.toml=2" in f.reason


def test_dependency_weight_unparseable_manifest_does_not_dilute_a_real_one():
    """One parseable + one unparseable manifest reports the parseable count
    and never silently folds the unknown one in as a zero."""
    pkg = '{"dependencies":{"a":"1","b":"1"}}'
    f = _check_dependency_weight(facts(manifests={
        "package.json": pkg,
        "setup.py": "from setuptools import setup\nsetup(install_requires=['x'])\n",
    }))
    assert f.status == STATUS_PASS
    assert "package.json=2" in f.reason
    assert "setup.py=0" not in f.reason


def test_dependency_weight_broken_package_json_is_unchecked():
    """package.json that is not valid JSON cannot be counted -> unchecked,
    never a clean '0 direct declared dependencies'."""
    f = _check_dependency_weight(
        facts(manifests={"package.json": "{ this is not json"})
    )
    assert f.status == STATUS_UNCHECKED


def test_dependency_weight_genuinely_zero_deps_is_not_unchecked():
    """A manifest that parses and truly declares nothing is INFO/0 — an
    honest zero must stay distinguishable from an unparseable manifest."""
    f = _check_dependency_weight(
        facts(manifests={"package.json": '{"name":"x","version":"1.0.0"}'})
    )
    assert f.status == STATUS_INFO
    assert "0" in f.reason


def test_count_python_deps_requirements_txt_ignores_comments():
    """requirements.txt: 2 package lines + 1 '#' comment -> 2."""
    text = "requests>=2.0\nclick\n# a comment\n"
    assert _count_python_deps(text) == 2


# ---------------------------------------------------------------------------
# 12. Purity guard
# ---------------------------------------------------------------------------


def test_quality_module_is_pure_no_clock_no_io():
    """quality.py must not read the wall clock or touch I/O. These would
    silently break tests and violate the module's contract.
    """
    src = inspect.getsource(quality)
    forbidden = (
        "datetime.now(",
        "datetime.utcnow",
        "urllib",
        "requests.",
        "socket",
        "open(",
    )
    for token in forbidden:
        assert token not in src, (
            f"repofacts.quality must not reference {token!r} (purity violated)"
        )


# ---------------------------------------------------------------------------
# 13. Cross-cutting invariant
# ---------------------------------------------------------------------------


def test_cross_cutting_legal_status_and_severity_on_arbitrary_inputs():
    """For ANY QualityFacts, every finding uses a legal status & severity,
    and the report always has exactly 10 findings (one per check)."""
    samples = [
        facts(),
        facts(
            tree_entries=[
                {"path": "tests/test_x.py", "type": "blob"},
                {"path": "docs", "type": "tree"},
            ],
            workflow_paths=[".github/workflows/ci.yml"],
            workflow_files={".github/workflows/ci.yml": "name: ci\non: [push]\n"},
            latest_check_conclusion="success",
            readme_length=2000,
            releases=[{"published_at": "2026-07-01T00:00:00Z", "tag_name": "v1"}],
            tags=["v1.2.3"],
            has_changelog=True,
            issue_response_hours=[2.0, 3.0],
            recent_commits=[{"author": {"login": "a"}} for _ in range(5)],
            manifests={
                "package.json": '{"dependencies":{"a":"1","b":"1","c":"1"}}'
            },
        ),
    ]
    for q in samples:
        report = assess_quality(q)
        assert len(report.findings) == 10
        for f in report.findings:
            assert f.status in _LEGAL_STATUSES, f"{f.name}: {f.status!r}"
            assert f.severity in _LEGAL_SEVERITIES, f"{f.name}: {f.severity!r}"
