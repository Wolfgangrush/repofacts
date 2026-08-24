"""Tests for repofacts.models — dataclass defaults, invariants, purity.

Drafted by the review against the module source, reviewed and consolidated by
the maintainer (per the model-separation rule).

These guard the load-bearing invariants of the data layer:

* "unchecked" is never "pass" — every tri-state field defaults to ``None``
  ("we could not check"), never ``False`` ("we checked, it is absent") and
  never a value that reads as a real result.
* frozen identity records (``RepoRef`` / ``Skip``) cannot be tampered with
  after extraction.
* mutable defaults are per-instance, never shared class state.
* nothing here reads the network, a file, or the clock — every dataclass is
  constructible offline.
* no dataclass carries a credential-shaped field, so the GitHub token can
  never ride along into ``--json`` output.
"""
from __future__ import annotations

import inspect
import re
import sys
from dataclasses import FrozenInstanceError, fields, is_dataclass
from pathlib import Path

import pytest

# --- sys.path bootstrap (mirrors the sibling test modules) -----------------
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from repofacts import models  # noqa: E402
from repofacts.models import (  # noqa: E402
    SEV_HIGH,
    SEV_INFO,
    SEV_LOW,
    SEV_MED,
    STATUS_FAIL,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_UNCHECKED,
    STATUS_WARN,
    Assessment,
    ClaimDiff,
    Finding,
    QualityFacts,
    QualityReport,
    RepoFacts,
    RepoRef,
    SecurityFacts,
    SecurityReport,
    Skip,
)


def _all_dataclasses_in_models():
    """Discover every dataclass actually defined in repofacts.models."""
    return [
        (name, obj)
        for name, obj in inspect.getmembers(models, inspect.isclass)
        if is_dataclass(obj) and obj.__module__ == models.__name__
    ]


# --- frozen identity records ----------------------------------------------


@pytest.mark.parametrize(
    "instance, attr, value",
    [
        (RepoRef(owner="o", repo="r", raw_mention="o/r"), "owner", "evil"),
        (Skip(raw="garbage", reason="no slash"), "reason", "silently dropped"),
    ],
)
def test_extraction_records_are_frozen(instance, attr, value):
    """RepoRef and Skip are the audit trail of what input became what.

    Design invariant #6 says nothing is ever silently dropped; if these
    records could be rewritten after extraction the trail would be worthless.
    """
    with pytest.raises(FrozenInstanceError):
        setattr(instance, attr, value)


def test_reporef_full_name_and_optional_line_no():
    """full_name is the canonical "owner/repo" key used everywhere downstream;
    line_no is optional provenance that must not be required to construct."""
    ref = RepoRef(owner="octo", repo="cat", raw_mention="@octo/cat")
    assert ref.full_name == "octo/cat"
    assert ref.line_no is None
    assert RepoRef(owner="o", repo="r", raw_mention="x", line_no=7).line_no == 7


# --- RepoFacts defaults ---------------------------------------------------


def test_repofacts_readme_status_defaults_to_missing_not_fetched():
    """rules.py gates the platform check on ``readme_status == "fetched"``.

    If the default were "fetched", a repo whose README was never retrieved
    would render as a *checked* platform claim — the exact "unchecked
    reported as pass" failure the whole program exists to prevent.
    """
    facts = RepoFacts(owner="o", repo="r")
    assert facts.readme_status == "missing"
    assert facts.readme_status != "fetched"
    # And the text it would have gated on is genuinely absent.
    assert facts.readme_text is None


def test_repofacts_defaults_assert_nothing_about_the_repo():
    """A freshly-constructed RepoFacts is a blank form, not a claim.

    Every boolean must default False and every unknown must default None, so
    an un-fetched repo can never be mistaken for a live, existing one.
    """
    facts = RepoFacts(owner="o", repo="r")
    assert facts.exists is False
    assert facts.archived is False
    assert facts.disabled is False
    assert facts.fork is False
    assert facts.private is False
    for name in (
        "stars",
        "forks",
        "language",
        "description",
        "pushed_at",
        "created_at",
        "default_branch",
        "parent_full_name",
        "license_spdx",
        "license_name",
        "readme_text",
        "moved_to",
        "error",
    ):
        assert getattr(facts, name) is None, f"{name} should default to None"
    assert facts.full_name == "o/r"


def test_repofacts_mutable_default_is_per_instance():
    """Shared-mutable-default bug: one repo's licence files must not leak
    into another repo's facts. field(default_factory=list) is required."""
    a = RepoFacts(owner="a", repo="a")
    b = RepoFacts(owner="b", repo="b")
    assert a.readme_license_files == []
    a.readme_license_files.append("LICENSE")
    assert a.readme_license_files == ["LICENSE"]
    assert b.readme_license_files == []
    assert a.readme_license_files is not b.readme_license_files


def test_repofacts_is_mutable_for_the_fetcher():
    """github.py populates RepoFacts in place (see github.py:448-451).

    Freezing this dataclass would break the only network module, so the
    mutability is a real contract, not an accident.
    """
    facts = RepoFacts(owner="o", repo="r")
    facts.exists = True
    facts.stars = 42
    facts.readme_status = "fetched"
    assert (facts.exists, facts.stars, facts.readme_status) == (True, 42, "fetched")


# --- Assessment defaults --------------------------------------------------


def test_assessment_platform_check_defaults_to_unchecked():
    """The single most load-bearing default in the program.

    "unchecked" must never be spelled "checked_clear". render.py prints this
    string straight into the table, JSON and Markdown output.
    """
    a = Assessment(ref=RepoRef(owner="o", repo="r", raw_mention="o/r"),
                   facts=RepoFacts(owner="o", repo="r"))
    assert a.platform_check == "unchecked"
    assert a.platform_check != "checked_clear"
    assert a.verdict == "OK"
    assert a.licence_class == "NONE"
    assert a.licence_as_of == ""
    assert a.multiple_licence_files is False


def test_assessment_mutable_defaults_are_per_instance():
    """Two assessments built from the same ref/facts must not share reason
    lists — cross-contaminated reasons would attribute one repo's problems
    to another."""
    ref = RepoRef(owner="o", repo="r", raw_mention="o/r")
    facts = RepoFacts(owner="o", repo="r")
    a = Assessment(ref=ref, facts=facts)
    b = Assessment(ref=ref, facts=facts)
    a.reasons.append("archived")
    a.platform_notes.append("linux-only")
    a.claim_diffs.append(
        ClaimDiff(full_name="o/r", raw="o/r has 9k stars", claim_type="star_count",
                  claimed_value="9000", actual_value="12", match=False)
    )
    assert b.reasons == []
    assert b.platform_notes == []
    assert b.claim_diffs == []


# --- status / severity vocabularies ---------------------------------------


def test_status_and_severity_constants_are_distinct():
    """Five statuses, four severities, no collisions.

    If STATUS_UNCHECKED ever equalled STATUS_PASS the tri-state contract
    would collapse silently everywhere it is compared.
    """
    statuses = [STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO, STATUS_UNCHECKED]
    assert len(set(statuses)) == 5
    assert STATUS_UNCHECKED != STATUS_PASS
    assert STATUS_UNCHECKED not in (STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO)
    severities = [SEV_HIGH, SEV_MED, SEV_LOW, SEV_INFO]
    assert len(set(severities)) == 4


def test_finding_requires_every_field_so_it_cannot_default_to_pass():
    """Finding deliberately has NO defaults.

    A default status would let a check that never ran be constructed as a
    pass. Omitting any field must be a hard TypeError at construction.
    """
    with pytest.raises(TypeError):
        Finding()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        # status omitted — the dangerous one
        Finding(name="BranchProtection", severity=SEV_HIGH, reason="r")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        Finding(name="x", status=STATUS_PASS, severity=SEV_HIGH)  # type: ignore[call-arg]
    ok = Finding(name="x", status=STATUS_UNCHECKED, severity=SEV_INFO, reason="no data")
    assert ok.status == STATUS_UNCHECKED


# --- deep-check fact containers -------------------------------------------


def test_securityfacts_defaults_are_none_and_empty_never_false():
    """None means "the fetcher could not get this"; False would mean
    "we looked and it is not there". Conflating them turns an unreachable
    endpoint into a confident finding."""
    s = SecurityFacts(owner="o", repo="r")
    assert s.has_security_policy is None
    assert s.has_dependabot_config is None
    assert s.has_renovate_config is None
    assert s.branch_protection is None
    assert s.default_branch is None
    assert s.error is None
    assert s.releases == []
    assert s.workflow_files == {}
    assert s.tree_entries == []
    assert s.contributors == []
    assert s.commit_activity_weeks == []
    assert s.manifests == {}


def test_securityfacts_collections_are_per_instance():
    """Repo A's fetched workflows/manifests must never appear under repo B."""
    a = SecurityFacts(owner="a", repo="a")
    b = SecurityFacts(owner="b", repo="b")
    a.releases.append({"tag_name": "v1"})
    a.workflow_files["ci.yml"] = "on: push"
    a.tree_entries.append({"path": "src", "type": "tree"})
    a.contributors.append({"login": "u", "contributions": 1})
    a.commit_activity_weeks.append({"week": 0, "total": 3})
    a.manifests["package.json"] = "{}"
    assert b.releases == []
    assert b.workflow_files == {}
    assert b.tree_entries == []
    assert b.contributors == []
    assert b.commit_activity_weeks == []
    assert b.manifests == {}


def test_qualityfacts_defaults_are_none_and_empty():
    """Same tri-state contract as SecurityFacts: unknowns start at None.

    readme_length is the subtle one — 0 would claim "we read it, it was
    empty", which is a very different finding from "we never read it".
    """
    q = QualityFacts(owner="o", repo="r")
    assert q.has_changelog is None
    assert q.readme_length is None
    assert q.readme_length != 0
    assert q.latest_check_conclusion is None
    assert q.head_sha is None
    assert q.default_branch is None
    assert q.fetched_at is None
    assert q.error is None
    assert q.tree_entries == []
    assert q.workflow_paths == []
    assert q.workflow_files == {}
    assert q.releases == []
    assert q.tags == []
    assert q.contributors == []
    assert q.recent_commits == []
    assert q.manifests == {}
    assert q.issue_response_hours == []


def test_qualityfacts_collections_are_per_instance():
    """Every QualityFacts collection needs its own default_factory."""
    a = QualityFacts(owner="a", repo="a")
    b = QualityFacts(owner="b", repo="b")
    a.tree_entries.append({"path": "tests", "type": "tree"})
    a.workflow_paths.append(".github/workflows/ci.yml")
    a.workflow_files["ci.yml"] = "on: push"
    a.releases.append({"tag_name": "v1"})
    a.tags.append("v1.0.0")
    a.contributors.append({"login": "u", "contributions": 1})
    a.recent_commits.append({"sha": "abc"})
    a.manifests["pyproject.toml"] = ""
    a.issue_response_hours.append(1.5)
    assert b.tree_entries == []
    assert b.workflow_paths == []
    assert b.workflow_files == {}
    assert b.releases == []
    assert b.tags == []
    assert b.contributors == []
    assert b.recent_commits == []
    assert b.manifests == {}
    assert b.issue_response_hours == []


def test_fetched_at_defaults_to_none_models_never_reads_the_clock():
    """Purity rule: models.py takes no clock. fetched_at is stamped by the
    fetcher, so two instances built back-to-back must both be None rather
    than two slightly different datetime.now() values."""
    s1, s2 = SecurityFacts(owner="o", repo="r"), SecurityFacts(owner="o", repo="r")
    q1, q2 = QualityFacts(owner="o", repo="r"), QualityFacts(owner="o", repo="r")
    assert s1.fetched_at is None and s2.fetched_at is None
    assert q1.fetched_at is None and q2.fetched_at is None


def test_reports_default_to_empty_findings_per_instance():
    """An empty report must be distinguishable from a report of passes —
    zero findings means nothing was assessed, not that everything is fine."""
    s, s2 = SecurityReport(owner="o", repo="r"), SecurityReport(owner="o", repo="r")
    q, q2 = QualityReport(owner="o", repo="r"), QualityReport(owner="o", repo="r")
    assert s.findings == [] and q.findings == []
    finding = Finding(name="x", status=STATUS_PASS, severity=SEV_INFO, reason="ok")
    s.findings.append(finding)
    q.findings.append(finding)
    assert s2.findings == []
    assert q2.findings == []


# --- claims ---------------------------------------------------------------


def test_claimdiff_match_is_tri_valued_and_line_no_optional():
    """match=None means "we could not parse the claim into a value" and must
    be constructible — collapsing it to False would report an unparseable
    claim as a contradiction."""
    base = dict(full_name="o/r", raw="o/r is MIT", claim_type="license",
                claimed_value="MIT", actual_value="Apache-2.0")
    assert ClaimDiff(**base, match=True).match is True
    assert ClaimDiff(**base, match=False).match is False
    assert ClaimDiff(**base, match=None).match is None
    assert ClaimDiff(**base, match=None).line_no is None
    # actual_value is allowed to be None (nothing fetched to compare against)
    unresolved = ClaimDiff(full_name="o/r", raw="x", claim_type="star_count",
                           claimed_value="9k", actual_value=None, match=None)
    assert unresolved.actual_value is None


# --- token safety / purity ------------------------------------------------


def test_no_dataclass_exposes_a_credential_field():
    """The GitHub token must never be printable or serialisable in any output
    mode, including --json. Every renderer walks these dataclasses, so the
    cheapest structural guarantee is that no field is credential-shaped."""
    forbidden = ("token", "secret", "password", "auth", "credential", "api_key")
    discovered = _all_dataclasses_in_models()
    assert discovered, "no dataclasses discovered — the guard would be vacuous"
    for cls_name, cls in discovered:
        for f in fields(cls):
            lowered = f.name.lower()
            for needle in forbidden:
                assert needle not in lowered, (
                    f"{cls_name}.{f.name} is credential-shaped"
                )


def test_models_is_pure_no_network_and_no_file_io():
    """models.py must be constructible with the network unplugged.

    github.py is the ONLY module allowed to touch the network. We assert on
    the source text rather than sys.modules because pytest itself imports
    http/socket for unrelated reasons.
    """
    src = inspect.getsource(models)
    for pattern in (
        r"^\s*(?:from|import)\s+urllib\b",
        r"^\s*(?:from|import)\s+http\b",
        r"^\s*(?:from|import)\s+socket\b",
        r"^\s*(?:from|import)\s+requests\b",
        r"^\s*(?:from|import)\s+ssl\b",
        r"\bopen\s*\(",
        r"\bPath\s*\(",
    ):
        assert not re.search(pattern, src, re.MULTILINE), (
            f"models.py contains forbidden pattern {pattern!r}"
        )
    # And nothing network-shaped is bound in the module namespace.
    leak = set(vars(models)) & {"urllib", "http", "socket", "requests", "ssl"}
    assert not leak, f"models exposes network modules: {leak}"


def test_every_dataclass_imports_and_constructs_with_the_network_unplugged():
    """The headline invariant, proved at runtime rather than by reading source.

    We hard-block the socket layer, load models.py fresh under that block, and
    construct every dataclass it defines. If import or construction reached the
    network — directly or through a lazily-imported helper — this raises.

    The module is loaded under a private name via spec_from_file_location so
    that ``sys.modules["repofacts.models"]`` is left untouched; rebinding it
    would hand sibling test modules a different set of class objects.
    """
    import importlib.util
    import socket
    from dataclasses import MISSING

    def _boom(*args, **kwargs):
        raise AssertionError("models.py attempted network access")

    saved = {
        name: getattr(socket, name)
        for name in ("socket", "create_connection", "getaddrinfo")
    }
    try:
        for name in saved:
            setattr(socket, name, _boom)

        spec = importlib.util.spec_from_file_location(
            "_repofacts_models_isolated", models.__file__
        )
        isolated = importlib.util.module_from_spec(spec)
        # @dataclass resolves string annotations via sys.modules[cls.__module__],
        # so the private name must be registered before exec_module runs.
        sys.modules["_repofacts_models_isolated"] = isolated
        spec.loader.exec_module(isolated)  # import-time purity

        discovered = [
            (n, o)
            for n, o in inspect.getmembers(isolated, inspect.isclass)
            if is_dataclass(o) and o.__module__ == "_repofacts_models_isolated"
        ]
        assert len(discovered) >= 9, (
            f"expected the full model set, found {[n for n, _ in discovered]}"
        )

        for cls_name, cls in discovered:
            required = [
                f.name
                for f in fields(cls)
                if f.default is MISSING and f.default_factory is MISSING
            ]
            # Plain dataclasses do no type validation, so a sentinel string is
            # a legitimate stand-in for every required field, including the
            # nested ref/facts on Assessment.
            instance = cls(**{n: "x" for n in required})
            assert instance is not None, f"{cls_name} failed to construct"
    finally:
        for name, original in saved.items():
            setattr(socket, name, original)
        sys.modules.pop("_repofacts_models_isolated", None)
