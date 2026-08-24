"""Tests for repofacts.render — token redaction and rendering semantics."""
from __future__ import annotations

import json
from dataclasses import dataclass

from repofacts.models import (
    Assessment,
    ClaimDiff,
    Finding,
    QualityReport,
    RepoFacts,
    RepoRef,
    SecurityReport,
    Skip,
)
from repofacts.render import (
    _scrub,
    _scrub_list,
    format_json,
    format_markdown,
    format_summary,
    format_table,
)
from repofacts.simulate import (
    ConflictSimulation,
    DuplicatePurposeWarning,
    FloatingDep,
    InstallHook,
    InstallSimulation,
    NewTransitiveSurface,
    RuntimeFloorConflict,
    TyposquatHit,
    VersionConflict,
)


TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
TOKEN_URL = f"https://x-access-token:{TOKEN}@github.com/acme/widget.git"


@dataclass
class DeepStub:
    security_report: object | None = None
    quality_report: object | None = None
    install_sim: object | None = None
    conflict_sim: object | None = None
    fetch_error: str | None = None


def assert_clean(text: str) -> None:
    """The token and the x-access-token URL form must not appear in the text."""
    assert TOKEN not in text, f"token leaked into output: {text[:200]!r}"
    assert "x-access-token:" not in text, f"x-access-token prefix leaked: {text[:200]!r}"


def make_assessment(
    owner: str = "acme",
    repo: str = "widget",
    *,
    verdict: str = "OK",
    licence_class: str = "MIT",
    platform_check: str = "unchecked",
    description: str | None = None,
    error: str | None = None,
    reasons: list[str] | None = None,
    platform_notes: list[str] | None = None,
    raw_mention: str | None = None,
    exists: bool = True,
    stars: int | None = 10,
    license_spdx: str | None = "MIT",
    claim_diffs: list[ClaimDiff] | None = None,
) -> Assessment:
    ref = RepoRef(
        owner=owner,
        repo=repo,
        raw_mention=raw_mention if raw_mention is not None else f"github.com/{owner}/{repo}",
        line_no=1,
    )
    facts = RepoFacts(
        owner=owner,
        repo=repo,
        exists=exists,
        stars=stars,
        description=description,
        error=error,
        license_spdx=license_spdx,
    )
    return Assessment(
        ref=ref,
        facts=facts,
        verdict=verdict,
        reasons=reasons or [],
        licence_class=licence_class,
        platform_check=platform_check,
        platform_notes=platform_notes or [],
        claim_diffs=claim_diffs or [],
    )


def make_skip(raw: str = "github.com/foo/bar", reason: str = "unparseable", line_no: int = 7) -> Skip:
    return Skip(raw=raw, reason=reason, line_no=line_no)


def make_deep(
    *,
    sec_findings: list[Finding] | None = None,
    qual_findings: list[Finding] | None = None,
    install_sim: InstallSimulation | None = None,
    conflict_sim: ConflictSimulation | None = None,
    fetch_error: str | None = None,
) -> DeepStub:
    sec = SecurityReport(owner="acme", repo="widget", findings=sec_findings or [])
    qual = QualityReport(owner="acme", repo="widget", findings=qual_findings or [])
    return DeepStub(
        security_report=sec,
        quality_report=qual,
        install_sim=install_sim if install_sim is not None else InstallSimulation(),
        conflict_sim=conflict_sim if conflict_sim is not None else ConflictSimulation(),
        fetch_error=fetch_error,
    )


# ---- 1. Token never leaks in any output mode --------------------------------

def test_token_never_leaks_in_any_output_mode():
    assessment = make_assessment(
        verdict="STOP",
        description=f"Project uses {TOKEN} for deployment",
        error=f"auth failed with {TOKEN}",
        reasons=[f"leaked secret {TOKEN}", "another concern"],
        platform_notes=[f"warn: token {TOKEN} in env"],
        raw_mention=f"github.com/acme/widget see {TOKEN}",
        claim_diffs=[
            ClaimDiff(
                full_name="acme/widget",
                raw=f"claim mentions {TOKEN}",
                claim_type="stars",
                claimed_value="100",
                actual_value="10",
                match=False,
                line_no=2,
            )
        ],
    )
    skip = make_skip(raw=f"github.com/acme/leak {TOKEN}", reason=f"failed: {TOKEN}")

    sec_finding = Finding("danger-1", "fail", "HIGH", f"credential leak {TOKEN}")
    qual_finding = Finding("lint-1", "fail", "MED", f"uses {TOKEN}")
    inst = InstallSimulation(
        hooks=[
            InstallHook(
                ecosystem="pypi",
                kind="script",
                name="setup",
                quote=f"running {TOKEN}",
                source=f"setup.py {TOKEN}",
                line_no=10,
            )
        ],
        floating=[
            FloatingDep(
                ecosystem="pypi",
                name="lib",
                spec=f"req with {TOKEN}",
                reason="missing",
                source=f"req.txt {TOKEN}",
            )
        ],
        typosquats=[
            TyposquatHit(name="requsts", canonical="requests", distance=1, source=f"mentions {TOKEN}")
        ],
        surface_note=f"surface note {TOKEN}",
        unparsed=[f"line with {TOKEN}"],
    )
    deep = make_deep(
        sec_findings=[sec_finding],
        qual_findings=[qual_finding],
        install_sim=inst,
        fetch_error=f"failed: {TOKEN}",
    )
    deep_by_full = {assessment.ref.full_name.lower(): deep}

    outputs: list[tuple[str, str]] = []
    for deep_arg in (None, deep_by_full):
        outputs.append(("table", format_table([assessment], [skip], deep_by_full=deep_arg)))
        outputs.append(("summary", format_summary([assessment], [skip], deep_by_full=deep_arg)))
        outputs.append(("json", format_json([assessment], [skip], "2026-01-01", deep_by_full=deep_arg)))
        outputs.append(("md", format_markdown([assessment], [skip], "2026-01-01", deep_by_full=deep_arg)))

    for name, text in outputs:
        assert_clean(text)

    # prove the scrubber actually fired (rather than fields being silently dropped)
    joined = "\n".join(t for _, t in outputs)
    assert "[REDACTED]" in joined, "scrubber did not fire in any output"


# ---- 2. Git-URL dependency carrying the token must never leak ----------------
def test_token_in_dependency_git_url_never_leaks():
    assessment = make_assessment(verdict="CAUTION")
    sec = SecurityReport(
        owner="acme",
        repo="widget",
        findings=[Finding("dep-leak", "fail", "HIGH", "private dep exposes credential")],
    )
    qual = QualityReport(owner="acme", repo="widget", findings=[])
    conflict = ConflictSimulation(
        version_conflicts=[
            VersionConflict(
                ecosystem="pypi",
                name="privatelib",
                declared_spec=TOKEN_URL,
                installed_version=TOKEN_URL,
                status="fail",
                note=f"see {TOKEN_URL}",
            )
        ],
        runtime_floors=[
            RuntimeFloorConflict(
                language="python",
                declared=TOKEN_URL,
                host_version=TOKEN_URL,
                status="fail",
            )
        ],
        new_transitive=[
            NewTransitiveSurface(
                ecosystem="pypi",
                name="privatelib",
                declared_spec=TOKEN_URL,
            )
        ],
        duplicate_purpose=[
            DuplicatePurposeWarning(
                brought=TOKEN_URL,
                brought_ecosystem="pypi",
                duplicates=TOKEN_URL,
                group="http",
            )
        ],
    )
    inst = InstallSimulation(
        floating=[
            FloatingDep(
                ecosystem="pypi",
                name="privatelib",
                spec=TOKEN_URL,
                reason="private",
                source="req.txt",
            )
        ],
        hooks=[
            InstallHook(
                ecosystem="pypi",
                kind="script",
                name="setup",
                quote=TOKEN_URL,
                source="setup.py",
                line_no=10,
            )
        ],
    )
    deep = DeepStub(
        security_report=sec,
        quality_report=qual,
        install_sim=inst,
        conflict_sim=conflict,
    )
    deep_by_full = {assessment.ref.full_name.lower(): deep}

    for text in (
        format_table([assessment], [], deep_by_full=deep_by_full),
        format_json([assessment], [], "2026-01-01", deep_by_full=deep_by_full),
        format_markdown([assessment], [], "2026-01-01", deep_by_full=deep_by_full),
    ):
        assert_clean(text)


# ---- 3. JSON carries token_source name but never token value -----------------
def test_json_carries_token_source_name_but_never_token_value():
    assessment = make_assessment()
    out = format_json([assessment], [], "2026-01-01", token_source="GITHUB_TOKEN")
    assert '"token_source": "GITHUB_TOKEN"' in out
    obj = json.loads(out)
    assert obj["token_source"] == "GITHUB_TOKEN"
    assert TOKEN not in out


# ---- 4. Unchecked finding renders as [unchecked] in the table ---------------
def test_unchecked_finding_renders_as_unchecked_in_table():
    assessment = make_assessment()
    sec_findings = [
        Finding("sec-pass", "pass", "INFO", "all good"),
        Finding("sec-unchecked", "unchecked", "INFO", "could not run"),
    ]
    qual_findings = [
        Finding("qual-pass", "pass", "INFO", "ok"),
        Finding("qual-unchecked", "unchecked", "INFO", "could not run"),
    ]
    deep = make_deep(sec_findings=sec_findings, qual_findings=qual_findings)
    table = format_table(
        [assessment], [],
        deep_by_full={assessment.ref.full_name.lower(): deep},
    )
    assert "[unchecked]" in table
    assert "sec-unchecked" in table
    assert "qual-unchecked" in table
    assert "[pass]" in table  # the real pass findings are still emitted
    for line in table.splitlines():
        if "sec-unchecked" in line or "qual-unchecked" in line:
            assert "[unchecked]" in line
            assert "[pass]" not in line


# ---- 5. JSON preserves "unchecked" verbatim, never rewriting to "pass" ------
def test_unchecked_status_survives_json_verbatim():
    assessment = make_assessment()
    sec = SecurityReport(
        owner="acme",
        repo="widget",
        findings=[
            Finding("a", "unchecked", "INFO", "x"),
            Finding("b", "pass", "INFO", "y"),
        ],
    )
    deep = DeepStub(
        security_report=sec,
        quality_report=QualityReport(owner="acme", repo="widget"),
    )
    out = format_json(
        [assessment], [], "2026-01-01",
        deep_by_full={assessment.ref.full_name.lower(): deep},
    )
    obj = json.loads(out)
    findings = obj["assessments"][0]["deep"]["security"]["findings"]
    statuses = [f["status"] for f in findings]
    assert "unchecked" in statuses
    assert "pass" in statuses
    assert sum(1 for s in statuses if s == "unchecked") == 1
    assert sum(1 for s in statuses if s == "pass") == 1


# ---- 6. Markdown preserves [unchecked] in the deep section -------------------
def test_unchecked_status_survives_markdown():
    assessment = make_assessment()
    sec = SecurityReport(
        owner="acme",
        repo="widget",
        findings=[Finding("a", "unchecked", "INFO", "could not run")],
    )
    deep = DeepStub(
        security_report=sec,
        quality_report=QualityReport(owner="acme", repo="widget"),
    )
    md = format_markdown(
        [assessment], [], "2026-01-01",
        deep_by_full={assessment.ref.full_name.lower(): deep},
    )
    assert "[unchecked]" in md
    assert "a" in md


# ---- 7. platform_check='unchecked' is rendered as the literal word ------------

def test_platform_check_unchecked_is_rendered_not_hidden():
    assessment = make_assessment(platform_check="unchecked")
    table = format_table([assessment], [])
    assert "unchecked" in table
    assert "checked_clear" not in table

    obj = json.loads(format_json([assessment], [], "2026-01-01"))
    assert obj["assessments"][0]["platform_check"] == "unchecked"

    md = format_markdown([assessment], [], "2026-01-01")
    assert "unchecked" in md
    assert "checked_clear" not in md


# ---- 8. Summary counts unchecked separately from fail ------------------------

def test_summary_counts_unchecked_separately_from_fail():
    assessment = make_assessment()
    sec_findings = [
        Finding("a", "fail", "HIGH", "x"),
        Finding("b", "unchecked", "INFO", "x"),
        Finding("c", "unchecked", "INFO", "x"),
    ]
    qual_findings = [
        Finding("d", "unchecked", "INFO", "x"),
    ]
    deep = make_deep(sec_findings=sec_findings, qual_findings=qual_findings)
    summary = format_summary(
        [assessment], [],
        deep_by_full={assessment.ref.full_name.lower(): deep},
    )
    assert "1 security-fail" in summary
    assert "2 security-unchecked" in summary
    assert "1 quality-unchecked" in summary
    # unchecked is never absorbed into pass counts
    assert "security-pass" not in summary
    assert "quality-pass" not in summary


# ---- 9. Table rows are ordered STOP < CAUTION < OK ---------------------------
def test_table_sorts_stop_first_then_caution_then_ok():
    stop = make_assessment(repo="zoo", verdict="STOP")
    caution = make_assessment(repo="middle", verdict="CAUTION")
    ok = make_assessment(repo="alpha", verdict="OK")
    # hand the renderer in an order that would scramble unsorted output
    table = format_table([ok, stop, caution], [])
    lines = table.splitlines()
    # format_table renders fixed-width columns, not pipe-delimited markdown:
    # the verdict is the first column, left-justified.
    stop_idx = next(i for i, line in enumerate(lines) if line.startswith("STOP "))
    caution_idx = next(i for i, line in enumerate(lines) if line.startswith("CAUTION "))
    ok_idx = next(i for i, line in enumerate(lines) if line.startswith("OK "))
    assert stop_idx < caution_idx < ok_idx
    # alphabetically "alpha" < "middle" < "zoo", so this ordering can only come
    # from the verdict rank dominating the name tiebreak.
    assert lines[stop_idx].split()[1] == "acme/zoo"
    assert lines[ok_idx].split()[1] == "acme/alpha"


# ---- 10. Empty input renders the sentinel string -----------------------------
def test_table_empty_input_returns_sentinel():
    assert format_table([], []) == "no repositories found"


# ---- 11. JSON: deep_by_full=None omits deep; deep_by_full={} adds deep=None ---
def test_json_fast_path_omits_deep_key_and_deep_path_adds_it():
    a = make_assessment()
    out_none = json.loads(format_json([a], [], "2026-01-01", deep_by_full=None))
    assert "deep" not in out_none["assessments"][0]

    out_empty = json.loads(format_json([a], [], "2026-01-01", deep_by_full={}))
    assert out_empty["assessments"][0]["deep"] is None


# ---- 12. Skipped mentions appear in every output mode ------------------------

def test_skipped_mentions_appear_in_every_output_mode():
    skip1 = make_skip(raw="github.com/foo/bar", reason="not a url", line_no=4)
    skip2 = make_skip(raw="random text", reason="garbage", line_no=9)
    a = make_assessment()

    table = format_table([a], [skip1, skip2])
    assert "github.com/foo/bar" in table
    assert "random text" in table

    obj = json.loads(format_json([a], [skip1, skip2], "2026-01-01"))
    assert len(obj["skipped"]) == 2
    raws = {entry["raw"] for entry in obj["skipped"]}
    assert "github.com/foo/bar" in raws
    assert "random text" in raws

    md = format_markdown([a], [skip1, skip2], "2026-01-01")
    assert "## Skipped" in md
    assert "github.com/foo/bar" in md
    assert "random text" in md


# ---- 13. A repo that doesn't exist is "missing", not "no-licence" ------------

def test_nonexistent_repo_not_counted_as_no_licence():
    ghost = make_assessment(exists=False, licence_class="NONE", stars=None)
    summary = format_summary([ghost], [])
    assert "1 missing" in summary
    assert "no-licence" not in summary


# ---- 14. Markdown headers are present, one data row per assessment -----------
def test_markdown_table_header_and_one_row_per_assessment():
    a1 = make_assessment(repo="alpha", verdict="STOP")
    a2 = make_assessment(repo="beta", verdict="OK")
    md = format_markdown([a1, a2], [], "2026-01-01")
    assert "| verdict | repo | stars | licence | platform | reason |" in md
    assert "| --- | --- | ---: | --- | --- | --- |" in md
    data_rows = [
        line for line in md.splitlines()
        if line.startswith("| STOP ")
        or line.startswith("| OK ")
        or line.startswith("| CAUTION ")
    ]
    assert len(data_rows) == 2


# ---- 15. _scrub leaves clean text alone and handles None / short lookalikes --
def test_scrub_leaves_clean_text_untouched_and_handles_none():
    assert _scrub(None) is None
    assert _scrub("plain text") == "plain text"
    assert _scrub_list(None) == []
    assert _scrub_list(["a", "b"]) == ["a", "b"]
    # short lookalike — only 8 chars after the prefix, well under the 36-char floor
    assert _scrub("ghp_tooshort") == "ghp_tooshort"
    # long non-token strings should be untouched
    assert _scrub("a" * 200) == "a" * 200
