"""Data models for repofacts.

Plain dataclasses only. No I/O, no network. These are the currency between
the network layer (`github.py`), the pure decision layer (`rules.py` /
`claims.py`), and the renderer (`render.py`).

Public dataclasses:
    RepoRef      — a reference to a GitHub repo, as extracted from input text
    Skip         — an input mention that was *not* turned into a RepoRef, with
                   a human-readable reason (never silently dropped)
    RepoFacts    — the set of facts GitHub returned about a repo
    ClaimDiff    — one (claim, truth) pair from the claims pipeline
    Assessment   — RepoFacts + the verdict, reasons, and licence class
    Finding      — one named check result, used by the deep assessors
    DeepFacts / SecurityReport / QualityReport — deep-check inputs/outputs.
    ``SecurityFacts`` and ``QualityFacts`` are kept as module-level
    aliases of ``DeepFacts`` (the union class) so every existing
    annotation, import, and constructor call still resolves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


# ----- Reference / extraction types ---------------------------------------


@dataclass(frozen=True)
class RepoRef:
    """A reference to a GitHub repository extracted from input text.

    Returned by :func:`repofacts.extract.extract_refs`.
    """
    owner: str
    repo: str
    raw_mention: str
    line_no: int | None = None

    @property
    def full_name(self) -> str:
        """Return ``owner/repo``."""
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True)
class Skip:
    """An input mention that could not be turned into a ``RepoRef``.

    Per design invariant #6, nothing is ever silently dropped — every skipped
    mention appears here with the reason it was rejected.
    """
    raw: str
    reason: str
    line_no: int | None = None


# ----- Network layer output -----------------------------------------------


@dataclass
class RepoFacts:
    """What GitHub told us about a repository.

    ``readme_status`` is intentionally separate from ``readme_text``: a README
    that was *not fetched* (network error, missing file, ``--no-readme``) must
    never look the same as one that was fetched and parsed. The platform
    check in ``rules.py`` is three-state (``checked_clear`` / ``checked_conflict``
    / ``unchecked``) and depends on ``readme_status == "fetched"``.
    """
    owner: str
    repo: str

    exists: bool = False
    stars: int | None = None
    forks: int | None = None
    language: str | None = None
    description: str | None = None
    pushed_at: str | None = None  # ISO-8601 from GitHub, e.g. "2025-01-31T12:34:56Z"
    created_at: str | None = None
    default_branch: str | None = None  # used by the deep fetchers to skip a redundant ``/repos/{owner}/{repo}`` call
    archived: bool = False
    disabled: bool = False
    fork: bool = False
    parent_full_name: str | None = None
    license_spdx: str | None = None
    license_name: str | None = None
    readme_text: str | None = None
    readme_status: str = "missing"  # fetched | missing | binary | too_large | no_branch | error | skipped
    readme_license_files: list[str] = field(default_factory=list)
    moved_to: str | None = None
    private: bool = False
    error: str | None = None

    @property
    def full_name(self) -> str:
        """Return ``owner/repo``."""
        return f"{self.owner}/{self.repo}"


# ----- Claims / diff ------------------------------------------------------


@dataclass
class ClaimDiff:
    """One diff between an LLM's claim about a repo and the truth we fetched.

    ``match`` is tri-valued:
      * ``True``  — claimed matches what GitHub reported
      * ``False`` — claimed disagrees with GitHub
      * ``None``  — we could not parse the claim into a concrete value
    """
    full_name: str
    raw: str
    claim_type: str  # "star_count" | "license"
    claimed_value: str
    actual_value: str | None
    match: bool | None
    line_no: int | None = None


# ----- Decision layer output ----------------------------------------------


@dataclass
class Assessment:
    """A ``RepoFacts`` with the rules verdict applied.

    Returned by :func:`repofacts.rules.assess`. The renderer turns this into
    a table / JSON / Markdown row.
    """
    ref: RepoRef
    facts: RepoFacts

    verdict: str = "OK"  # OK | CAUTION | STOP
    reasons: list[str] = field(default_factory=list)
    licence_class: str = (
        "NONE"  # NONE | UNRECOGNISED | PERMISSIVE | COPYLEFT | NETWORK_COPYLEFT | SOURCE_AVAILABLE
    )
    licence_as_of: str = ""  # UTC ISO-8601 timestamp
    platform_check: str = "unchecked"  # checked_clear | checked_conflict | unchecked
    platform_notes: list[str] = field(default_factory=list)
    claim_diffs: list[ClaimDiff] = field(default_factory=list)
    multiple_licence_files: bool = False


# ----- Deep checks: security & quality ------------------------------------
#
# These dataclasses extend the repo-fact contract without touching the
# existing fields. ``DeepFacts`` (and its ``SecurityFacts`` /
# ``QualityFacts`` aliases) is populated by ``github.py`` — the only
# network module — and consumed by the pure ``security.py`` and
# ``quality.py`` assessors.
#
# The three-state ``Finding.status`` invariant (``pass | fail | warn | info
# | unchecked``) is the same one rules.py uses for ``platform_check``: a
# check that did not run is *never* allowed to render the same as a check
# that passed. ``unchecked`` is the explicit default for any data point
# the fetcher could not obtain.


#: ``Finding.status`` values. ``unchecked`` MUST be distinct from ``pass``.
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_WARN = "warn"
STATUS_INFO = "info"
STATUS_UNCHECKED = "unchecked"


#: ``Finding.severity`` values.
SEV_HIGH = "HIGH"
SEV_MED = "MED"
SEV_LOW = "LOW"
SEV_INFO = "INFO"


@dataclass
class Finding:
    """One named check result from the security or quality assessors.

    Attributes:
        name: The check name (e.g. ``"BranchProtection"``, ``"TestsPresent"``).
            Names mirror OpenSSF Scorecard conventions where applicable, but
            the implementation is ours.
        status: One of ``"pass"`` (``STATUS_PASS``), ``"fail"`` (``STATUS_FAIL``),
            ``"warn"`` (``STATUS_WARN``), ``"info"`` (``STATUS_INFO``), or
            ``"unchecked"`` (``STATUS_UNCHECKED``). ``unchecked`` is the
            default for every check that did not have its data fetched;
            it is NEVER the same as ``pass``.
        severity: One of ``"HIGH"`` (``SEV_HIGH``), ``"MED"`` (``SEV_MED``),
            ``"LOW"`` (``SEV_LOW``), ``"INFO"`` (``SEV_INFO``).
        reason: A one-line human-readable explanation. Safe to print.

    Returned by every individual check inside
    :func:`repofacts.security.assess_security` and
    :func:`repofacts.quality.assess_quality`.
    """
    name: str
    status: str
    severity: str
    reason: str


@dataclass
class DeepFacts:
    """Network-layer output for the deep security + quality checks.

    This is the **union** of the fields the security and quality
    assessors need. Both used to be near-identical dataclasses with ten
    fields of identical shape; the duplication forced a duplicated fetcher
    in :mod:`repofacts.github` (every ``--deep`` run burned the same five
    GitHub API call-groups twice per repo). One class is the right shape:
    every field is ``None`` / empty until
    :func:`repofacts.github.fetch_deep_facts` populates it, and a field
    that is still ``None`` after the fetcher ran means the data was not
    obtainable (404, permission, network) — the assess layer treats that
    as ``unchecked``, never as ``pass``.

    Fields unique to the security battery:

        * ``branch_protection`` — raw ``/branches/{branch}/protection``
        * ``has_security_policy`` — ``SECURITY.md`` lookup
        * ``commit_activity_weeks`` — ``/stats/commit_activity``
        * ``has_dependabot_config`` / ``has_renovate_config``

    Fields unique to the quality battery:

        * ``head_sha`` — default branch HEAD commit SHA
        * ``workflow_paths`` — ``.github/workflows/`` listing
        * ``tags`` — ``/tags``
        * ``recent_commits`` — ``/commits``
        * ``has_changelog`` — ``CHANGELOG.md`` lookup
        * ``readme_length`` — length of the fetched README
        * ``latest_check_conclusion`` — check-runs on HEAD
        * ``issue_response_hours`` — first-response timing

    Shared fields (same name, same type, identical semantics in both
    assessors): ``owner``, ``repo``, ``fetched_at``, ``default_branch``,
    ``releases``, ``tree_entries``, ``workflow_files``, ``contributors``,
    ``manifests``, ``error``. No collision on the union.

    All fields are raw or near-raw so the pure assess layer can decide
    what is and is not a problem without further I/O.
    """
    owner: str
    repo: str

    #: UTC timestamp captured when the fetcher ran. Pure assessors use
    #: this when ``now`` is not passed in; never overwritten downstream.
    fetched_at: datetime | None = None

    #: Default branch name from the repo metadata. ``None`` if the repo
    #: does not exist.
    default_branch: str | None = None

    # --- security-specific fields --------------------------------------

    #: Raw ``/branches/{branch}/protection`` payload, or ``None`` if the
    #: endpoint returned 404 (not protected) or was unreachable.
    branch_protection: dict | None = None

    #: ``True`` if a ``SECURITY.md`` (in any conventional location) was
    #: fetched, ``False`` if the lookup returned 404, ``None`` if the
    #: fetcher could not run.
    has_security_policy: bool | None = None

    #: ``/stats/commit_activity`` payload: a list of 52 weekly buckets,
    #: each with ``week`` (epoch seconds), ``total``, and ``days`` (a
    #: 7-element list of ints).
    commit_activity_weeks: list[dict] = field(default_factory=list)

    #: ``True``/``False``/``None`` for ``.github/dependabot.yml`` (or
    #: ``.yaml``) lookup.
    has_dependabot_config: bool | None = None

    #: ``True``/``False``/``None`` for ``renovate.json`` (or
    #: ``.renovaterc{,json,json5}``) lookup.
    has_renovate_config: bool | None = None

    # --- shared fields (identical semantics in both assessors) ---------

    #: Most recent releases (capped). Each entry is the raw GitHub
    #: release object: ``tag_name``, ``published_at``, ``assets``, etc.
    releases: list[dict] = field(default_factory=list)

    #: Workflow file contents: ``path -> YAML text``. Empty if no
    #: workflows were fetched.
    workflow_files: dict[str, str] = field(default_factory=dict)

    #: Repo tree (top 2 levels). Each entry has ``path``, ``type``
    #: (``"blob"`` or ``"tree"``), and optionally ``size``.
    tree_entries: list[dict] = field(default_factory=list)

    #: ``/contributors`` entries. Each entry has ``login`` and
    #: ``contributions`` (int).
    contributors: list[dict] = field(default_factory=list)

    #: Fetched manifest files: ``path -> content``. Path is the
    #: repo-relative path (``package.json``, ``pyproject.toml``, …).
    manifests: dict[str, str] = field(default_factory=dict)

    #: Network-layer error summary if the fetcher could not run at all.
    error: str | None = None

    # --- quality-specific fields ---------------------------------------

    #: SHA of the default branch's HEAD commit. Used to fetch check-runs.
    head_sha: str | None = None

    #: Workflow file *paths* (under ``.github/workflows/``). Used by
    #: CIConfigured.
    workflow_paths: list[str] = field(default_factory=list)

    #: Tag names from ``/releases`` or ``/tags``. Used by SemVerAdherence.
    tags: list[str] = field(default_factory=list)

    #: Recent commits (default-branch). Each entry has ``author.login``
    #: and ``commit.author.date``.
    recent_commits: list[dict] = field(default_factory=list)

    #: ``True``/``False``/``None`` for ``CHANGELOG.md`` (and a few
    #: variants) presence.
    has_changelog: bool | None = None

    #: Length of the fetched README in characters, or ``None`` if the
    #: README was not fetched.
    readme_length: int | None = None

    #: Conclusion of the latest check-run on the default branch's HEAD:
    #: ``"success"``, ``"failure"``, ``"neutral"``, ``"cancelled"``,
    #: ``"timed_out"``, ``"action_required"``, ``"skipped"``, or
    #: ``None`` if there were no check-runs.
    latest_check_conclusion: str | None = None

    #: Issue response times, in hours, for the most recent issues that
    #: had at least one comment. Empty if we did not / could not fetch.
    issue_response_hours: list[float] = field(default_factory=list)


#: Backward-compatible alias. The security assessor takes a
#: :class:`SecurityFacts`; with the union, that *is* a :class:`DeepFacts`.
#: Keeping the name means every existing type annotation, import, and
#: constructor call in the codebase and the tests still works.
SecurityFacts = DeepFacts

#: Backward-compatible alias. Same story as :data:`SecurityFacts`.
QualityFacts = DeepFacts


@dataclass
class SecurityReport:
    """Output of :func:`repofacts.security.assess_security`.

    Attributes:
        owner: GitHub owner.
        repo: GitHub repo name.
        findings: One :class:`Finding` per check, in declaration order.
    """
    owner: str
    repo: str
    findings: list[Finding] = field(default_factory=list)


@dataclass
class QualityReport:
    """Output of :func:`repofacts.quality.assess_quality`.

    Attributes:
        owner: GitHub owner.
        repo: GitHub repo name.
        findings: One :class:`Finding` per check, in declaration order.
    """
    owner: str
    repo: str
    findings: list[Finding] = field(default_factory=list)
