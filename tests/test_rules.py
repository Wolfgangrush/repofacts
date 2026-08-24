"""Tests for the pure decision layer.

Per the project's model-separation rule, whoever writes the implementation does
not write its tests. These encode real cases observed on 2026-08-24, not
invented ones.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from repofacts.models import RepoFacts, RepoRef  # noqa: E402
from repofacts.rules import assess, classify_licence  # noqa: E402

NOW = datetime(2026, 8, 24, 14, 0, 0, tzinfo=timezone.utc)


def _ref(owner="o", repo="r"):
    return RepoRef(owner=owner, repo=repo, raw_mention=f"{owner}/{repo}")


def _facts(**kw):
    base = dict(
        owner="o", repo="r", exists=True, stars=1000, forks=10,
        pushed_at="2026-08-01T00:00:00Z", created_at="2024-01-01T00:00:00Z",
        license_spdx="MIT", license_name="MIT License",
        readme_text="# a project\ninstall it\n", readme_status="fetched",
    )
    base.update(kw)
    return RepoFacts(**base)


def _assess(**kw):
    return assess(_ref(), _facts(**kw), "Darwin", "arm64", now=NOW)


# --- licence classification: NONE must not depend on the README ------------

def test_no_licence_file_is_NONE_even_when_readme_is_long():
    """REAL CASE av/facts (2026-08-24): GitHub returns license: null.

    No licence file = no grant of rights = STOP. The README is irrelevant to
    that fact. Including readme_text in the emptiness test made NONE
    effectively unreachable, since nearly every repo has a README.
    """
    assert classify_licence(None, None, "# a long readme\n" * 200) == "NONE"


def test_no_licence_file_is_NONE_with_empty_readme():
    assert classify_licence(None, None, "") == "NONE"


def test_no_licence_repo_is_STOP_not_caution():
    a = _assess(license_spdx=None, license_name=None)
    assert a.verdict == "STOP", f"expected STOP, got {a.verdict}: {a.reasons}"


def test_noassertion_with_elv2_marker_is_source_available():
    """REAL CASE mksglu/context-mode: API says NOASSERTION, badge says ELv2."""
    assert classify_licence("NOASSERTION", "Other", "License: ELv2") == "SOURCE_AVAILABLE"


def test_noassertion_without_marker_is_unrecognised():
    assert classify_licence("NOASSERTION", "Other", "plain readme") == "UNRECOGNISED"


def test_recognised_licences():
    assert classify_licence("MIT", "MIT License", "") == "PERMISSIVE"
    assert classify_licence("AGPL-3.0", "AGPL", "") == "NETWORK_COPYLEFT"
    assert classify_licence("GPL-3.0", "GPL", "") == "COPYLEFT"


# --- the headline case: a low-star repo ranked #1 by a model ---------------

def test_very_low_star_repo_is_flagged():
    """REAL CASE D0NMEGA/donnyclaude — 8 stars, ranked #1 by the model.

    This single case is why the tool exists. Returning OK here makes the
    product pointless.
    """
    a = _assess(stars=8)
    assert a.verdict != "OK", f"8-star repo returned OK: {a.reasons}"
    assert any("star" in r.lower() for r in a.reasons), a.reasons


def test_healthy_popular_repo_is_OK():
    """The false-STOP guard: a healthy repo must stay OK (FALSIFIER #1)."""
    a = _assess(stars=5649, license_spdx="Apache-2.0", license_name="Apache 2.0")
    assert a.verdict == "OK", f"healthy repo not OK: {a.reasons}"


# --- archived: corrected in the Phase-3 pass -------------------------------

def test_freshly_archived_is_not_stop():
    a = _assess(archived=True, pushed_at="2026-06-01T00:00:00Z")
    assert a.verdict != "STOP", a.reasons


def test_long_archived_is_caution_not_stop():
    a = _assess(archived=True, pushed_at="2022-01-01T00:00:00Z")
    assert a.verdict == "CAUTION", a.reasons


# --- fork blindness (Phase-3 finding #6) -----------------------------------

def test_low_star_fork_is_flagged_and_names_parent():
    a = _assess(stars=8, fork=True, parent_full_name="famous/upstream")
    assert a.verdict != "OK"
    assert any("famous/upstream" in r for r in a.reasons), a.reasons


# --- platform: three states, unchecked must not read as clear --------------

def test_platform_conflict_on_mac_is_flagged():
    """REAL CASE aiptimizer/TurboOCR — Linux + NVIDIA only, on Apple Silicon."""
    a = _assess(readme_text="## Requirements\nLinux, NVIDIA driver 595+, CUDA, TensorRT")
    assert a.verdict in ("STOP", "CAUTION"), a.reasons
    assert any("nvidia" in r.lower() or "cuda" in r.lower() or "linux" in r.lower()
               for r in a.reasons), a.reasons


def test_unchecked_readme_is_not_reported_as_clear():
    """A check that did not run must never render like a check that passed."""
    a = _assess(readme_text=None, readme_status="missing")
    assert a.platform_check == "unchecked", a.platform_check


# --- existence -------------------------------------------------------------

def test_missing_repo_is_stop():
    a = _assess(exists=False)
    assert a.verdict == "STOP"
