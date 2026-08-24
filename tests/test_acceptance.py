"""ACCEPTANCE — the BMAD falsifier, replayed offline.

04-BMAD-SPEC names this the acceptance criterion: reproduce every failure a
human caught by hand across the three real 2026-08-24 recommendation lists,
with ZERO false STOPs. Facts below are the values verified live via `gh api`
on 2026-08-24, frozen as fixtures so the gate is deterministic and offline.
"""
from __future__ import annotations
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from repofacts.models import RepoFacts, RepoRef  # noqa: E402
from repofacts.rules import assess  # noqa: E402

NOW = datetime(2026, 8, 24, 16, 0, 0, tzinfo=timezone.utc)


def _a(owner, repo, **kw):
    base = dict(
        owner=owner, repo=repo, exists=True, stars=1000, forks=10,
        pushed_at="2026-08-20T00:00:00Z", created_at="2024-01-01T00:00:00Z",
        license_spdx="MIT", license_name="MIT License",
        readme_text="# project\n", readme_status="fetched",
    )
    base.update(kw)
    return assess(RepoRef(owner=owner, repo=repo, raw_mention=f"{owner}/{repo}"),
                  RepoFacts(**base), "Darwin", "arm64", now=NOW)


# ---- must be caught (the human caught each of these by hand) --------------

def test_fabricated_repo_is_stop():
    assert _a("thisorgdoesnotexist12345", "nope", exists=False).verdict == "STOP"

def test_no_licence_file_is_stop():
    """av/facts — GitHub returns license: null."""
    a = _a("av", "facts", stars=199, license_spdx=None, license_name=None)
    assert a.verdict == "STOP", a.reasons

def test_eight_star_top_pick_is_flagged():
    """D0NMEGA/donnyclaude — the model's #1 pick."""
    a = _a("D0NMEGA", "donnyclaude", stars=8)
    assert a.verdict != "OK", a.reasons

def test_twentyfour_star_top_pick_is_flagged():
    """chuchuyei/SentiCore — agy's #1 the following sweep."""
    assert _a("chuchuyei", "SentiCore", stars=24).verdict != "OK"

def test_two_year_dead_repo_is_flagged():
    """suno-ai/bark — 39k stars, last push 2024-08."""
    a = _a("suno-ai", "bark", stars=39250, pushed_at="2024-08-19T00:00:00Z")
    assert a.verdict == "CAUTION", a.reasons

def test_nvidia_linux_only_on_apple_silicon_is_flagged():
    """aiptimizer/TurboOCR — recommended to a Mac user."""
    a = _a("aiptimizer", "TurboOCR", stars=1019,
           readme_text="## Requirements\nLinux, NVIDIA driver 595+, CUDA, TensorRT")
    assert a.verdict in ("STOP", "CAUTION"), a.reasons

def test_source_available_licence_is_flagged():
    """mksglu/context-mode — NOASSERTION on the API, ELv2 in reality."""
    a = _a("mksglu", "context-mode", stars=20108,
           license_spdx="NOASSERTION", license_name="Other",
           readme_text="License: ELv2")
    assert a.verdict != "OK", a.reasons


# ---- FALSIFIER #1: zero false STOPs on healthy repos ---------------------

HEALTHY = [
    ("ossf", "scorecard", 5649, "Apache-2.0"),
    ("google", "osv-scanner", 10911, "Apache-2.0"),
    ("espanso", "espanso", 14341, "GPL-3.0"),
    ("cocoindex-io", "cocoindex", 11391, "Apache-2.0"),
    ("graykode", "abtop", 3467, "MIT"),
]

def test_no_false_stop_on_any_healthy_repo():
    """Falsifier #1. A single false STOP means the ruleset is wrong."""
    bad = []
    for owner, repo, stars, spdx in HEALTHY:
        a = _a(owner, repo, stars=stars, license_spdx=spdx, license_name=spdx)
        if a.verdict == "STOP":
            bad.append(f"{owner}/{repo}: {a.reasons}")
    assert not bad, f"FALSE STOP on healthy repos: {bad}"
