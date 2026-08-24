"""Pure verdict rules.

No I/O, no network, no clock reads beyond values passed in. Tests inject
``RepoFacts`` and a host string, and the rules are deterministic.

The non-negotiable subtlety this module exists to enforce:

    ``NONE != NOASSERTION``

A repo whose ``license.spdx_id`` is ``None`` has **no licence file at all** —
legally there is no grant, so the verdict must be ``STOP``. A repo with
``spdx_id == "NOASSERTION"`` has *some* licence file GitHub could not
identify, and the appropriate response is to sniff the README for BSL/ELv2/
Commons-Clause markers — see :func:`classify_licence`.

Other state machines kept here:

* **Liveness** — last-push >1y/2y, archived age, fork blindness.
* **Platform** — three-state (checked_clear / checked_conflict / unchecked).
  ``unchecked`` is the default when ``readme_status != "fetched"``; never a
  silent ``OK``.
* **Multiple licence files** — when ``LICENSES/`` or ``LICENSE-*`` is
  mentioned in the README we cannot in principle resolve it without reading
  every file, so we emit ``CAUTION: verify manually`` (a known limitation,
  stated not pretended away).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .models import Assessment, ClaimDiff, RepoFacts, RepoRef


# ---------------------------------------------------------------------------
# Licence classification
# ---------------------------------------------------------------------------

# SPDX identifiers that map to "permissive": use freely with attribution and
# preservation of copyright. Extends beyond the strict FSF/OSS list because
# some widely-used business-friendly licences (Elastic License v2 is *not*
# here — it is SOURCE_AVAILABLE).
_PERMISSIVE_IDS: frozenset[str] = frozenset({
    "MIT", "MIT-0",
    "Apache-2.0", "Apache-1.1", "Apache-1.0",
    "BSD-2-Clause", "BSD-3-Clause", "0BSD",
    "ISC",
    "Unlicense", "CC0-1.0",
    "Zlib", "libpng-2.0",
    "WTFPL",
    "W3C", "W3C-Software-and-Document",
    "AFL-3.0", "Artistic-2.0",
    "MS-PL",
    "MPL-2.0", "EPL-2.0", "EPL-1.0",
    "LGPL-2.1", "LGPL-3.0", "LGPL-2.0",
    "EUPL-1.2", "EUPL-1.1",
    "PSF-2.0", "Python-2.0",
    "NCSA",
    "OFL-1.1", "OFL-1.0",
    "BSL-1.0", "BSL",
})
# Strong copyleft — fine for end users, less so for embedded proprietary work.
_COPYLEFT_IDS: frozenset[str] = frozenset({
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
})
# Network copyleft — running the code is fine; *offering it as a service*
# forces source release. ``SSPL`` is Mongo's, with similar effect.
_NETWORK_COPYLEFT_IDS: frozenset[str] = frozenset({
    "AGPL-1.0", "AGPL-1.0-only",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0",
})
# Source-available — *not* open-source by OSI/FSF definitions but otherwise
# usable. We treat these as CAUTION: commercially restrictive.
_SOURCE_AVAILABLE_REGEXES = [
    re.compile(r"\bBusiness Source License\b", re.IGNORECASE),
    re.compile(r"\bBUSL[\s-]?1\.1\b", re.IGNORECASE),
    re.compile(r"\bElastic License\b(?!.*open)", re.IGNORECASE),
    re.compile(r"\bELv2\b", re.IGNORECASE),
    re.compile(r"\bElastic-2\.0\b", re.IGNORECASE),
    re.compile(r"\bServer Side Public License\b", re.IGNORECASE),
    re.compile(r"\bSSPL\b", re.IGNORECASE),
    re.compile(r"\bCommons Clause\b", re.IGNORECASE),
    re.compile(r"\bSource[-\s]?Available\b", re.IGNORECASE),
]


def classify_licence(
    spdx_id: str | None,
    license_name: str | None,
    readme_text: str | None,
) -> str:
    """Classify a repo's licence into one of the known categories.

    Returns one of:
        ``NONE``             — *no* licence file at all (STOP)
        ``UNRECOGNISED``     — file exists but neither GitHub nor the
                               heuristics could identify it (CAUTION: caller
                               decides)
        ``PERMISSIVE``       — MIT, Apache, BSD, MPL, …
        ``COPYLEFT``         — GPL
        ``NETWORK_COPYLEFT`` — AGPL, SSPL
        ``SOURCE_AVAILABLE`` — BSL, ELv2, Commons Clause
    """
    spdx = (spdx_id or "").strip()
    name = (license_name or "").strip()
    text = readme_text or ""

    # ``NONE`` is distinct from ``NOASSERTION``: we have *no licence file*.
    # This depends ONLY on GitHub's licence fields. The README is NOT evidence
    # of a licence grant, and including it here made ``NONE`` unreachable for
    # any repo that has a README — i.e. almost all of them.
    # REAL CASE av/facts (2026-08-24): license: null, long README, must be NONE.
    if not spdx and not name:
        return "NONE"

    no_asser = spdx in {"", "NOASSERTION", "noassertion", "other", "Other", "None"}

    if no_asser:
        # Sniff for source-available markers in both the licence-name field
        # GitHub returned and the README body.
        haystack = f"{name}\n{text}"
        for pat in _SOURCE_AVAILABLE_REGEXES:
            if pat.search(haystack):
                return "SOURCE_AVAILABLE"
        return "UNRECOGNISED"

    if spdx in _NETWORK_COPYLEFT_IDS:
        return "NETWORK_COPYLEFT"
    if spdx in _COPYLEFT_IDS:
        return "COPYLEFT"
    if spdx in _PERMISSIVE_IDS:
        return "PERMISSIVE"

    # Some licences are reported under a variant or alias GitHub doesn't
    # canonicalise; fall back to UNRECOGNISED rather than guess.
    return "UNRECOGNISED"


# ---------------------------------------------------------------------------
# Liveness
# ---------------------------------------------------------------------------


def _years_since(iso_str: str | None, now: datetime) -> float | None:
    """Return ``years`` between ``iso_str`` (ISO-8601) and ``now`` (UTC-aware).

    Returns ``None`` if the input is empty or unparseable. Timezones are
    normalised to UTC; non-UTC-aware inputs are treated as UTC.
    """
    if not iso_str:
        return None
    try:
        s = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).days / 365.25


# ---------------------------------------------------------------------------
# Platform fitness
# ---------------------------------------------------------------------------

# Token → regex. Order does not matter; we test every one independently.
_HARD_PLATFORM_TOKENS: dict[str, re.Pattern] = {
    "CUDA": re.compile(r"\bCUDA\b"),
    "NVIDIA": re.compile(r"\bNVIDIA\b"),
    "TensorRT": re.compile(r"\bTensorRT\b"),
    "ROCm": re.compile(r"\bROCm\b"),
    "Linux-only": re.compile(r"\bLinux[- ]only\b", re.IGNORECASE),
    "Windows-only": re.compile(r"\bWindows[- ]only\b", re.IGNORECASE),
    "macOS-only": re.compile(r"\b(?:macOS|Mac OS X?)[- ]only\b", re.IGNORECASE),
    "ESP32": re.compile(r"\bESP32\b"),
    "Arduino": re.compile(r"\bArduino\b"),
    "Raspberry-Pi": re.compile(r"\bRaspberry\s*Pi\b"),
}

# Signals that we are inside a "prerequisites / installation" section, used to
# discount passing mentions like "unlike CUDA-based tools we don't need a
# GPU" or "doesn't require ESP32".
_REQUIREMENT_CONTEXT = [
    re.compile(r"(?im)^#+\s*(requirement|prereq|prerequisites|install|installation"
              r"|setup|getting\s+started|hardware|supported\s+platforms|build"
              r"|dependencies|requirements?)"),
    re.compile(r"(?im)^\s*[-*+]\s+"),                # bullet list
    re.compile(r"(?im)^\s*\|"),                      # table cell
    re.compile(r"(?i)you(?:'| wi)?ll\s+need"),
    re.compile(r"(?i)requires?\s+(?:a\s+|the\s+|an\s+)?"),
    re.compile(r"(?i)must\s+have"),
    re.compile(r"(?i)needs?\s+to\s+(?:be\s+)?installed"),
]


def _in_requirement_context(text: str, line_index: int) -> bool:
    """Return True if any of the requirement-context regexes match near this line."""
    lines = text.splitlines()
    window = lines[max(0, line_index - 5): min(len(lines), line_index + 3)]
    blob = "\n".join(window)
    return any(rx.search(blob) for rx in _REQUIREMENT_CONTEXT)


def _platform_conflicts_for_host(
    text: str, host_system: str, host_machine: str
) -> list[str]:
    """Find README mentions of hard platform requirements that don't fit host.

    Returns a list of human-readable notes, each one quoting the suspect line.
    """
    host = (host_system or "").lower()
    notes: list[str] = []
    if not text:
        return notes

    for line_index, line in enumerate(text.splitlines()):
        for label, pattern in _HARD_PLATFORM_TOKENS.items():
            if not pattern.search(line):
                continue
            if not _in_requirement_context(text, line_index):
                # Discount passing mentions, but only if the line is short
                # (typical of an "unlike X" aside). Be loud about uncertainty.
                if len(line) > 200:
                    continue
                if "unlike" in line.lower() or "no need for" in line.lower():
                    continue
            # Decide whether host matches.
            conflict = False
            if label in {"CUDA", "NVIDIA", "TensorRT", "ROCm"}:
                # We can't know about GPU availability without probing; we
                # surface this as a note rather than a hard STOP per the
                # Phase-3 finding "a false STOP is worse than a missed
                # CAUTION".
                notes.append(
                    f"line {line_index + 1}: '{line.strip()[:120]}' "
                    f"hosts={host_system}/{host_machine}"
                )
            elif label.endswith("only"):
                wanted = label.split("-")[0].lower()
                wanted = {"macos-only": "darwin"}.get(label.lower(), wanted)
                if host != wanted:
                    notes.append(
                        f"line {line_index + 1}: '{line.strip()[:120]}' "
                        f"but host is {host_system}"
                    )
            else:  # ESP32, Arduino, Raspberry-Pi
                notes.append(
                    f"line {line_index + 1}: '{line.strip()[:120]}' "
                    f"(embedded target on {host_system})"
                )
            # Note: we set ``conflict`` for symmetry but don't currently
            # branch on it — every conflict is a CAUTION note, not a STOP.
            _ = conflict
    return notes


def assess_platform(
    facts: RepoFacts, host_system: str, host_machine: str
) -> tuple[str, list[str]]:
    """Three-state platform check: ``checked_clear`` / ``checked_conflict`` /
    ``unchecked``.

    Per the Phase-3 finding, a check that did *not* happen must never look the
    same as a check that passed. Returns ``("unchecked", [])`` whenever the
    README wasn't fetched.
    """
    if facts.readme_status != "fetched" or not facts.readme_text:
        return "unchecked", []

    notes = _platform_conflicts_for_host(
        facts.readme_text, host_system, host_machine
    )
    if notes:
        return "checked_conflict", notes
    return "checked_clear", []


# ---------------------------------------------------------------------------
# Verdict composition
# ---------------------------------------------------------------------------


def assess(
    ref: RepoRef,
    facts: RepoFacts,
    host_system: str,
    host_machine: str,
    *,
    now: datetime | None = None,
    claim_diffs: list[ClaimDiff] | None = None,
    min_stars: int = 25,
) -> Assessment:
    """Combine all of the above into a single :class:`Assessment`.

    Precedence:
      * If the repo doesn't exist or is disabled, ``STOP`` immediately.
      * Otherwise, walk the rules; any CAUTION condition tightens the verdict
        upward (OK → CAUTION). STOPs are reported if and only if a hard-stop
        rule triggers.

    The reason strings are intentionally short and human-readable: they are
    what the user sees, and a v2 here is where to spend effort on wording.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    claim_diffs = claim_diffs or []

    reasons: list[str] = []
    verdict = "OK"

    # ----- Hard STOPs ------------------------------------------------------

    if not facts.exists:
        if facts.moved_to:
            reasons.append(f"repo moved to {facts.moved_to}")
        elif facts.error:
            reasons.append(f"could not verify — {facts.error}")
        else:
            reasons.append("repo not found on GitHub")
        return Assessment(
            ref=ref,
            facts=facts,
            verdict="STOP",
            reasons=reasons,
            licence_as_of=now.isoformat(),
        )

    if facts.disabled:
        reasons.append("repo disabled by GitHub")
        return Assessment(
            ref=ref,
            facts=facts,
            verdict="STOP",
            reasons=reasons,
            licence_as_of=now.isoformat(),
        )

    # ----- Licence ---------------------------------------------------------

    licence_class = classify_licence(
        facts.license_spdx, facts.license_name, facts.readme_text
    )
    if licence_class == "NONE":
        verdict = "STOP"
        reasons.append("no licence file at all — no grant of any rights")
    elif licence_class == "SOURCE_AVAILABLE":
        verdict = _raise(verdict, "CAUTION")
        reasons.append(
            "source-available licence (BSL/ELv2/SSPL/Commons Clause) — "
            "not open source, commercially restrictive"
        )
    elif licence_class == "NETWORK_COPYLEFT":
        verdict = _raise(verdict, "CAUTION")
        spdx = facts.license_spdx or "AGPL"
        reasons.append(
            f"network copyleft ({spdx}) — embedding in a proprietary network "
            f"service requires sharing source"
        )
    elif licence_class == "UNRECOGNISED":
        verdict = _raise(verdict, "CAUTION")
        reasons.append(
            "licence present but not an SPDX-recognised open-source licence"
        )

    # ----- Adoption --------------------------------------------------------
    # REAL CASE D0NMEGA/donnyclaude (2026-08-24): 8 stars, ranked #1 by the
    # model. A tiny star count is not proof of low quality -- a good new repo
    # starts at zero -- so this is CAUTION, never STOP. It exists so the
    # rank-vs-reality gap becomes visible, which is the product's whole point.
    if facts.stars is not None and facts.stars < min_stars:
        verdict = _raise(verdict, "CAUTION")
        reasons.append(
            f"only {facts.stars} stars — very few users; verify this is really "
            f"the best option for you"
        )

    # ----- Liveness --------------------------------------------------------

    yrs_push = _years_since(facts.pushed_at, now)

    if yrs_push is not None and yrs_push > 1.0:
        # Phase-3: do not STOP on liveness; only CAUTION.
        verdict = _raise(verdict, "CAUTION")
        reasons.append(f"last push ~{yrs_push:.1f}y ago")

    # ----- Archived -------------------------------------------------------

    if facts.archived:
        # Stale archive → CAUTION; fresh archive → OK with note.
        if yrs_push is not None and yrs_push > 2.0:
            verdict = _raise(verdict, "CAUTION")
            if facts.moved_to:
                reasons.append(
                    f"archived, last push ~{yrs_push:.1f}y ago; moved to {facts.moved_to}"
                )
            else:
                reasons.append(
                    f"archived, last push ~{yrs_push:.1f}y ago; check for successor"
                )
        else:
            reasons.append("archived (no successor known)")

    # ----- Fork blindness -------------------------------------------------

    if (
        facts.fork
        and facts.parent_full_name
        and (facts.stars is None or facts.stars < 200)
    ):
        verdict = _raise(verdict, "CAUTION")
        reasons.append(
            f"low-star fork of {facts.parent_full_name} — README may be copied from upstream"
        )

    # ----- Multiple licence files -----------------------------------------

    multiple = bool(facts.readme_license_files)
    if multiple:
        verdict = _raise(verdict, "CAUTION")
        reasons.append(
            "multiple licence files detected (LICENSES/ or LICENSE-*) — verify manually"
        )

    # ----- Platform check -------------------------------------------------

    platform_state, platform_notes = assess_platform(facts, host_system, host_machine)
    if platform_state == "checked_conflict":
        verdict = _raise(verdict, "CAUTION")
        for note in platform_notes:
            reasons.append(f"platform mismatch: {note}")

    # ----- Private to token -----------------------------------------------

    if facts.private:
        reasons.append("private — visible to your token, not to your users")

    # ----- Claim mismatches ----------------------------------------------

    for cd in claim_diffs:
        if cd.match is False:
            verdict = _raise(verdict, "CAUTION")
            if cd.claim_type == "star_count":
                reasons.append(
                    f"claimed {cd.claimed_value} stars on line {cd.line_no}, actual {cd.actual_value}"
                )
            elif cd.claim_type == "license":
                reasons.append(
                    f"claimed licence {cd.claimed_value} on line {cd.line_no}, actual {cd.actual_value or 'NONE'}"
                )

    return Assessment(
        ref=ref,
        facts=facts,
        verdict=verdict,
        reasons=reasons,
        licence_class=licence_class,
        licence_as_of=now.isoformat(),
        platform_check=platform_state,
        platform_notes=platform_notes,
        claim_diffs=claim_diffs,
        multiple_licence_files=multiple,
    )


def _raise(current: str, target: str) -> str:
    """Order-of-severity helper. ``STOP > CAUTION > OK``."""
    rank = {"OK": 0, "CAUTION": 1, "STOP": 2}
    return current if rank[current] >= rank[target] else target
