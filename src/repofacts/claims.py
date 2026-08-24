"""Pure claim extraction and diff.

Narrow on purpose. The Phase-3 hard-question pass explicitly recorded that a
broad regex grammar mostly emits "not parsed" — so we extract *only* the two
highest-frequency, highest-signal claim shapes LLM output actually produces:

    1. Star counts in the vicinity of a repo mention (e.g. ``"12.4k stars"``)
    2. SPDX-ish licence tokens anywhere on the line of a repo mention.

Everything else reports ``match=None`` so the renderer can say "not parsed",
not "I checked and you're wrong".
"""

from __future__ import annotations

import re

from .models import ClaimDiff, RepoFacts, RepoRef


# ---------------------------------------------------------------------------
# Star-count patterns
# ---------------------------------------------------------------------------
#
# Capture groups: (numeric, suffix).
#   "10k stars"    → ("10", "k")
#   "1.2M stars"   → ("1.2", "M")
#   "10,000 stars" → ("10,000", "")
#   "100 stars"    → ("100", "")
#   "10★"          → ("10", "")
#
# We are deliberately permissive on suffixes; we are deliberately strict on
# requiring ``stars`` / ``★`` to follow so we don't pick up every random
# number in text.

# NOTE on the trailing word boundary: it belongs *inside* the alternation, on
# the ``stars?`` branch only. ``\b`` after ``★`` can never hold in real prose —
# ``★`` is a non-word character, so a boundary would require the very next
# character to be a word character, which rules out "10★", "10★." and "10★ ".
# Hanging the ``\b`` off the whole group made the documented ``N★`` form dead.
_STAR_PATTERNS = [
    re.compile(r"\b(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)\s*([kKmMbB]?)\s*(?:stars?\b|★)"),
    re.compile(r"(?:stars?|★)\s*(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)\s*([kKmMbB]?)\b"),
]

# ---------------------------------------------------------------------------
# SPDX-ish licence tokens. Match whole word, case-insensitively.
# ---------------------------------------------------------------------------

_SPDX_TOKENS = (
    "MIT", "Apache-2.0", "Apache-1.1", "BSD-3-Clause", "BSD-2-Clause",
    "ISC", "GPL-2.0", "GPL-3.0", "AGPL-3.0", "AGPL-1.0",
    "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0", "EPL-1.0",
    "Unlicense", "BSL-1.1", "BUSL-1.1", "Elastic-2.0",
    "SSPL-1.0", "NOASSERTION", "ELv2",
    "0BSD", "CC0-1.0",
)


def _parse_star_count(value: str, suffix: str) -> int | None:
    """Parse ``"10"`` / ``"10.5"`` with suffix ``k/m/b`` into an int.

    Returns ``None`` for any unparseable shape; we don't want to emit "0"
    for nonsense and then claim it didn't match.
    """
    try:
        n = float(value.replace(",", ""))
    except ValueError:
        return None
    s = suffix.lower()
    if s == "k":
        n *= 1_000
    elif s == "m":
        n *= 1_000_000
    elif s == "b":
        n *= 1_000_000_000
    return int(round(n))


def _spdx_matchers() -> list[tuple[str, re.Pattern]]:
    return [(tok, re.compile(rf"\b{re.escape(tok)}\b", re.IGNORECASE)) for tok in _SPDX_TOKENS]


def extract_claims(text: str, refs: list[RepoRef]) -> list[dict]:
    """Find star / licence claims in ``text``, scoped to nearby repo mentions.

    A claim is associated to a repo when it appears on the same line as the
    repo's ``owner/repo`` mention, or within ±2 lines (adjacent lines in
    typical LLM output).

    Returns:
        A list of dicts:
            ``{"owner", "repo", "claim_type", "claimed_value", "raw", "line_no"}``
        where ``claim_type`` is ``"star_count"`` or ``"license"``.

    The function does not consult any network — it is suitable for offline
    testing with fixtures.
    """
    lines = text.splitlines()

    # Build line → refs map. A ref covers its anchor line plus ±2 lines.
    refs_by_line: dict[int, list[RepoRef]] = {}
    for ref in refs:
        for i, line in enumerate(lines, start=1):
            full = ref.full_name.lower()
            if full in line.lower():
                for d in (0, -1, -2, 1, 2):
                    nl = i + d
                    if nl > 0:
                        refs_by_line.setdefault(nl, []).append(ref)
                # Also: lines that reference just the repo by ``repo`` name in
                # the immediate context, but only if the owner is mentioned
                # elsewhere too. We keep this conservative.

    out: list[dict] = []
    spdx = _spdx_matchers()
    seen: set = set()

    for line_no, line in enumerate(lines, start=1):
        refs_here = refs_by_line.get(line_no)
        if not refs_here:
            continue
        # Star counts.
        for pat in _STAR_PATTERNS:
            for m in pat.finditer(line):
                nstr = m.group(1)
                suf = m.group(2) or ""
                parsed = _parse_star_count(nstr, suf)
                if parsed is None:
                    continue
                for r in refs_here:
                    key = (r.full_name.lower(), "star_count", str(parsed), line_no)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({
                        "owner": r.owner,
                        "repo": r.repo,
                        "claim_type": "star_count",
                        "claimed_value": str(parsed),
                        "raw": m.group(0),
                        "line_no": line_no,
                    })
        # SPDX tokens.
        for tok, pat in spdx:
            for m in pat.finditer(line):
                for r in refs_here:
                    key = (r.full_name.lower(), "license", tok, line_no)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({
                        "owner": r.owner,
                        "repo": r.repo,
                        "claim_type": "license",
                        "claimed_value": tok,
                        "raw": m.group(0),
                        "line_no": line_no,
                    })

    return out


def diff_claims(
    claims: list[dict], facts_by_full: dict[str, RepoFacts]
) -> list[ClaimDiff]:
    """Compare extracted claims to fetched facts.

    ``facts_by_full`` is keyed by lowercase ``owner/repo``.

    ``match`` is tri-valued:
        ``True``  — claimed value == GitHub-attested value
        ``False`` — they disagree
        ``None``  — either the claim or the truth is unparseable
    """
    diffs: list[ClaimDiff] = []
    for c in claims:
        full = f"{c['owner']}/{c['repo']}"
        key = full.lower()
        facts = facts_by_full.get(key)
        if facts is None:
            continue
        actual: str | None
        match: bool | None
        if c["claim_type"] == "star_count":
            actual = str(facts.stars) if facts.stars is not None else None
            if actual is None:
                # We never obtained a star count, so the check did not run.
                # An unchecked check is None — never False. Reporting False
                # here would make rules.py escalate to CAUTION and print
                # "claimed N stars, actual None", i.e. accuse the model of
                # inventing a number we simply never fetched.
                match = None
            else:
                try:
                    match = int(actual) == int(c["claimed_value"])
                except ValueError:
                    # The claimed value is not an integer — unparseable, so
                    # again unchecked rather than a confident mismatch.
                    match = None
            diffs.append(ClaimDiff(
                full_name=full,
                raw=c.get("raw", ""),
                claim_type="star_count",
                claimed_value=c["claimed_value"],
                actual_value=actual,
                match=match,
                line_no=c.get("line_no"),
            ))
        elif c["claim_type"] == "license":
            actual = facts.license_spdx
            # Strip any ``-only`` / ``-or-later`` suffix before comparing.
            norm = re.sub(r"(-only|-or-later)$", "", actual or "", flags=re.IGNORECASE)
            claimed_norm = re.sub(
                r"(-only|-or-later)$", "", c["claimed_value"], flags=re.IGNORECASE
            )
            match = (norm.upper() == claimed_norm.upper()) if actual else None
            diffs.append(ClaimDiff(
                full_name=full,
                raw=c.get("raw", ""),
                claim_type="license",
                claimed_value=c["claimed_value"],
                actual_value=actual,
                match=match,
                line_no=c.get("line_no"),
            ))
        else:
            diffs.append(ClaimDiff(
                full_name=full,
                raw=c.get("raw", ""),
                claim_type=c["claim_type"],
                claimed_value=c["claimed_value"],
                actual_value=None,
                match=None,
                line_no=c.get("line_no"),
            ))
    return diffs
