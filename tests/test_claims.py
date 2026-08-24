"""Tests for ``repofacts.claims`` — pure star/licence claim extraction and diffing.

The load-bearing invariant exercised throughout: a check that could not run
must report itself as unchecked. In this module that is ``ClaimDiff.match``
being tri-valued — ``True`` (agrees), ``False`` (disagrees), ``None`` (we
could not parse or could not check). ``None`` must never collapse into
``False``: ``rules.py`` escalates the verdict to CAUTION on ``match is False``,
so a mis-typed ``None`` becomes a public accusation that the LLM lied about a
number we never actually fetched.

Everything here is offline and deterministic — ``claims.py`` is a pure
function over text.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from repofacts import claims as claims_mod
from repofacts.claims import diff_claims, extract_claims
from repofacts.models import RepoFacts, RepoRef


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ref(owner: str, repo: str, line_no: int | None = 1) -> RepoRef:
    """Build a RepoRef the way ``extract.extract_refs`` would."""
    return RepoRef(owner=owner, repo=repo, raw_mention=f"{owner}/{repo}", line_no=line_no)


def _star_claim(value: str, owner: str = "team", repo: str = "project", line_no: int = 1) -> dict:
    """Build a hand-made ``star_count`` claim dict (the shape extract_claims emits)."""
    return {
        "owner": owner,
        "repo": repo,
        "claim_type": "star_count",
        "claimed_value": value,
        "raw": f"{value} stars",
        "line_no": line_no,
    }


def _license_claim(token: str, owner: str = "team", repo: str = "project", line_no: int = 1) -> dict:
    """Build a hand-made ``license`` claim dict."""
    return {
        "owner": owner,
        "repo": repo,
        "claim_type": "license",
        "claimed_value": token,
        "raw": token,
        "line_no": line_no,
    }


def _stars(claims: list[dict]) -> list[dict]:
    return [c for c in claims if c["claim_type"] == "star_count"]


def _licences(claims: list[dict]) -> list[dict]:
    return [c for c in claims if c["claim_type"] == "license"]


# ---------------------------------------------------------------------------
# Star-count extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spoken,expected", [
    ("12.4k stars", "12400"),
    ("1.2M stars", "1200000"),
    ("10,000 stars", "10000"),
    ("250 stars", "250"),
    ("3B stars", "3000000000"),
    ("1 star", "1"),
])
def test_star_suffix_arithmetic(spoken, expected):
    """Every supported star shape must resolve to the right integer-as-string.

    ``k`` -> x1_000, ``M`` -> x1_000_000, ``B`` -> x1_000_000_000, comma
    groupings stripped. If any shape resolved to a different number the diff
    layer would either miss a real fabrication or invent a fake one.
    """
    text = f"Take a look at team/project — {spoken} on GitHub.\n"
    got = _stars(extract_claims(text, [_ref("team", "project")]))
    assert len(got) == 1, f"expected exactly one star claim for {spoken!r}, got {got}"
    assert got[0]["claimed_value"] == expected, (
        f"{spoken!r} must parse to {expected!r}, got {got[0]['claimed_value']!r}"
    )


@pytest.mark.parametrize("spoken,expected", [
    ("12.4k★", "12400"),
    ("250★", "250"),
])
def test_star_glyph_suffix_form_is_parsed(spoken, expected):
    """The ``N★`` glyph form is a documented supported shape and must parse.

    ``claims.py``'s own module comment lists ``"10★" -> ("10", "")`` as a
    capture example and the regex carries a ``★`` alternative, so an LLM
    writing "12.4k★" must get its number verified like anyone else. Failing
    to extract it is a silent miss — the claim never reaches the diff layer
    and the user is never told it went unchecked.
    """
    text = f"Take a look at team/project — {spoken} on GitHub.\n"
    got = _stars(extract_claims(text, [_ref("team", "project")]))
    assert len(got) == 1, f"expected exactly one star claim for {spoken!r}, got {got}"
    assert got[0]["claimed_value"] == expected, (
        f"{spoken!r} must parse to {expected!r}, got {got[0]['claimed_value']!r}"
    )


@pytest.mark.parametrize("line", [
    "team/project is version 3 and has 4000 users right now.",
    "team/project shipped 12 releases and 900 commits.",
    "team/project — see issue 4200 for the roadmap.",
    "team/project has 10 starships in the demo.",
])
def test_bare_number_is_never_guessed_to_be_a_star_count(line):
    """A number without ``stars``/``★`` must NOT become a star claim.

    The module is deliberately strict here: guessing that "4000 users" means
    4000 stars would let repofacts report a mismatch against a claim the LLM
    never made. Silence is the only honest output.
    """
    got = _stars(extract_claims(line + "\n", [_ref("team", "project")]))
    assert got == [], f"no star claim may be inferred from {line!r}, got {got}"


def _text_with_claim_at_distance(distance: int) -> str:
    """Build text where the star claim sits ``distance`` lines from the mention.

    Negative distance puts the claim *above* the mention, positive below,
    zero on the same line.
    """
    mention = "Check out team/project today."
    claim = "It has 12.4k stars."
    if distance == 0:
        lines = [f"{mention} It has 12.4k stars."]
    elif distance > 0:
        lines = [mention] + [""] * (distance - 1) + [claim]
    else:
        lines = [claim] + [""] * (abs(distance) - 1) + [mention]
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("distance,should_attribute", [
    (0, True),    # same line
    (1, True),    # one line below
    (2, True),    # bottom edge of the +/-2 window
    (3, False),   # one past the edge
    (6, False),   # far away
    (-1, True),   # one line above
    (-2, True),   # top edge of the window
    (-3, False),  # one past the edge, upwards
])
def test_proximity_window_is_plus_minus_two_lines(distance, should_attribute):
    """Claims attach to a repo only within +/-2 lines of its mention.

    Beyond that window the number almost certainly belongs to a different
    repo, so attributing it would manufacture a false mismatch. Inside the
    window it must attach — otherwise real fabrications go unchecked.
    """
    got = _stars(extract_claims(_text_with_claim_at_distance(distance), [_ref("team", "project")]))
    if should_attribute:
        assert len(got) == 1, (
            f"a star claim {distance} lines from the mention is inside the +/-2 "
            f"window and must be attributed, got {got}"
        )
        assert got[0]["claimed_value"] == "12400"
    else:
        assert got == [], (
            f"a star claim {distance} lines from the mention is outside the +/-2 "
            f"window and must NOT be attributed to it, got {got}"
        )


def test_star_counts_attach_to_the_right_repo_when_two_are_nearby():
    """With two repos in one document each star count goes to its own repo.

    Cross-attribution would be the worst kind of false positive: repofacts
    would tell the user the LLM lied about repo A using repo B's number.
    """
    text = (
        "alpha/one is a solid choice.\n"      # line 1
        "It has 500 stars.\n"                  # line 2
        "\n"                                   # line 3
        "\n"                                   # line 4
        "beta/two is the alternative.\n"       # line 5
        "It has 900 stars.\n"                  # line 6
    )
    refs = [_ref("alpha", "one", line_no=1), _ref("beta", "two", line_no=5)]
    got = _stars(extract_claims(text, refs))
    attributed = {(c["owner"] + "/" + c["repo"], c["claimed_value"]) for c in got}
    assert attributed == {("alpha/one", "500"), ("beta/two", "900")}, (
        f"each star count must attach only to its own repo, got {attributed}"
    )


# ---------------------------------------------------------------------------
# Licence extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spoken", ["MIT", "mit", "Mit", "mIt"])
def test_licence_token_is_canonicalised_regardless_of_case(spoken):
    """Any casing of a token surfaces as the canonical SPDX spelling.

    Matching is case-insensitive but ``claimed_value`` must be the canonical
    token, or the diff layer would compare "mit" against "MIT" and call a
    genuine agreement a mismatch.
    """
    text = f"Check out team/project, released under the {spoken} licence.\n"
    got = _licences(extract_claims(text, [_ref("team", "project")]))
    assert len(got) == 1, f"expected one licence claim for {spoken!r}, got {got}"
    assert got[0]["claimed_value"] == "MIT", (
        f"{spoken!r} must canonicalise to 'MIT', got {got[0]['claimed_value']!r}"
    )


@pytest.mark.parametrize("sentence", [
    "I committed my changes to team/project yesterday.",
    "The patch was submitted upstream to team/project last week.",
    "Logs are transmitted by team/project over TLS.",
    "team/project has a permissive stance on contributions.",
])
def test_licence_tokens_require_word_boundaries(sentence):
    """A token embedded in an ordinary English word is not a licence claim.

    "committed" / "submitted" / "transmitted" all contain "mit". Substring
    matching would have repofacts assert the repo claims MIT when nobody
    said anything of the sort.
    """
    got = _licences(extract_claims(sentence + "\n", [_ref("team", "project")]))
    assert got == [], f"no licence claim may be extracted from {sentence!r}, got {got}"


def test_agpl_is_not_aliased_to_gpl():
    """``AGPL-3.0`` yields exactly one AGPL-3.0 claim, never a stray GPL-3.0.

    "GPL-3.0" is a literal substring of "AGPL-3.0", and the two are very
    different obligations. Emitting both would mean repofacts reports a
    licence conflict for a repo that has none.
    """
    text = "Check out team/project, licensed under AGPL-3.0.\n"
    got = _licences(extract_claims(text, [_ref("team", "project")]))
    values = [c["claimed_value"] for c in got]
    assert values == ["AGPL-3.0"], (
        f"AGPL-3.0 must produce exactly one AGPL-3.0 claim and no GPL-3.0 alias, got {values}"
    )


@pytest.mark.parametrize("sentence", [
    "team/project is licensed under the Foobar Public License.",
    "team/project uses a custom commercial licence, contact sales.",
    "team/project — licence terms are in the enterprise agreement.",
])
def test_unrecognised_licence_text_produces_silence_not_a_guess(sentence):
    """Unknown licence prose yields no claim at all.

    The module's contract is explicit: everything it cannot parse must fall
    through so the renderer can say "not parsed" rather than "I checked and
    you're wrong".
    """
    got = _licences(extract_claims(sentence + "\n", [_ref("team", "project")]))
    assert got == [], f"unparseable licence prose must yield no claim, got {got}"


# ---------------------------------------------------------------------------
# diff_claims — the tri-state contract
# ---------------------------------------------------------------------------


def test_star_agreement_reports_true():
    """Claim equal to the fetched truth is ``match is True``."""
    facts = RepoFacts(owner="team", repo="project", stars=12400)
    diffs = diff_claims([_star_claim("12400")], {"team/project": facts})
    assert len(diffs) == 1, f"expected one diff, got {diffs}"
    assert diffs[0].match is True, (
        f"12400 claimed vs 12400 actual must be `match is True`, got {diffs[0].match!r}"
    )
    assert diffs[0].actual_value == "12400"


def test_star_disagreement_reports_false_and_surfaces_the_truth():
    """Claim different from the fetched truth is ``match is False``.

    ``actual_value`` must carry the real number so the renderer can show the
    user what GitHub actually said.
    """
    facts = RepoFacts(owner="team", repo="project", stars=300)
    diffs = diff_claims([_star_claim("12400")], {"team/project": facts})
    assert diffs[0].match is False, (
        f"12400 claimed vs 300 actual must be `match is False`, got {diffs[0].match!r}"
    )
    assert diffs[0].actual_value == "300", (
        f"actual_value must surface GitHub's number, got {diffs[0].actual_value!r}"
    )


def test_star_count_with_unknown_truth_is_unchecked_not_a_mismatch():
    """THE LOAD-BEARING INVARIANT.

    When ``facts.stars is None`` we never obtained a star count — the check
    did not run. It must report ``match is None``.

    ``match is False`` here would be a fabricated accusation: ``rules.py``
    escalates the verdict to CAUTION on ``match is False`` and prints
    "claimed 12400 stars on line 1, actual None". That tells the user the
    LLM lied about a number repofacts never actually fetched, which is
    exactly the failure this project exists to prevent.
    """
    facts = RepoFacts(owner="team", repo="project", stars=None)
    diffs = diff_claims([_star_claim("12400")], {"team/project": facts})
    assert len(diffs) == 1, f"expected one diff, got {diffs}"
    assert diffs[0].match is None, (
        "an unfetched star count must report `match is None` (unchecked), "
        f"never `match is False` (a confident mismatch); got {diffs[0].match!r}"
    )
    assert diffs[0].actual_value is None, (
        f"actual_value must stay None when the truth is unknown, got {diffs[0].actual_value!r}"
    )


def test_unparseable_claimed_star_value_is_unchecked():
    """A claimed value that is not an integer reports ``match is None``.

    ``diff_claims`` is public and may be handed claims from elsewhere. A
    non-numeric claimed value cannot be compared, so it is unchecked — not
    a mismatch.
    """
    claim = _star_claim("lots")
    facts = RepoFacts(owner="team", repo="project", stars=12400)
    diffs = diff_claims([claim], {"team/project": facts})
    assert diffs[0].match is None, (
        f"an unparseable claimed value must be `match is None`, got {diffs[0].match!r}"
    )


def test_licence_with_unknown_truth_is_unchecked_not_a_mismatch():
    """``facts.license_spdx is None`` means we never read a licence.

    Symmetric with the star case: unknown truth is ``None``, never ``False``.
    Accusing an LLM of misstating a licence we never fetched is worse than
    saying nothing.
    """
    facts = RepoFacts(owner="team", repo="project", license_spdx=None)
    diffs = diff_claims([_license_claim("MIT")], {"team/project": facts})
    assert len(diffs) == 1
    assert diffs[0].match is None, (
        "an unfetched licence must report `match is None` (unchecked), "
        f"never `match is False`; got {diffs[0].match!r}"
    )
    assert diffs[0].actual_value is None


@pytest.mark.parametrize("claimed,actual,expected", [
    ("GPL-3.0", "GPL-3.0-or-later", True),   # SPDX suffix stripped before comparing
    ("GPL-3.0", "GPL-3.0-only", True),
    ("gpl-3.0", "GPL-3.0", True),            # comparison is case-insensitive
    ("GPL-3.0", "GPL-2.0", False),           # a real version disagreement
    ("MIT", "Apache-2.0", False),            # a real licence disagreement
])
def test_licence_suffix_normalisation_and_real_disagreements(claimed, actual, expected):
    """``-only`` / ``-or-later`` are stripped; genuine differences still fail.

    "GPL-3.0" and "GPL-3.0-or-later" are the same practical answer, so
    flagging them as a conflict would be noise. "GPL-3.0" vs "GPL-2.0" is a
    genuine difference and must still be reported.
    """
    facts = RepoFacts(owner="team", repo="project", license_spdx=actual)
    diffs = diff_claims([_license_claim(claimed)], {"team/project": facts})
    assert len(diffs) == 1, f"expected one diff, got {diffs}"
    assert diffs[0].match is expected, (
        f"claimed {claimed!r} vs actual {actual!r}: expected `match is {expected}`, "
        f"got {diffs[0].match!r}"
    )


def test_unrecognised_claim_type_is_unchecked_never_a_pass():
    """A claim type the module cannot check reports ``match is None``.

    Returning ``True`` would claim we verified something we never looked at;
    returning ``False`` would accuse the LLM on no evidence. Only ``None`` is
    honest.
    """
    claim = {
        "owner": "team",
        "repo": "project",
        "claim_type": "fork_count",
        "claimed_value": "42",
        "raw": "42 forks",
        "line_no": 1,
    }
    facts = RepoFacts(owner="team", repo="project", forks=42)
    diffs = diff_claims([claim], {"team/project": facts})
    assert len(diffs) == 1, f"an unknown claim type must still be reported, got {diffs}"
    assert diffs[0].match is None, (
        f"an uncheckable claim type must be `match is None`, got {diffs[0].match!r} — "
        "a confident pass or fail would be a silent lie"
    )
    assert diffs[0].actual_value is None


def test_diff_lookup_key_is_case_insensitive_lowercase():
    """``facts_by_full`` is documented as keyed by lowercase ``owner/repo``.

    A claim carrying the repo's display casing must still find its facts,
    otherwise a real mismatch would be silently dropped.
    """
    facts = RepoFacts(owner="Team", repo="Project", stars=300)
    diffs = diff_claims(
        [_star_claim("12400", owner="Team", repo="Project")], {"team/project": facts}
    )
    assert len(diffs) == 1, f"mixed-case claim must resolve against the lowercase key, got {diffs}"
    assert diffs[0].match is False
    assert diffs[0].full_name == "Team/Project"


# ---------------------------------------------------------------------------
# Purity and determinism
# ---------------------------------------------------------------------------


def test_claims_module_performs_no_io_and_reads_no_clock():
    """``claims.py`` is contractually pure: no network, no file I/O, no clock.

    Parsed from the AST rather than grepped, so a name appearing in a comment
    or docstring cannot produce a false alarm — and a real import cannot hide.
    """
    tree = ast.parse(inspect.getsource(claims_mod))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])

    forbidden = {
        "urllib", "http", "socket", "ssl", "requests", "httpx",  # network
        "pathlib", "os", "io", "shutil", "tempfile", "subprocess",  # file / process
        "time", "datetime", "random",  # clock / non-determinism
    }
    leaked = imported & forbidden
    assert not leaked, (
        f"claims.py must stay pure but imports {sorted(leaked)} — "
        "network, file I/O and the clock all belong in github.py / the caller"
    )

    called = {
        n.func.id for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "open" not in called, "claims.py must not open files — it is a pure function over text"


def test_extraction_is_deterministic_and_deduplicates_overlapping_coverage():
    """Repeated coverage of one line by one ref must not duplicate its claims.

    Here the repo is mentioned on both lines, so line 2 is covered twice (as
    line 1's "+1" neighbour and as its own anchor). Without deduplication the
    same star claim would be emitted twice and the report would show the same
    finding two times over. Also asserts the function is deterministic.
    """
    text = (
        "team/project is a small library.\n"                    # line 1
        "team/project has 12.4k stars and is MIT licensed.\n"   # line 2
    )
    refs = [_ref("team", "project", line_no=1)]

    first = extract_claims(text, refs)
    second = extract_claims(text, refs)
    assert first == second, f"extract_claims must be deterministic: {first} != {second}"

    assert len(_stars(first)) == 1, (
        f"the single star claim must be emitted once despite overlapping ref coverage, "
        f"got {_stars(first)}"
    )
    assert len(_licences(first)) == 1, (
        f"the single licence claim must be emitted once despite overlapping ref coverage, "
        f"got {_licences(first)}"
    )
    assert _stars(first)[0]["line_no"] == 2, "claims must record the line they were found on"


def test_extract_claims_on_text_with_no_refs_returns_nothing():
    """With no repo references there is nothing to attribute a claim to.

    A loose "12.4k stars" floating in text belongs to no repo, and guessing an
    owner for it would be exactly the fabrication this module refuses to make.
    """
    text = "Some library out there has 12.4k stars and an MIT licence.\n"
    assert extract_claims(text, []) == [], "claims must never be emitted without a repo to own them"
