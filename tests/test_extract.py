"""Tests for repofacts.extract - enforces the documented contract."""
from repofacts.extract import extract_refs


def names(refs):
    return [r.full_name for r in refs]


def skip_raws(skips):
    return [s.raw for s in skips]


def test_plain_github_url_extracted():
    """A plain github.com URL produces exactly one ref with the right owner/repo/line."""
    refs, _ = extract_refs("See https://github.com/psf/requests for HTTP.")
    assert len(refs) == 1
    r = refs[0]
    assert r.owner == "psf"
    assert r.repo == "requests"
    assert r.full_name == "psf/requests"
    assert r.line_no == 1


def test_url_variants_all_normalise_to_same_repo():
    """All URL variants (suffix, slash, tree, anchor, query, issues) yield psf/requests."""
    text = (
        "https://github.com/psf/requests\n"
        "https://github.com/psf/requests/\n"
        "https://github.com/psf/requests.git\n"
        "https://github.com/psf/requests/tree/main/src\n"
        "https://github.com/psf/requests#readme\n"
        "https://github.com/psf/requests/issues/42\n"
    )
    refs, _ = extract_refs(text)
    assert {r.full_name for r in refs} == {"psf/requests"}
    assert all(r.owner == "psf" and r.repo == "requests" for r in refs)


def test_url_trailing_sentence_punctuation_stripped():
    """Trailing sentence punctuation and closing parens are stripped from repo."""
    refs1, _ = extract_refs("Try https://github.com/psf/requests.")
    refs2, _ = extract_refs("(see https://github.com/psf/requests)")
    assert len(refs1) == 1 and refs1[0].repo == "requests"
    assert len(refs2) == 1 and refs2[0].repo == "requests"


def test_markdown_link_extracted_with_full_raw_mention():
    """A markdown link yields a ref whose raw_mention is the full markdown link."""
    text = "Use [Requests](https://github.com/psf/requests) today."
    refs, _ = extract_refs(text)
    assert len(refs) == 1
    r = refs[0]
    assert r.owner == "psf"
    assert r.repo == "requests"
    assert "[Requests](" in r.raw_mention
    assert r.raw_mention.startswith("[Requests](")


def test_backticked_pair_extracted():
    """A backticked `owner/repo` yields a ref and the raw_mention includes the backticks."""
    text = "We like `psf/requests` for HTTP."
    refs, _ = extract_refs(text)
    assert len(refs) == 1
    r = refs[0]
    assert r.owner == "psf"
    assert r.repo == "requests"
    assert r.raw_mention.startswith("`")
    assert r.raw_mention.endswith("`")
    assert "`psf/requests`" in r.raw_mention


def test_bare_pair_not_extracted_in_strict_mode_but_is_listed_as_skip():
    """Bare owner/repo in prose is NOT a ref in strict mode, but is listed as a skip."""
    text = "I recommend psf/requests for HTTP work."
    refs, skips = extract_refs(text, loose=False)
    assert "psf/requests" not in names(refs)
    raws = skip_raws(skips)
    assert any("psf/requests" in s for s in raws), (
        f"Expected psf/requests in skips, got {raws}"
    )
    relevant = [s for s in skips if "psf/requests" in s.raw]
    assert relevant, "no skip matched psf/requests"
    assert relevant[0].reason.strip() != ""


def test_bare_pair_extracted_in_loose_mode():
    """Bare owner/repo in prose IS a ref when loose=True."""
    text = "I recommend psf/requests for HTTP work."
    refs, _ = extract_refs(text, loose=True)
    assert "psf/requests" in names(refs)
    r = next(x for x in refs if x.full_name == "psf/requests")
    assert r.owner == "psf" and r.repo == "requests"


def test_and_or_is_not_a_repo():
    """Stopword pairs like 'and/or' and 'input/output' are never extracted as refs."""
    text = "Choose and/or decide, then handle input/output carefully."
    refs, _ = extract_refs(text, loose=True)
    full_names = {r.full_name for r in refs}
    assert "and/or" not in full_names
    assert "input/output" not in full_names


def test_and_or_rejection_is_reported_as_a_skip():
    """Rejected bare pairs are listed as skips with a non-empty reason (never silently dropped)."""
    text = "Choose and/or decide, then handle input/output carefully."
    _, skips = extract_refs(text, loose=True)
    raws = skip_raws(skips)
    assert any("and/or" in s for s in raws), f"Expected and/or in {raws}"
    assert any("input/output" in s for s in raws), f"Expected input/output in {raws}"
    relevant = [s for s in skips if "and/or" in s.raw or "input/output" in s.raw]
    for s in relevant:
        assert s.reason.strip() != ""


def test_dates_are_not_repos():
    """Numeric dates like '24/08' and ratios like '3/4' are not extracted as refs."""
    text = "The meeting on 24/08 and the ratio 3/4 were noted."
    refs, skips = extract_refs(text, loose=True)
    full_names = {r.full_name for r in refs}
    assert "24/08" not in full_names
    assert "3/4" not in full_names
    raws = skip_raws(skips)
    assert any("24/08" in s for s in raws), f"Expected 24/08 in skips {raws}"


def test_package_name_in_install_context_is_skipped_not_checked():
    """Package-shaped tokens in install contexts are Skip'd with the documented reason."""
    text = "pip install requests-oauthlib to get started."
    refs, skips = extract_refs(text)
    assert "requests-oauthlib" not in names(refs)
    matches = [s for s in skips if s.raw == "requests-oauthlib"]
    assert matches, f"Expected a skip for requests-oauthlib, got {skips}"
    assert matches[0].reason == "looks like a package name, not checked"


def test_line_numbers_and_dedup_across_lines():
    """Dedup keeps first occurrence's line_no; multiple distinct refs keep distinct line_nos."""
    text = (
        "Look at https://github.com/psf/requests.\n"
        "And also `psf/requests` is great.\n"
        "Try https://github.com/pallets/flask too.\n"
    )
    refs, _ = extract_refs(text)
    assert len(refs) == 2
    full = {r.full_name: r for r in refs}
    assert "psf/requests" in full
    assert "pallets/flask" in full
    assert full["psf/requests"].line_no == 1
    assert full["pallets/flask"].line_no == 3


def test_nothing_is_silently_dropped():
    """Load-bearing invariant: every slash-candidate is either a ref or a listed skip."""
    text = (
        "I recommend psf/requests for HTTP work.\n"
        "Choose and/or decide.\n"
        "The meeting on 24/08 was moved.\n"
    )
    refs, skips = extract_refs(text, loose=False)
    accounted = " ".join(names(refs) + [r.raw_mention for r in refs] + skip_raws(skips))
    for candidate in ("psf/requests", "and/or", "24/08"):
        assert candidate in accounted, (
            f"{candidate!r} was silently dropped: refs={names(refs)} skips={skip_raws(skips)}"
        )


def test_every_skip_carries_a_nonempty_reason_and_line_number():
    """A Skip with no reason is the same as a silent drop; both are banned."""
    text = (
        "pip install requests-oauthlib first.\n"
        "Then handle input/output and prefer psf/requests.\n"
    )
    _, skips = extract_refs(text, loose=False)
    assert skips, "expected at least one skip for this input"
    for s in skips:
        assert s.raw.strip() != ""
        assert isinstance(s.reason, str) and s.reason.strip() != ""
        assert s.line_no is not None and s.line_no >= 1


def test_empty_input_returns_two_empty_lists():
    """Empty / whitespace-only input yields no refs and no skips, not an error."""
    for text in ("", "   ", "\n\n"):
        refs, skips = extract_refs(text)
        assert refs == []
        assert skips == []
