"""Extract repository references from arbitrary text.

Pure: no network, no I/O beyond reading the input string. Side-effects are
limited to returning ``list[RepoRef]`` and ``list[Skip]``.

Three high-confidence shapes are recognised:

1. Markdown links      ``[text](https://github.com/owner/repo…)``
2. Bare GitHub URLs    ``https://github.com/owner/repo…``
3. Backticked pairs    ``` `owner/repo` ``

Bare ``owner/repo`` in running prose (e.g. ``and/or``, ``24/08``) is *not*
extracted by default — its false-positive rate is high. Pass ``loose=True`` to
opt in; the same candidates are surfaced as :class:`Skip` entries so the user
sees them either way.

Bare package-name-shaped tokens in install / import / require contexts are
also reported as :class:`Skip` entries (the exact slopsquatting bait — an
LLM saying "use X for the task" where X is a PyPI package, not a repo).
"""

from __future__ import annotations

import re

from .models import RepoRef, Skip


# GitHub username grammar: alphanumeric, hyphens, 1–39 chars, no leading hyphen.
GH_USER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"

# GitHub repo name grammar: alphanumeric, hyphens, underscores, dots.
GH_REPO = r"[A-Za-z0-9._-]+"

# Full https URL to a GitHub repo, with optional trailing path/query/fragment.
# The trailing class ``[^\s)\]"'<>]*`` deliberately excludes characters that
# almost always mean we're outside the URL (markdown close-paren, end of attr,
# etc.).
_GITHUB_URL = re.compile(
    rf"https?://github\.com/(?P<owner>{GH_USER})/(?P<repo>{GH_REPO})"
    rf"(?P<trail>[^\s)\]\"'<>]*)",
    re.IGNORECASE,
)

# Markdown link whose target is a github.com URL.
_MARKDOWN_LINK = re.compile(
    rf"\[(?P<text>[^\]\n]*)\]\((?P<url>https?://github\.com/(?P<md_owner>{GH_USER})/(?P<md_repo>{GH_REPO})[^\s)\"']*)\)",
    re.IGNORECASE,
)

# Backticked `owner/repo`.
_BACKTICK_PAIR = re.compile(
    rf"`(?P<bt_owner>{GH_USER})/(?P<bt_repo>{GH_REPO})`"
)

# Bare `owner/repo` in prose — used only when ``--loose`` is set.
_BARE_PAIR = re.compile(
    rf"(?<![\w`/.])(?P<b_owner>{GH_USER})/(?P<b_repo>{GH_REPO})(?![\w`/.])"
)

# Install / use / require contexts that suggest a package name follows.
_PACKAGE_CONTEXT = re.compile(
    r"\b(?:install|use|using|require[ds]?|import|from|include|add|with)\b"
    r"|(?:pip|conda|npm|yarn|pnpm|cargo|gem|brew)\s+install"
    r"|require\s*\(",
    re.IGNORECASE,
)

# Tokens that look like package names: lowercase, optional separators, length≥3.
# Conservative: requires either a separator (so we don't sweep every short
# English word) **or** length ≥ 6 (catches ``requests``, ``lodash``).
_PACKAGE_TOKEN = re.compile(
    r"\b([a-z][a-z0-9]*(?:[-_.][a-z0-9]+)+|[a-z][a-z0-9]{5,})\b"
)

# Tokens that, on either side of a slash, almost always mean *English*, not a
# repo. The list is deliberately short — bias is toward extraction, with the
# surface in the skip list catching the rest.
_BARE_OWNER_STOPWORDS = frozenset({
    "and", "or", "nor", "vs", "via", "per", "at", "by", "to", "of",
    "in", "on", "up", "do", "if", "is", "it", "be", "an", "as",
    "the", "for", "from", "with", "without", "into", "out", "off",
    "over", "under", "between", "while", "until", "than", "then",
})
_BARE_REPO_STOPWORDS = frozenset({
    "or", "and", "input", "output", "stdout", "stderr", "stdin",
    "file", "files", "dir", "directory", "function", "class", "method",
    "methods", "object", "instance", "module", "package", "lib", "libs",
})


_PUNCT = ".,;:!?)]}'\"`"


def _clean_repo(repo: str) -> str:
    """Strip trailing punctuation and a ``.git`` suffix from a repo name.

    ``https://github.com/psf/requests.git`` and ``https://github.com/psf/requests``
    name the same repository; GitHub itself forbids a repo name ending in
    ``.git``, so the suffix is always clone-URL sugar, never part of the name.
    """
    repo = repo.rstrip(_PUNCT)
    if len(repo) > 4 and repo.lower().endswith(".git"):
        repo = repo[:-4].rstrip(_PUNCT)
    return repo


def _add_ref(refs: dict, owner: str, repo: str, raw: str, line_no: int) -> None:
    """Insert one ref into the ``refs`` dict, keyed by lowercase full-name."""
    repo = _clean_repo(repo)
    if not owner or not repo:
        return
    key = f"{owner.lower()}/{repo.lower()}"
    if key not in refs:
        refs[key] = RepoRef(
            owner=owner, repo=repo, raw_mention=raw, line_no=line_no
        )


#: Reason strings attached to bare-pair skips. Every rejected candidate gets
#: one — design invariant #6 forbids dropping a mention without saying why.
REASON_BARE_PROSE = (
    "bare owner/repo in prose reads as an English phrase, not a repo — not checked"
)
REASON_BARE_NUMERIC = (
    "bare owner/repo is all digits (a date or a ratio), not a repo — not checked"
)
REASON_BARE_LOW_CONFIDENCE = (
    "bare owner/repo in prose is low confidence — not checked; rerun with --loose"
)


def _bare_pair_reject_reason(owner: str, repo: str) -> str | None:
    """Return why this bare pair is *not* a repo, or ``None`` if it plausibly is.

    Filters the noisiest bare-pair false positives (``and/or``, ``input/output``,
    ``24/08``, ``3/4``).
    """
    if owner.lower() in _BARE_OWNER_STOPWORDS or repo.lower() in _BARE_REPO_STOPWORDS:
        return REASON_BARE_PROSE
    if owner.isdigit() and repo.isdigit():
        return REASON_BARE_NUMERIC
    return None


def _extract_high_confidence(
    text: str, refs: dict[str, RepoRef]
) -> None:
    """Walk the input line by line applying the three high-confidence rules."""
    for idx, line in enumerate(text.splitlines(), start=1):
        for m in _MARKDOWN_LINK.finditer(line):
            _add_ref(refs, m.group("md_owner"), m.group("md_repo"), m.group(0), idx)
        for m in _GITHUB_URL.finditer(line):
            # Skip — already covered by the markdown link above, which captures
            # the full ``[text](url)`` as raw_mention. Dedup happens in
            # ``_add_ref``.
            _add_ref(refs, m.group("owner"), m.group("repo"), m.group(0), idx)
        for m in _BACKTICK_PAIR.finditer(line):
            _add_ref(refs, m.group("bt_owner"), m.group("bt_repo"), m.group(0), idx)


def _extract_bare_pairs(
    text: str, refs: dict[str, RepoRef], skips: list[Skip], loose: bool
) -> None:
    """Walk bare ``owner/repo`` candidates in running prose.

    Every candidate ends up somewhere. A plausible pair becomes a ``RepoRef``
    when ``loose`` is set and a ``Skip`` when it is not; an implausible pair
    (``and/or``, ``24/08``) always becomes a ``Skip`` carrying the reason it
    was rejected. Nothing is dropped in silence — that is design invariant #6,
    and it is the whole point of returning a skip list at all.
    """
    for idx, line in enumerate(text.splitlines(), start=1):
        for m in _BARE_PAIR.finditer(line):
            owner = m.group("b_owner")
            repo = _clean_repo(m.group("b_repo"))
            if not owner or not repo:
                continue
            reason = _bare_pair_reject_reason(owner, repo)
            if reason is None:
                if f"{owner.lower()}/{repo.lower()}" in refs:
                    # Already captured by a URL / markdown link / backtick pair
                    # elsewhere in the input — not a skip.
                    continue
                if loose:
                    _add_ref(refs, owner, repo, m.group(0), idx)
                    continue
                reason = REASON_BARE_LOW_CONFIDENCE
            skips.append(Skip(raw=m.group(0), reason=reason, line_no=idx))


def _extract_package_name_skips(
    text: str, refs: dict[str, RepoRef]
) -> list[Skip]:
    """Surface bare tokens that look like a package, not a repo."""
    skips: list[Skip] = []
    lines = text.splitlines()
    extracted_full_names = {k for k in refs.keys()}
    extracted_parts = set()
    for k in extracted_full_names:
        owner, _, repo = k.partition("/")
        extracted_parts.add(owner)
        extracted_parts.add(repo)

    for idx, line in enumerate(lines, start=1):
        if not _PACKAGE_CONTEXT.search(line):
            continue
        for m in _PACKAGE_TOKEN.finditer(line):
            word = m.group(1)
            if "/" in word:
                continue
            if word.lower() in extracted_parts:
                continue
            # Filter the obvious English stoplist inline.
            if word.lower() in {"this", "that", "with", "from", "have", "into",
                                "your", "you", "all", "any", "can", "use",
                                "and", "the", "for", "etc", "via", "code",
                                "data", "are", "but", "not"}:
                continue
            # Skip version-shaped things.
            if re.match(r"^\d+\.\d", word):
                continue
            skips.append(Skip(
                raw=word,
                reason="looks like a package name, not checked",
                line_no=idx,
            ))
    return skips


def extract_refs(text: str, loose: bool = False) -> tuple[list[RepoRef], list[Skip]]:
    """Parse input text into a list of repo references and a list of skips.

    Returns:
        A tuple ``(refs, skips)`` where ``refs`` is a deduplicated list of
        :class:`RepoRef` and ``skips`` is a deduplicated list of :class:`Skip`.

    Behaviour:
      * URLs, markdown links, and backticked pairs are always extracted.
      * Bare ``owner/repo`` is only extracted when ``loose=True``; otherwise
        it is reported as a :class:`Skip` so the user still sees it. Bare
        pairs rejected as prose or as a date are reported as :class:`Skip`
        in *both* modes.
      * Tokens that look like a package name and appear in an install / use /
        require context are *always* reported as :class:`Skip` — never
        silently dropped.
    """
    refs: dict[str, RepoRef] = {}

    _extract_high_confidence(text, refs)

    skips: list[Skip] = []

    _extract_bare_pairs(text, refs, skips, loose)

    pkg_skips = _extract_package_name_skips(text, refs)
    skips.extend(pkg_skips)

    # Deduplicate skips by (raw.lower(), reason).
    seen: set = set()
    deduped: list[Skip] = []
    for s in skips:
        key = (s.raw.lower(), s.reason)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(s)

    # Stable order: refs in insertion order, skips in insertion order.
    return list(refs.values()), deduped
