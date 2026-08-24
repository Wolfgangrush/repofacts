"""Tests for repofacts.cli — argparse, exit codes, and the non-deep fast path."""
from __future__ import annotations

import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest  # noqa: E402

from repofacts import cli  # noqa: E402
from repofacts.models import RepoFacts  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


#: A high-confidence mention: a full github.com URL, which extract_refs
#: always promotes to a RepoRef.
URL_INPUT = "Try https://github.com/acme/widget for this.\n"

#: A bare owner/repo in prose. extract_refs deliberately SKIPS this unless
#: --loose is passed; several tests rely on that distinction.
BARE_INPUT = "Try acme/widget for this.\n"


def _healthy_facts(owner: str = "acme", repo: str = "widget") -> RepoFacts:
    """Return a RepoFacts that rules.assess judges as a healthy 'OK' repo."""
    now = datetime.now(timezone.utc)
    return RepoFacts(
        owner=owner, repo=repo,
        exists=True, stars=100, forks=10,
        language="Python", description="A small Python utility.",
        pushed_at=(now - timedelta(days=2)).isoformat(),
        created_at=(now - timedelta(days=365)).isoformat(),
        default_branch="main",
        archived=False, disabled=False,
        fork=False, parent_full_name=None,
        license_spdx="MIT", license_name="MIT License",
        readme_text="# Widget\n\nA tiny Python utility that does one thing.",
        readme_status="fetched",
        readme_license_files=[],
        moved_to=None, private=False,
    )


def _feed(monkeypatch, text: str) -> None:
    """Put text on sys.stdin for the duration of the test."""
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


@pytest.fixture
def empty_stdin(monkeypatch):
    """Replace sys.stdin with an empty stream."""
    monkeypatch.setattr("sys.stdin", io.StringIO(""))


@pytest.fixture
def wire_one_repo(monkeypatch):
    """Patch all network calls so a default run processes one healthy repo end-to-end.

    The deep fetchers (security / quality) are wired to MagicMock instances that
    raise AssertionError on any invocation — this guarantees the fast path never
    touches them.
    """
    monkeypatch.setattr(
        cli, "discover_token",
        lambda token_env=None, env=None: (None, "none"),
    )
    monkeypatch.setattr(
        cli, "fetch_all",
        lambda refs, token, *, workers=8, want_readme=True: ([_healthy_facts()], False),
    )
    monkeypatch.setattr(
        cli, "fetch_security_facts",
        MagicMock(side_effect=AssertionError("deep security fetcher must not run on the fast path")),
    )
    monkeypatch.setattr(
        cli, "fetch_quality_facts",
        MagicMock(side_effect=AssertionError("deep quality fetcher must not run on the fast path")),
    )
    monkeypatch.setattr(cli, "GitHubClient", MagicMock())


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------


def test_json_and_markdown_are_mutually_exclusive():
    """argparse rejects --json --markdown with exit code 2."""
    with pytest.raises(SystemExit) as ei:
        cli.main(["--json", "--markdown"])
    assert ei.value.code == 2


def test_version_prints_and_exits(capsys):
    """--version prints 'repofacts <version>' and exits with code 0."""
    with pytest.raises(SystemExit) as ei:
        cli.main(["--version"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "repofacts" in out
    assert "0.1.0" in out


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_clean_run_returns_ok(wire_one_repo, monkeypatch, capsys):
    """A healthy repo with no partial fetches returns EXIT_OK (0)."""
    _feed(monkeypatch, "Use https://github.com/acme/widget.")
    rc = cli.main([])
    assert rc == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "acme/widget" in out


def test_missing_repo_returns_stop(monkeypatch, capsys):
    """exists=False forces verdict STOP and cli returns EXIT_STOP (1)."""
    missing = _healthy_facts()
    missing.exists = False
    monkeypatch.setattr(cli, "discover_token", lambda token_env=None, env=None: (None, "none"))
    monkeypatch.setattr(
        cli, "fetch_all",
        lambda refs, token, *, workers=8, want_readme=True: ([missing], False),
    )
    monkeypatch.setattr(cli, "fetch_security_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "fetch_quality_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "GitHubClient", MagicMock())
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main([])
    assert rc == cli.EXIT_STOP
    out = capsys.readouterr().out
    assert "acme/widget" in out


def test_partial_run_returns_partial(monkeypatch, capsys):
    """fetch_all reporting partial=True -> EXIT_PARTIAL (2); stderr mentions partial."""
    monkeypatch.setattr(cli, "discover_token", lambda token_env=None, env=None: (None, "none"))
    monkeypatch.setattr(
        cli, "fetch_all",
        lambda refs, token, *, workers=8, want_readme=True: ([_healthy_facts()], True),
    )
    monkeypatch.setattr(cli, "fetch_security_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "fetch_quality_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "GitHubClient", MagicMock())
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main([])
    assert rc == cli.EXIT_PARTIAL
    err = capsys.readouterr().err
    assert "partial" in err.lower()


def test_partial_takes_precedence_over_stop(monkeypatch):
    """partial=True beats STOP: documented ordering pins EXIT_PARTIAL (2).

    run() checks ``partial`` before ``verdict == 'STOP'`` so incomplete data
    always wins over a stop verdict — this test pins the current, documented
    ordering so any future refactor cannot silently swap the priority.
    """
    missing = _healthy_facts()
    missing.exists = False
    monkeypatch.setattr(cli, "discover_token", lambda token_env=None, env=None: (None, "none"))
    monkeypatch.setattr(
        cli, "fetch_all",
        lambda refs, token, *, workers=8, want_readme=True: ([missing], True),
    )
    monkeypatch.setattr(cli, "fetch_security_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "fetch_quality_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "GitHubClient", MagicMock())
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main([])
    assert rc == cli.EXIT_PARTIAL


def test_fetch_all_runtime_error_returns_partial_with_stderr(monkeypatch, capsys):
    """fetch_all raising RuntimeError -> EXIT_PARTIAL, message on stderr, empty stdout."""
    monkeypatch.setattr(cli, "discover_token", lambda token_env=None, env=None: (None, "none"))

    def boom(*a, **kw):
        raise RuntimeError("budget gate denied")

    monkeypatch.setattr(cli, "fetch_all", boom)
    monkeypatch.setattr(cli, "fetch_security_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "fetch_quality_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "GitHubClient", MagicMock())
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main([])
    assert rc == cli.EXIT_PARTIAL
    out, err = capsys.readouterr()
    assert out == ""
    assert "repofacts: " in err
    assert "budget gate denied" in err


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("args", [[], ["--json"], ["--markdown"]])
def test_empty_input_early_return(monkeypatch, empty_stdin, args):
    """Empty input in any output mode -> EXIT_OK and fetch_all is never called."""
    fetch_all = MagicMock()
    monkeypatch.setattr(cli, "fetch_all", fetch_all)
    monkeypatch.setattr(cli, "discover_token", lambda token_env=None, env=None: (None, "none"))
    rc = cli.main(args)
    assert rc == cli.EXIT_OK
    assert fetch_all.call_count == 0


# ---------------------------------------------------------------------------
# Non-deep fast path
# ---------------------------------------------------------------------------


def test_deep_fetchers_not_called(wire_one_repo, monkeypatch):
    """Without --deep, fetch_security_facts and fetch_quality_facts are never called.

    The mocks installed by wire_one_repo raise AssertionError on any invocation;
    the test passes because run() never reaches the deep branch.
    """
    sec_mock = cli.fetch_security_facts
    qua_mock = cli.fetch_quality_facts
    assert isinstance(sec_mock, MagicMock)
    assert isinstance(qua_mock, MagicMock)
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main([])
    assert rc == cli.EXIT_OK
    assert sec_mock.call_count == 0
    assert qua_mock.call_count == 0


def test_renderers_receive_none_deep(wire_one_repo, monkeypatch):
    """Without --deep, renderers receive deep_by_full=None in every output mode.

    Spies wrap each renderer, record the deep_by_full kwarg, and delegate to
    the real implementation so the rest of the output path stays honest.
    """
    seen: dict[str, object] = {}

    real_table = cli.format_table
    real_summary = cli.format_summary
    real_json = cli.format_json
    real_md = cli.format_markdown

    def spy_table(assessments, skips, *, deep_by_full=None):
        seen["table"] = deep_by_full
        return real_table(assessments, skips, deep_by_full=deep_by_full)

    def spy_summary(assessments, skips, *, deep_by_full=None):
        seen["summary"] = deep_by_full
        return real_summary(assessments, skips, deep_by_full=deep_by_full)

    def spy_json(assessments, skips, licence_as_of, *, partial=False, token_source="none",
                 deep_by_full=None, **kwargs):
        seen["json"] = deep_by_full
        return real_json(
            assessments, skips, licence_as_of,
            partial=partial, token_source=token_source, deep_by_full=deep_by_full,
            **kwargs,
        )

    def spy_md(assessments, skips, licence_as_of, *, deep_by_full=None):
        seen["md"] = deep_by_full
        return real_md(assessments, skips, licence_as_of, deep_by_full=deep_by_full)

    monkeypatch.setattr(cli, "format_table", spy_table)
    monkeypatch.setattr(cli, "format_summary", spy_summary)
    monkeypatch.setattr(cli, "format_json", spy_json)
    monkeypatch.setattr(cli, "format_markdown", spy_md)

    # Table + summary mode (default).
    seen.clear()
    _feed(monkeypatch, URL_INPUT)
    assert cli.main([]) == cli.EXIT_OK
    assert seen.get("table") is None
    assert seen.get("summary") is None

    # JSON mode.
    seen.clear()
    _feed(monkeypatch, URL_INPUT)
    assert cli.main(["--json"]) == cli.EXIT_OK
    assert seen.get("json") is None

    # Markdown mode.
    seen.clear()
    _feed(monkeypatch, URL_INPUT)
    assert cli.main(["--markdown"]) == cli.EXIT_OK
    assert seen.get("md") is None


# ---------------------------------------------------------------------------
# Token leak
# ---------------------------------------------------------------------------


SECRET_TOKEN = "ghp_" + "a" * 36


def _wire_with_token(monkeypatch, token: str, source: str) -> None:
    """Wire the CLI mocks and force discover_token to return a known secret."""
    monkeypatch.setattr(
        cli, "discover_token",
        lambda token_env=None, env=None: (token, source),
    )
    monkeypatch.setattr(
        cli, "fetch_all",
        lambda refs, token, *, workers=8, want_readme=True: ([_healthy_facts()], False),
    )
    monkeypatch.setattr(cli, "fetch_security_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "fetch_quality_facts", MagicMock(side_effect=AssertionError))
    monkeypatch.setattr(cli, "GitHubClient", MagicMock())


@pytest.mark.parametrize("args", [[], ["--json"], ["--markdown"]])
def test_token_never_leaked(monkeypatch, args, capsys):
    """Token literal never appears in stdout or stderr in any output mode."""
    _wire_with_token(monkeypatch, SECRET_TOKEN, "REPOFACTS_TOKEN")
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main(args)
    assert rc == cli.EXIT_OK
    out, err = capsys.readouterr()
    assert SECRET_TOKEN not in out
    assert SECRET_TOKEN not in err


def test_json_exposes_token_source_name_only(monkeypatch, capsys):
    """--json output includes token_source as a name only — never the token value."""
    _wire_with_token(monkeypatch, SECRET_TOKEN, "REPOFACTS_TOKEN")
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main(["--json"])
    assert rc == cli.EXIT_OK
    out = capsys.readouterr().out
    obj = json.loads(out)
    assert obj["token_source"] == "REPOFACTS_TOKEN"
    assert SECRET_TOKEN not in json.dumps(obj)


# ---------------------------------------------------------------------------
# Argument forwarding
# ---------------------------------------------------------------------------


def test_platform_forwarded_to_assess(wire_one_repo, monkeypatch):
    """--platform 'Windows' is forwarded as host_system to rules.assess."""
    real_assess = cli.assess
    seen: dict[str, object] = {}

    def spy(ref, facts, host_system, host_machine, *, now=None, claim_diffs=None, min_stars=25):
        seen["host_system"] = host_system
        return real_assess(
            ref, facts, host_system, host_machine,
            now=now, claim_diffs=claim_diffs, min_stars=min_stars,
        )

    monkeypatch.setattr(cli, "assess", spy)
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main(["--platform", "Windows"])
    assert rc == cli.EXIT_OK
    assert seen["host_system"] == "Windows"


def test_no_readme_forwards_want_readme_false(wire_one_repo, monkeypatch):
    """--no-readme causes fetch_all to be called with want_readme=False."""
    seen: dict[str, object] = {}

    def spy(refs, token, *, workers=8, want_readme=True):
        seen["want_readme"] = want_readme
        return ([_healthy_facts()], False)

    monkeypatch.setattr(cli, "fetch_all", spy)
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main(["--no-readme"])
    assert rc == cli.EXIT_OK
    assert seen["want_readme"] is False


def test_workers_clamped_to_at_least_one(wire_one_repo, monkeypatch):
    """--workers 0 is clamped to 1 before reaching fetch_all (never zero workers)."""
    seen: dict[str, object] = {}

    def spy(refs, token, *, workers=8, want_readme=True):
        seen["workers"] = workers
        return ([_healthy_facts()], False)

    monkeypatch.setattr(cli, "fetch_all", spy)
    _feed(monkeypatch, URL_INPUT)
    rc = cli.main(["--workers", "0"])
    assert rc == cli.EXIT_OK
    assert seen["workers"] == 1


def test_loose_forwarded_to_extract_refs(wire_one_repo, monkeypatch):
    """--loose forwards loose=True to extract_refs."""
    real_extract = cli.extract_refs
    seen: dict[str, object] = {}

    def spy(text, loose=False):
        seen["loose"] = loose
        refs, skips = real_extract(text, loose=loose)
        seen["refs"] = [r.full_name for r in refs]
        return refs, skips

    monkeypatch.setattr(cli, "extract_refs", spy)
    _feed(monkeypatch, BARE_INPUT)
    rc = cli.main(["--loose"])
    assert rc == cli.EXIT_OK
    assert seen["loose"] is True
    # And --loose really does promote the bare mention into a checked repo.
    assert seen["refs"] == ["acme/widget"], seen["refs"]


# ---------------------------------------------------------------------------
# Input reading
# ---------------------------------------------------------------------------


def test_stdin_and_file_produce_same_exit_code(wire_one_repo, tmp_path, monkeypatch):
    """Reading the same input from a file or from stdin yields the same exit code."""
    text = URL_INPUT
    p = tmp_path / "input.md"
    p.write_text(text, encoding="utf-8")

    rc_file = cli.main([str(p)])
    _feed(monkeypatch, text)
    rc_stdin = cli.main([])
    assert rc_file == rc_stdin == cli.EXIT_OK


# ---------------------------------------------------------------------------
# Parser defaults
# ---------------------------------------------------------------------------


def test_parser_defaults_are_the_fast_path():
    """Every flag defaults off, so a bare invocation is the cheap fast path.

    --deep in particular MUST default to False: it multiplies the API calls
    per repo, so a default flip would silently blow the rate-limit budget of
    every existing caller.
    """
    args = cli._build_parser().parse_args([])
    assert args.path is None
    assert args.workers == 8
    assert args.deep is False
    assert args.json is False
    assert args.markdown is False
    assert args.claims is False
    assert args.loose is False
    assert args.no_readme is False
    assert args.platform is None
    assert args.token_env is None


# ---------------------------------------------------------------------------
# --deep positive control
# ---------------------------------------------------------------------------


def test_deep_flag_runs_battery_and_never_reports_a_pass_it_did_not_earn(
    monkeypatch, capsys,
):
    """--deep is the positive control for the fast-path tests above.

    Two things are proven at once:

    1. With --deep the deep fetchers ARE called and the renderer receives a
       populated dict — so `test_deep_fetchers_not_called` and
       `test_renderers_receive_none_deep` are meaningful, not vacuous.
    2. When the fetcher comes back empty (the shape of a 404 / permission
       failure / rate limit), every single finding is 'unchecked' and NOT a
       single one is 'pass'. A check that could not run must never render as
       a check that passed — the most load-bearing invariant in this codebase.
    """
    from repofacts.models import QualityFacts, SecurityFacts

    sec_calls: list[tuple[str, str]] = []
    qua_calls: list[tuple[str, str]] = []

    def fake_sec(client, owner, repo, *, facts=None, now=None):
        sec_calls.append((owner, repo))
        return SecurityFacts(owner=owner, repo=repo, fetched_at=now)

    def fake_qua(client, owner, repo, *, facts=None, now=None):
        qua_calls.append((owner, repo))
        return QualityFacts(owner=owner, repo=repo, fetched_at=now)

    monkeypatch.setattr(cli, "discover_token", lambda token_env=None, env=None: (None, "none"))
    monkeypatch.setattr(
        cli, "fetch_all",
        lambda refs, token, *, workers=8, want_readme=True: ([_healthy_facts()], False),
    )
    monkeypatch.setattr(cli, "fetch_security_facts", fake_sec)
    monkeypatch.setattr(cli, "fetch_quality_facts", fake_qua)
    monkeypatch.setattr(cli, "GitHubClient", MagicMock())

    seen: dict[str, object] = {}
    real_json = cli.format_json

    def spy_json(assessments, skips, licence_as_of, *, partial=False,
                 token_source="none", deep_by_full=None, **kwargs):
        seen["deep_by_full"] = deep_by_full
        return real_json(
            assessments, skips, licence_as_of,
            partial=partial, token_source=token_source, deep_by_full=deep_by_full,
            **kwargs,
        )

    monkeypatch.setattr(cli, "format_json", spy_json)

    _feed(monkeypatch, URL_INPUT)
    rc = cli.main(["--deep", "--json"])
    assert rc == cli.EXIT_OK

    # 1. The battery really ran, and the renderer got a real dict.
    assert sec_calls == [("acme", "widget")], sec_calls
    assert qua_calls == [("acme", "widget")], qua_calls
    deep = seen["deep_by_full"]
    assert isinstance(deep, dict)
    entry = deep["acme/widget"]
    assert entry.fetch_error is None, entry.fetch_error
    assert entry.security_report is not None
    assert entry.quality_report is not None

    # 2. Unfetchable data is 'unchecked' everywhere and 'pass' nowhere.
    findings = list(entry.security_report.findings) + list(entry.quality_report.findings)
    assert findings, "the battery produced no findings at all"
    statuses = {f.status for f in findings}
    assert "pass" not in statuses, [
        (f.name, f.status) for f in findings if f.status == "pass"
    ]
    assert "unchecked" in statuses, statuses

    # And the same is true of what actually reaches the user's screen: assert
    # on the serialised `status` field itself, not a substring of the blob.
    obj = json.loads(capsys.readouterr().out)
    rendered = obj["assessments"][0]["deep"]
    assert rendered is not None
    rendered_findings = (
        rendered["security"]["findings"] + rendered["quality"]["findings"]
    )
    assert rendered_findings, rendered
    assert not [f for f in rendered_findings if f["status"] == "pass"], [
        f["name"] for f in rendered_findings if f["status"] == "pass"
    ]
    assert any(f["status"] == "unchecked" for f in rendered_findings)


# ---------------------------------------------------------------------------
# Unreadable input
# ---------------------------------------------------------------------------


def test_unreadable_input_exits_partial_not_traceback(monkeypatch, tmp_path, capsys):
    """An unreadable input file is a FAILED RUN (exit 2), not a traceback.

    cli.py's own docstring fixes the contract: 0 = clean, 1 = any STOP,
    2 = run failed or partial. A missing path, a directory, or a non-UTF-8
    file are all 'the run failed' — they must be reported on stderr with the
    'repofacts: ' prefix and exit 2. Letting the OSError escape gives the
    user a Python traceback AND exit code 1, which a wrapping script reads
    as 'a repo said STOP' — the worst possible confusion, because it turns a
    tooling failure into a false verdict about someone's repository.
    """
    monkeypatch.setattr(cli, "discover_token", lambda token_env=None, env=None: (None, "none"))
    monkeypatch.setattr(
        cli, "fetch_all",
        MagicMock(side_effect=AssertionError("must not fetch when input is unreadable")),
    )

    missing = tmp_path / "does-not-exist.md"
    a_directory = tmp_path / "adir"
    a_directory.mkdir()
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\x80\x81\x82\xff")

    for bad in (missing, a_directory, binary):
        rc = cli.main([str(bad)])
        out, err = capsys.readouterr()
        assert rc == cli.EXIT_PARTIAL, f"{bad.name} gave exit {rc}, expected 2"
        assert rc != cli.EXIT_STOP, f"{bad.name} must not look like a STOP verdict"
        assert err.startswith("repofacts: "), (bad.name, err)
        assert out == "", (bad.name, out)
