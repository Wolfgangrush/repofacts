"""Tests for repofacts.github: token discovery, envelope unwrap, budget gate,
repo-move handling, rate-limit signalling, and token-leak prevention."""
import base64
import dataclasses
import json

import pytest

from repofacts import github
from repofacts.models import RepoFacts, RepoRef


VALID_TOKEN = "ghp_" + "a" * 36


# ----- Fakes -------------------------------------------------------------


class FakeResponse:
    """Minimal stand-in for http.client.HTTPResponse used by GitHubClient."""

    def __init__(self, status=200, body=b"", headers=None):
        self.status = status
        self._body = body
        self._headers_list = list((headers or {}).items())

    def read(self):
        return self._body

    def getheader(self, name, default=None):
        for k, v in self._headers_list:
            if k.lower() == str(name).lower():
                return v
        return default

    def getheaders(self):
        return list(self._headers_list)

    def close(self):
        pass


class FakeConn:
    """Minimal stand-in for http.client.HTTPSConnection."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.requests = []

    def request(self, method, url, headers=None, body=None):
        self.requests.append(dict(method=method, url=url, headers=headers))

    def getresponse(self):
        if not self.responses:
            raise IndexError("no scripted responses remaining")
        return self.responses.pop(0)

    def close(self):
        pass


class FailingConn(FakeConn):
    """A FakeConn that raises a non-retryable error on every getresponse().

    Raises ValueError instead of ConnectionResetError on purpose: the real
    GitHubClient._request would catch ConnectionResetError, null out
    self._conn, and try again with a freshly constructed HTTPSConnection --
    which would then make a REAL network call. ValueError escapes the retry
    loop immediately and lands in budget_gate's except clause.
    """

    def getresponse(self):
        raise ValueError("simulated probe failure")


def _nuke_sleep(monkeypatch):
    """Stop time.sleep from actually sleeping during retries / 429 backoff."""
    monkeypatch.setattr(github.time, "sleep", lambda *a, **k: None)


# ----- Token discovery: priority chain -----------------------------------


def test_discover_token_full_priority_chain(monkeypatch):
    """token_env > REPOFACTS_TOKEN > GH_TOKEN > GITHUB_TOKEN > gh > none.

    Each rung wins when the higher-priority rungs are absent; the presence
    of a lower-priority rung never overrules a higher one.
    """
    _nuke_sleep(monkeypatch)
    monkeypatch.setattr(github, "_run_gh_auth_token", lambda: None)

    a = "ghp_" + "a" * 36
    b = "ghp_" + "b" * 36
    c = "ghp_" + "c" * 36
    d = "ghp_" + "d" * 36
    f = "ghp_" + "f" * 36

    # 1. token_env override beats everything else.
    env = dict(MY_TOKEN=a, REPOFACTS_TOKEN=b, GH_TOKEN=c, GITHUB_TOKEN=d)
    t, s = github.discover_token(token_env="MY_TOKEN", env=env)
    assert t == a and s == "MY_TOKEN"

    # 2. REPOFACTS_TOKEN beats GH_TOKEN and GITHUB_TOKEN.
    env = dict(REPOFACTS_TOKEN=a, GH_TOKEN=b, GITHUB_TOKEN=c)
    t, s = github.discover_token(env=env)
    assert t == a and s == "REPOFACTS_TOKEN"

    # 3. GH_TOKEN beats GITHUB_TOKEN.
    env = dict(GH_TOKEN=a, GITHUB_TOKEN=b)
    t, s = github.discover_token(env=env)
    assert t == a and s == "GH_TOKEN"

    # 4. GITHUB_TOKEN is the last env-var rung.
    env = dict(GITHUB_TOKEN=a)
    t, s = github.discover_token(env=env)
    assert t == a
    assert s == "GITHUB_TOKEN (Actions-provisioned, 1000/hr)"

    # 5. gh CLI beats nothing.
    monkeypatch.setattr(github, "_run_gh_auth_token", lambda: f)
    t, s = github.discover_token(env=dict())
    assert t == f and s == "gh"

    # 6. No source at all.
    monkeypatch.setattr(github, "_run_gh_auth_token", lambda: None)
    t, s = github.discover_token(env=dict())
    assert t is None and s == "none"


def test_discover_token_gh_cli_used_when_no_env(monkeypatch):
    _nuke_sleep(monkeypatch)
    cli = "ghp_" + "c" * 36
    monkeypatch.setattr(github, "_run_gh_auth_token", lambda: cli)
    token, source = github.discover_token(env=dict())
    assert token == cli
    assert source == "gh"


def test_discover_token_returns_none_source_when_nothing(monkeypatch):
    _nuke_sleep(monkeypatch)
    monkeypatch.setattr(github, "_run_gh_auth_token", lambda: None)
    token, source = github.discover_token(env=dict())
    assert token is None
    assert source == "none"


# ----- Token-shape validation --------------------------------------------


def test_validate_token_shape_rejects_gh_help_text():
    # The classic failure: `gh auth token` prints usage to stdout and exits 0.
    help_text = (
        "Authenticate GitHub CLI and access GitHub from the terminal.\n\n"
        "USAGE\n  gh auth token [flags]\n\n"
        "FLAGS\n  -h, --hostname string   Hostname of the GitHub instance\n"
        "      --user              Include the user in the token\n"
    )
    assert github._validate_token_shape(help_text) is False


def test_discover_token_skips_malformed_env_value_and_continues(monkeypatch):
    _nuke_sleep(monkeypatch)
    monkeypatch.setattr(github, "_run_gh_auth_token", lambda: None)
    good = "ghp_" + "g" * 36
    env = dict(
        REPOFACTS_TOKEN="not a real token, gh auth status help text etc",
        GH_TOKEN=good,
    )
    token, source = github.discover_token(env=env)
    assert token == good
    assert source == "GH_TOKEN"


# ----- Contents-envelope unwrap -----------------------------------------


def test_unwrap_contents_envelope_decodes_base64_and_passes_raw():
    inner = (
        "module example.com/foo/bar\n\ngo 1.21\n\n"
        "require (\n\tgithub.com/foo/bar v1.0.0\n)\n"
    )
    envelope = json.dumps(dict(
        name="go.mod",
        path="go.mod",
        encoding="base64",
        content=base64.b64encode(inner.encode()).decode(),
        type="file",
    ))
    out = github._unwrap_contents_envelope(envelope)
    assert out == inner
    # The envelope itself must NOT survive into the result.
    assert "encoding" not in out
    assert "base64" not in out

    # Raw text (non-JSON, or JSON without base64 encoding) passes through.
    raw = "this is plain text, not a json object"
    assert github._unwrap_contents_envelope(raw) == raw


def test_fetch_manifest_contents_unwraps_go_mod_envelope(monkeypatch):
    """The /contents/ endpoint returns a JSON envelope -- fetching must unwrap it."""
    _nuke_sleep(monkeypatch)
    inner = "module example.com/foo/bar\n\ngo 1.21\n"
    envelope = json.dumps(dict(
        name="go.mod",
        path="go.mod",
        encoding="base64",
        content=base64.b64encode(inner.encode()).decode(),
        type="file",
    )).encode()
    conn = FakeConn([FakeResponse(200, envelope)])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)
    out = github._fetch_manifest_contents(
        client, "owner", "repo", [dict(path="go.mod", type="blob")]
    )
    assert out == {"go.mod": inner}
    # The fetched manifest must be the real Go module text, not the envelope.
    assert "encoding" not in out["go.mod"]


# ----- Budget gate ------------------------------------------------------


def test_budget_gate_refuses_when_insufficient_names_reset(monkeypatch):
    _nuke_sleep(monkeypatch)
    rl = json.dumps(dict(
        resources=dict(core=dict(remaining=5, reset=1700000000))
    )).encode()
    conn = FakeConn([FakeResponse(200, rl)])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)
    ok, msg = github.budget_gate(client, num_refs=10, calls_per_ref=10)
    assert ok is False
    assert "5" in msg
    assert "100" in msg
    # The reset time must be NAMED (formatted as ISO date).
    assert "2023" in msg


def test_budget_gate_allows_when_enough(monkeypatch):
    _nuke_sleep(monkeypatch)
    rl = json.dumps(dict(
        resources=dict(core=dict(remaining=500, reset=1700000000))
    )).encode()
    conn = FakeConn([FakeResponse(200, rl)])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)
    ok, msg = github.budget_gate(client, num_refs=10, calls_per_ref=10)
    assert ok is True
    assert msg == ""


def test_budget_gate_probe_failure_returns_ok_true_with_warning(monkeypatch):
    _nuke_sleep(monkeypatch)
    client = github.GitHubClient(token=VALID_TOKEN, conn=FailingConn())
    ok, msg = github.budget_gate(client, num_refs=10, calls_per_ref=10)
    assert ok is True
    assert "could not probe" in msg
    assert "proceeding unguarded" in msg


# ----- Repo-move (301) and 404 handling ----------------------------------


def test_fetch_repo_metadata_301_location_then_body_url(monkeypatch):
    _nuke_sleep(monkeypatch)
    # Case A: Location header carries the new full_name.
    headers = dict(Location="https://api.github.com/repos/newowner/newrepo")
    conn_a = FakeConn([FakeResponse(301, b"{}", headers)])
    client_a = github.GitHubClient(token=VALID_TOKEN, conn=conn_a)
    facts_a = github.fetch_repo_metadata(client_a, "oldowner", "oldrepo")
    assert facts_a.exists is False
    assert facts_a.moved_to == "newowner/newrepo"

    # Case B: no Location header -- the body['url'] field is parsed instead.
    body = json.dumps(dict(
        url="https://api.github.com/repos/newowner2/newrepo2",
        message="Moved Permanently",
    )).encode()
    conn_b = FakeConn([FakeResponse(301, body, dict())])
    client_b = github.GitHubClient(token=VALID_TOKEN, conn=conn_b)
    facts_b = github.fetch_repo_metadata(client_b, "oldowner", "oldrepo")
    assert facts_b.exists is False
    assert facts_b.moved_to == "newowner2/newrepo2"


def test_fetch_repo_metadata_404_returns_not_exists_no_moved_to(monkeypatch):
    _nuke_sleep(monkeypatch)
    conn = FakeConn([FakeResponse(404, b'{"message":"Not Found"}')])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)
    facts = github.fetch_repo_metadata(client, "owner", "repo")
    assert facts.exists is False
    assert facts.moved_to is None


# ----- Rate-limit signalling --------------------------------------------


def test_request_raises_rate_limit_error_on_403_zero_remaining(monkeypatch):
    _nuke_sleep(monkeypatch)
    # Header names are hyphenated; a dict(**kwargs) literal cannot express them.
    headers = {
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1700000000",
        "Retry-After": "60",
    }
    conn = FakeConn([FakeResponse(403, b'{"message":"rate limit"}', headers)])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)
    with pytest.raises(github.RateLimitError) as exc:
        client.get_json("/repos/foo/bar")
    assert exc.value.reset == 1700000000
    assert exc.value.retry_after == "60"
    assert "1700000000" in str(exc.value)


# ----- Token-leak prevention --------------------------------------------


def test_token_never_appears_in_repofacts_or_error_string(monkeypatch):
    _nuke_sleep(monkeypatch)
    secret = "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"

    # Path 1: a 301 move sets moved_to. None of the fields may contain the token.
    headers = dict(Location="https://api.github.com/repos/newowner/newrepo")
    conn = FakeConn([FakeResponse(301, b"{}", headers)])
    client = github.GitHubClient(token=secret, conn=conn)
    facts = github.fetch_repo_metadata(client, "owner", "repo")
    for field in dataclasses.fields(facts):
        val = getattr(facts, field.name)
        if isinstance(val, str):
            assert secret not in val, "token leaked into " + field.name
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    assert secret not in item, "token leaked into " + field.name
    assert secret not in repr(facts)

    # Path 2: a 500 surfaces as facts.error. Same guarantee must hold.
    conn2 = FakeConn([FakeResponse(500, b"oops")])
    client2 = github.GitHubClient(token=secret, conn=conn2)
    facts2 = github.fetch_repo_metadata(client2, "owner", "repo")
    assert facts2.error is not None
    assert secret not in facts2.error

    # Path 3: the encoded Bearer header itself must not echo anywhere.
    sent_headers = conn.requests[0]["headers"]
    assert sent_headers["Authorization"] == "Bearer " + secret

# ----- Token shape: exact boundaries -------------------------------------


def test_validate_token_shape_boundaries():
    """TOKEN_PATTERN is ^gh[pous]_[A-Za-z0-9]{36,}$ -- nothing looser."""
    v = github._validate_token_shape

    # All four documented prefixes are accepted (gho_ is what `gh` issues).
    for prefix in ("ghp_", "gho_", "ghu_", "ghs_"):
        assert v(prefix + "A" * 36) is True, prefix

    assert v("ghp_" + "A" * 36) is True
    assert v("ghp_" + "A" * 35) is False          # one character short
    assert v("ghp_" + "A" * 255) is True          # no upper bound
    assert v("ghx_" + "A" * 36) is False          # unknown prefix letter
    assert v("gh_" + "A" * 36) is False           # missing prefix letter
    assert v("github_pat_" + "A" * 36) is False   # fine-grained PAT: not this shape
    assert v("ghp_" + "A" * 30 + "-!@#$%") is False  # non-alphanumeric body
    assert v("") is False
    assert v(None) is False

    # Surrounding whitespace is tolerated (values come from env / CLI output).
    assert v("  ghp_" + "A" * 36 + "  \n") is True

    # ...but an *embedded* newline must never validate: that value would be
    # interpolated into `Authorization: Bearer <token>` and could inject a
    # second header line.
    assert v("ghp_" + "A" * 36 + "\nX-Injected: 1") is False


def test_discover_token_strips_whitespace_from_env_value(monkeypatch):
    """A trailing newline in an env var must not reach the Bearer header."""
    monkeypatch.setattr(github, "_run_gh_auth_token", lambda: None)
    raw = "ghp_" + "k" * 36
    token, source = github.discover_token(env={"GH_TOKEN": "  " + raw + "\n"})
    assert token == raw
    assert source == "GH_TOKEN"
    assert "\n" not in token


# ----- 429 / secondary rate limits ---------------------------------------


def test_429_with_retry_after_is_retried_once_then_succeeds(monkeypatch):
    slept = []
    monkeypatch.setattr(github.time, "sleep", lambda s: slept.append(s))
    conn = FakeConn([
        FakeResponse(429, b"{}", {"Retry-After": "3"}),
        FakeResponse(200, b'{"stargazers_count": 7}', {}),
    ])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)

    status, _, data = client.get_json("/repos/foo/bar")
    assert status == 200
    assert data["stargazers_count"] == 7
    assert slept == [3]              # honoured Retry-After, capped at 30
    assert len(conn.requests) == 2   # retried exactly once


def test_429_with_zero_remaining_raises_rate_limit_error(monkeypatch):
    """A 429 that survives the Retry-After retry is a hard rate limit.

    RateLimitError's own docstring says "403/429 with X-RateLimit-Remaining
    == 0". If a 429 is instead handed back as an ordinary status, every repo
    in the run is recorded as "github returned HTTP 429" and ``fetch_all``
    reports ``partial=False`` -- i.e. a check that could not run is rendered
    as a result. That is the one failure mode this codebase cannot have.
    """
    monkeypatch.setattr(github.time, "sleep", lambda *a, **k: None)
    headers = {
        "Retry-After": "60",
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1700000000",
    }
    conn = FakeConn([
        FakeResponse(429, b'{"message":"rate limit"}', headers),
        FakeResponse(429, b'{"message":"rate limit"}', headers),
    ])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)

    with pytest.raises(github.RateLimitError) as exc:
        client.get_json("/repos/foo/bar")
    assert exc.value.reset == 1700000000
    assert exc.value.retry_after == "60"


def test_rate_limit_signal_detected_with_lowercase_headers(monkeypatch):
    """HTTP field names are case-insensitive (RFC 9110 5.1).

    ``http.client`` hands back whatever casing the server used, and GitHub
    sends ``x-ratelimit-remaining`` lower-cased. If the client only looks up
    the canonical casing, the rate-limit signal is silently lost and the run
    reports per-repo HTTP errors instead of "rate limited, results partial".
    """
    monkeypatch.setattr(github.time, "sleep", lambda *a, **k: None)
    headers = {
        "x-ratelimit-remaining": "0",
        "x-ratelimit-reset": "1700000000",
        "retry-after": "42",
    }
    conn = FakeConn([FakeResponse(403, b'{"message":"rate limit"}', headers)])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)

    with pytest.raises(github.RateLimitError) as exc:
        client.get_json("/repos/foo/bar")
    assert exc.value.reset == 1700000000
    assert exc.value.retry_after == "42"


def test_403_that_is_not_a_rate_limit_is_not_swallowed(monkeypatch):
    """403 with budget remaining is a permission error, not a rate limit."""
    monkeypatch.setattr(github.time, "sleep", lambda *a, **k: None)
    headers = {"X-RateLimit-Remaining": "4321"}
    conn = FakeConn([FakeResponse(403, b'{"message":"Forbidden"}', headers)])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)

    status, _, _ = client.get_json("/repos/foo/bar")
    assert status == 403


# ----- /contents/ envelope: the other caller, and the 404 contract --------


def test_fetch_workflow_contents_unwraps_envelope(monkeypatch):
    monkeypatch.setattr(github.time, "sleep", lambda *a, **k: None)
    yaml_text = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
    envelope = json.dumps({
        "path": ".github/workflows/ci.yml",
        "encoding": "base64",
        "content": base64.b64encode(yaml_text.encode()).decode(),
    }).encode()
    conn = FakeConn([FakeResponse(200, envelope)])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)

    out = github._fetch_workflow_contents(
        client, "owner", "repo", [".github/workflows/ci.yml"]
    )
    assert out == {".github/workflows/ci.yml": yaml_text}
    assert "base64" not in out[".github/workflows/ci.yml"]


def test_envelope_unwrap_survives_multiline_base64_and_non_utf8():
    """GitHub line-wraps its base64 payload at 60 chars."""
    inner = "requests==2.31.0\nurllib3==2.2.1\n" * 40
    b64 = base64.encodebytes(inner.encode()).decode()  # wrapped with \n
    assert "\n" in b64.strip()
    envelope = json.dumps({"encoding": "base64", "content": b64})
    assert github._unwrap_contents_envelope(envelope) == inner

    # A latin-1 byte must not blow up the unwrapper.
    envelope2 = json.dumps({
        "encoding": "base64",
        "content": base64.b64encode(b"caf\xe9 = 1\n").decode(),
    })
    assert "1" in github._unwrap_contents_envelope(envelope2)


def test_envelope_unwrap_passes_through_a_genuine_json_manifest():
    """package.json is real JSON and must survive unchanged."""
    pkg = '{\n  "name": "left-pad",\n  "dependencies": {"a": "^1.0.0"}\n}\n'
    assert github._unwrap_contents_envelope(pkg) == pkg
    # Truncated / invalid JSON also passes through rather than raising.
    assert github._unwrap_contents_envelope('{"encoding": "base') == '{"encoding": "base'


def test_manifest_that_404s_is_omitted_never_empty_string(monkeypatch):
    """A manifest we could not read must be ABSENT, not present-and-empty.

    An empty string parses as "zero dependencies", which renders as a clean
    supply-chain result -- a check that could not run masquerading as a pass.
    """
    monkeypatch.setattr(github.time, "sleep", lambda *a, **k: None)
    conn = FakeConn([FakeResponse(404, b'{"message":"Not Found"}')])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)

    out = github._fetch_manifest_contents(
        client, "owner", "repo", [{"path": "package.json", "type": "blob"}]
    )
    assert out == {}
    assert "package.json" not in out


# ----- Budget gate: boundary + whole-run refusal --------------------------


def test_budget_gate_boundary_exactly_enough_vs_one_short(monkeypatch):
    monkeypatch.setattr(github.time, "sleep", lambda *a, **k: None)

    def gate(remaining):
        body = json.dumps({
            "resources": {"core": {"remaining": remaining, "reset": 1700000000}}
        }).encode()
        client = github.GitHubClient(
            token=VALID_TOKEN, conn=FakeConn([FakeResponse(200, body)])
        )
        return github.budget_gate(client, num_refs=10, calls_per_ref=2)

    ok, msg = gate(20)          # exactly enough
    assert ok is True and msg == ""

    ok, msg = gate(19)          # one short
    assert ok is False
    assert "19" in msg and "20" in msg
    assert "2023-11-14" in msg  # reset time is named, not just the epoch


def test_fetch_all_refuses_to_start_when_budget_gate_refuses(monkeypatch):
    """An insufficient budget must abort the whole run, not half-run it."""
    monkeypatch.setattr(
        github,
        "budget_gate",
        lambda *a, **k: (False, "only 3 requests remaining, need 40; "
                                "rate-limit resets at 2023-11-14T22:13:20+00:00"),
    )
    refs = [
        RepoRef(owner="o", repo=f"r{i}", raw_mention=f"o/r{i}")
        for i in range(20)
    ]
    with pytest.raises(RuntimeError) as exc:
        github.fetch_all(refs, VALID_TOKEN, workers=4)
    assert "rate-limit resets at" in str(exc.value)
    assert "need 40" in str(exc.value)


def test_fetch_repo_metadata_200_populates_and_returns_repofacts(monkeypatch):
    monkeypatch.setattr(github.time, "sleep", lambda *a, **k: None)
    body = json.dumps({
        "stargazers_count": 42,
        "forks_count": 3,
        "language": "Go",
        "default_branch": "trunk",
        "archived": True,
        "license": {"spdx_id": "AGPL-3.0", "name": "GNU AGPL v3"},
    }).encode()
    conn = FakeConn([FakeResponse(200, body)])
    client = github.GitHubClient(token=VALID_TOKEN, conn=conn)

    facts = github.fetch_repo_metadata(client, "owner", "repo")
    assert isinstance(facts, RepoFacts)
    assert facts.exists is True
    assert facts.stars == 42
    assert facts.default_branch == "trunk"
    assert facts.archived is True
    assert facts.license_spdx == "AGPL-3.0"
    assert facts.moved_to is None
    assert facts.error is None
    # readme_status must still be the un-fetched default: metadata alone
    # never implies the README was checked.
    assert facts.readme_status != "fetched"
