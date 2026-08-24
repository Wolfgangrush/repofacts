"""GitHub REST client — the *only* module that touches the network.

Implementation notes:

* Uses :class:`http.client.HTTPSConnection` (one persistent keep-alive
  connection per worker). ``urllib.request`` opens a fresh TCP+TLS handshake
  per call, which makes 8 workers *slower* than 1 — a finding raised in the
  Phase-3 pass that this code addresses.
* Standard library only; no third-party deps.
* Token discovery order — explicit so test_github.py can audit it:
      ``$REPOFACTS_TOKEN`` → ``$GH_TOKEN`` → ``$GITHUB_TOKEN`` →
      ``gh auth token`` → unauthenticated.
* The token is *never* logged, returned in a string that could be serialised,
  or echoed back to the caller as text. ``discover_token`` returns it only
  as opaque data for the next call to use.
"""

from __future__ import annotations

import concurrent.futures
import gzip
import http.client
import base64
import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone

from .models import DeepFacts, QualityFacts, RepoFacts, RepoRef, SecurityFacts


GITHUB_API_HOST = "api.github.com"
API_BASE = f"https://{GITHUB_API_HOST}"

# GitHub PAT shape: ``gh[pous]_<36+ alnum>``. Includes ``gho_`` (OAuth), which
# is exactly what the ``gh`` CLI issues. Validating before sending prevents
# the "help text sent as Bearer token → baffling 401" failure mode.
TOKEN_PATTERN = re.compile(r"^gh[pous]_[A-Za-z0-9]{36,}$")


# ----- Errors -------------------------------------------------------------


class RateLimitError(Exception):
    """Raised when GitHub returns 403/429 with X-RateLimit-Remaining == 0."""

    def __init__(self, retry_after: str = "", reset: int = 0, url: str = ""):
        super().__init__(f"rate limited (reset={reset} retry_after={retry_after})")
        self.retry_after = retry_after
        self.reset = reset
        self.url = url


class HTTPStatusError(Exception):
    """Raised for non-2xx responses other than 301/404 (handled separately)."""

    def __init__(self, status: int, url: str, body: str = ""):
        super().__init__(f"HTTP {status} from {url}")
        self.status = status
        self.url = url
        self.body = body


# ----- Token discovery ----------------------------------------------------


def _validate_token_shape(token: str | None) -> bool:
    """Return ``True`` iff ``token`` looks like a real GitHub PAT/OAuth token.

    ``gh auth token`` can print help text to stdout and exit 0 — without this
    check, that help text becomes a Bearer token and produces a confusing
    401.
    """
    if not token:
        return False
    return bool(TOKEN_PATTERN.match(token.strip()))


def _run_gh_auth_token() -> str | None:
    """Best-effort: ask ``gh`` for its token. Returns ``None`` on any failure."""
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    out = (result.stdout or "").strip()
    if _validate_token_shape(out):
        return out
    return None


def discover_token(
    token_env: str | None = None,
    env: dict | None = None,
) -> tuple[str | None, str]:
    """Find a usable GitHub token.

    Args:
        token_env: If set, this env-var name is tried *before* the default
            chain. The default chain is documented in the module docstring.
        env: Override of ``os.environ`` for testing; defaults to real env.

    Returns:
        ``(token, source)`` where ``source`` is one of:
            ``"REPOFACTS_TOKEN"``, ``"GH_TOKEN"``, ``"GITHUB_TOKEN"``,
            ``"GITHUB_TOKEN (Actions-provisioned, 1000/hr)"``,
            ``"gh"``, ``"none"``.

        The *token value itself is never serialised or returned as a string
        suitable for logging*; callers must use it only for the next HTTP
        request. The string ``source`` is safe to print.
    """
    e = env if env is not None else os.environ

    def lookup(name: str) -> str | None:
        v = e.get(name)
        if v and _validate_token_shape(v):
            return v.strip()
        return None

    # 0. Caller-specified override (treated as the highest priority).
    if token_env:
        t = lookup(token_env)
        if t is not None:
            return t, token_env

    # 1-2. The repo-facts-local envs come first on purpose.
    if (t := lookup("REPOFACTS_TOKEN")) is not None:
        return t, "REPOFACTS_TOKEN"
    if (t := lookup("GH_TOKEN")) is not None:
        return t, "GH_TOKEN"

    # 3. GitHub Actions' auto-provisioned token — deliberately *after* the
    # user's local env vars so a personal PAT is preferred.
    if (t := lookup("GITHUB_TOKEN")) is not None:
        return t, "GITHUB_TOKEN (Actions-provisioned, 1000/hr)"

    # 4. Best-effort `gh`.
    t = _run_gh_auth_token()
    if t is not None:
        return t, "gh"

    # 5. Unauthenticated.
    return None, "none"


# ----- Connection / client ------------------------------------------------


class _Headers(dict):
    """Response headers with case-insensitive lookup.

    HTTP field names are case-insensitive (RFC 9110 §5.1) and GitHub sends
    ``x-ratelimit-remaining`` / ``retry-after`` lower-cased, but
    ``http.client`` hands back whatever casing the server used — so a plain
    ``dict(resp.getheaders())`` misses ``headers.get("X-RateLimit-Remaining")``
    entirely. That silently disabled the hard rate-limit signal: every repo in
    the run was recorded as "github returned HTTP 403" and ``fetch_all``
    reported ``partial=False``, i.e. a check that could not run rendered as a
    result.

    Keys keep their original casing (so ``dict(headers)`` is unchanged for any
    caller that iterates); only lookup is case-folded. This fixes the whole
    class of lookup, not just the rate-limit one — the ``Location`` and
    ``Content-Type`` readers were already hand-rolling ``get("X") or
    get("x")`` around the same hazard.
    """

    def __init__(self, items=()):
        super().__init__(items)
        self._folded = {k.lower(): v for k, v in self.items()}

    def get(self, key, default=None):
        if isinstance(key, str):
            return self._folded.get(key.lower(), default)
        return super().get(key, default)

    def __getitem__(self, key):
        if isinstance(key, str) and key.lower() in self._folded:
            return self._folded[key.lower()]
        return super().__getitem__(key)

    def __contains__(self, key):
        if isinstance(key, str) and key.lower() in self._folded:
            return True
        return super().__contains__(key)


class GitHubClient:
    """A small GitHub REST client using a persistent HTTPS connection.

    Construct one per worker thread. ``conn`` may be injected for testing.
    """

    USER_AGENT = "repofacts/0.1.0"

    def __init__(
        self,
        token: str | None = None,
        *,
        conn: http.client.HTTPSConnection | None = None,
        host: str = GITHUB_API_HOST,
        timeout: float = 15.0,
    ):
        self._token = token
        self._host = host
        self._timeout = timeout
        self._conn = conn

    # -- public API ---------------------------------------------------------

    def get_json(self, path: str) -> tuple[int, dict, dict]:
        """GET a path; return ``(status, headers, body-as-dict)``."""
        status, headers, body = self._request("GET", path)
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = {}
        return status, headers, data

    def get_raw(self, path: str) -> tuple[int, dict, bytes]:
        """GET a path; return ``(status, headers, body-bytes)``.

        Body is gzip-decoded if needed. Used for README contents.
        """
        status, headers, body = self._request("GET", path)
        return status, headers, body

    # -- internals ----------------------------------------------------------

    def _connect(self) -> http.client.HTTPSConnection:
        if self._conn is None:
            # Not thread-safe: each worker owns its own connection and never
            # shares it across threads.
            self._conn = http.client.HTTPSConnection(self._host, timeout=self._timeout)
        return self._conn

    def _headers(self, extra: dict | None = None) -> dict:
        h = {
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "gzip",
            "User-Agent": self.USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        if extra:
            h.update(extra)
        return h

    def _request(self, method: str, path: str, extra_headers: dict | None = None):
        """Perform one HTTP request; handle gzip, retries, rate-limit signals.

        Returns ``(status, headers, body_bytes)``.

        Retries transient connection drops up to 3 times with a short backoff.
        Honours ``Retry-After`` on 429 by sleeping before retrying once.
        Raises :class:`RateLimitError` on hard rate-limit signal so the caller
        can short-circuit the run.
        """
        url = path if path.startswith("/") else f"/{path}"
        full_url = f"{API_BASE}{url}"
        attempt = 0
        last_err: Exception | None = None
        transient_retried_after = False

        while attempt < 3:
            attempt += 1
            conn = self._connect()
            try:
                conn.request(method, url, headers=self._headers(extra_headers))
                resp = conn.getresponse()
                raw = resp.read()
                if resp.getheader("Content-Encoding") == "gzip":
                    try:
                        raw = gzip.decompress(raw)
                    except OSError:
                        pass
                headers = _Headers(resp.getheaders())
                status = resp.status

                if status == 429 and not transient_retried_after:
                    ra = headers.get("Retry-After", "")
                    if ra:
                        try:
                            time.sleep(min(int(ra), 30))
                        except ValueError:
                            time.sleep(5)
                        transient_retried_after = True
                        continue  # try the same call once more

                # 403 *and* 429 signal a hard limit — RateLimitError's
                # contract says "403/429 with X-RateLimit-Remaining == 0".
                # 429 is what GitHub's secondary rate limiter returns; handing
                # it back as an ordinary status made the run look merely
                # broken instead of merely incomplete.
                if (
                    status in (403, 429)
                    and headers.get("X-RateLimit-Remaining") == "0"
                ):
                    reset_raw = headers.get("X-RateLimit-Reset", "0")
                    try:
                        reset = int(reset_raw)
                    except ValueError:
                        reset = 0
                    raise RateLimitError(
                        retry_after=headers.get("Retry-After", ""),
                        reset=reset,
                        url=full_url,
                    )

                return status, headers, raw

            except (http.client.RemoteDisconnected, ConnectionResetError, OSError) as e:
                last_err = e
                self._conn = None  # force reconnect
                time.sleep(0.5 * attempt)

        raise HTTPStatusError(0, full_url, body=str(last_err))

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


# ----- Repo fetch --------------------------------------------------------


_LICENSE_FILE_PATTERNS = [
    re.compile(r"LICENSES?[-_/]([A-Za-z0-9._-]+)", re.IGNORECASE),
    re.compile(r"LICENSE-([A-Za-z0-9._-]+)", re.IGNORECASE),
]


def _find_licence_file_refs(readme_text: str | None) -> list[str]:
    """Return a deduplicated list of ``LICENSES/…`` or ``LICENSE-…`` refs."""
    if not readme_text:
        return []
    seen: set = set()
    out: list[str] = []
    for pat in _LICENSE_FILE_PATTERNS:
        for m in pat.finditer(readme_text):
            token = m.group(0)
            if token not in seen:
                seen.add(token)
                out.append(token)
    return out


def fetch_repo_metadata(
    client: GitHubClient, owner: str, repo: str
) -> RepoFacts:
    """Fetch ``/repos/{owner}/{repo}`` and translate into :class:`RepoFacts`.

    Handles 404 (missing), 301 (moved), and a few other shapes. Body is only
    filled when the endpoint says the repo exists.
    """
    facts = RepoFacts(owner=owner, repo=repo)
    try:
        status, headers, data = client.get_json(f"/repos/{owner}/{repo}")
    except RateLimitError:
        raise
    except HTTPStatusError as e:
        facts.error = f"github API error: {e}"
        return facts
    except Exception as e:
        facts.error = f"github API error: {e}"
        return facts

    if status == 404:
        facts.exists = False
        return facts

    if status in (301, 302):
        # Moved permanently — try to extract the new full_name from the
        # response body or the Location header.
        new_full = ""
        location = headers.get("Location", "") or headers.get("location", "")
        m = re.search(r"/repos/([^/]+)/([^/]+)", location)
        if m:
            new_full = f"{m.group(1)}/{m.group(2)}"
        if not new_full:
            url = (data or {}).get("url", "")
            m = re.search(r"/repos/([^/]+)/([^/]+)", url)
            if m:
                new_full = f"{m.group(1)}/{m.group(2)}"
        if not new_full:
            new_full = location or ""
        facts.exists = False
        facts.moved_to = new_full or None
        return facts

    if status >= 400:
        facts.error = f"github returned HTTP {status}"
        return facts

    facts.exists = True
    facts.stars = data.get("stargazers_count")
    facts.forks = data.get("forks_count")
    facts.language = data.get("language")
    facts.description = data.get("description")
    facts.pushed_at = data.get("pushed_at")
    facts.created_at = data.get("created_at")
    facts.default_branch = data.get("default_branch")
    facts.archived = bool(data.get("archived"))
    facts.disabled = bool(data.get("disabled"))
    facts.fork = bool(data.get("fork"))
    parent = data.get("parent") or {}
    facts.parent_full_name = parent.get("full_name")
    lic = data.get("license") or {}
    facts.license_spdx = lic.get("spdx_id")
    facts.license_name = lic.get("name")
    if data.get("private"):
        facts.private = True
    return facts


def fetch_repo_readme(
    client: GitHubClient, owner: str, repo: str, max_bytes: int = 1_500_000
) -> tuple[str, str | None]:
    """Fetch the README for a repo.

    Returns ``(readme_status, readme_text)``. Status is one of:
        ``fetched``, ``missing``, ``binary``, ``too_large``, ``no_branch``,
        ``error``.

    Keeps the README text under ``max_bytes`` to bound memory.
    """
    try:
        status, headers, body = client.get_raw(f"/repos/{owner}/{repo}/readme")
    except RateLimitError:
        raise
    except HTTPStatusError as e:
        return "error", f"readme fetch HTTP {e.status}"
    except Exception as e:
        return "error", f"readme fetch failed: {e}"

    if status == 404:
        return "missing", None
    if status >= 400:
        return "error", None

    ctype = headers.get("Content-Type", headers.get("content-type", "")).lower()
    if "octet-stream" in ctype or "binary" in ctype:
        return "binary", None

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = body.decode("latin-1", errors="replace")
        except Exception:
            return "binary", None

    if not text:
        return "missing", None

    if len(text) > max_bytes:
        truncated = text[:max_bytes]
        return "too_large", truncated

    return "fetched", text


def fetch_facts(
    client: GitHubClient,
    ref: RepoRef,
    *,
    want_readme: bool = True,
) -> RepoFacts:
    """Fetch all facts about one repo (metadata + optional README)."""
    facts = fetch_repo_metadata(client, ref.owner, ref.repo)
    if not facts.exists:
        return facts
    if not want_readme:
        facts.readme_status = "skipped"
        return facts
    status, text = fetch_repo_readme(client, ref.owner, ref.repo)
    facts.readme_status = status
    if status == "fetched" or status == "too_large":
        facts.readme_text = text
        facts.readme_license_files = _find_licence_file_refs(text)
    return facts


# ----- Budget gate + parallel fetch ---------------------------------------


def budget_gate(
    client: GitHubClient, num_refs: int, calls_per_ref: int
) -> tuple[bool, str]:
    """Pre-flight check against ``/rate_limit``.

    Returns ``(ok, message)``. ``ok=False`` means we have *insufficient*
    budget to do the run and the caller should refuse to start, naming the
    reset time in ``message``. ``ok=True`` with a non-empty ``message`` means
    the probe itself failed and the caller is being told to proceed with
    caution.
    """
    try:
        _, _, rl = client.get_json("/rate_limit")
    except Exception as e:
        return True, f"could not probe rate limit ({e}); proceeding unguarded"

    core = ((rl or {}).get("resources") or {}).get("core") or {}
    remaining = core.get("remaining", 0)
    reset = core.get("reset", 0)
    needed = max(1, num_refs * calls_per_ref)
    if remaining < needed:
        if reset:
            try:
                reset_str = datetime.fromtimestamp(reset, tz=timezone.utc).isoformat()
            except (OSError, ValueError, OverflowError):
                reset_str = str(reset)
        else:
            reset_str = "unknown"
        return False, (
            f"only {remaining} requests remaining, need {needed}; "
            f"rate-limit resets at {reset_str}"
        )
    return True, ""


def fetch_all(
    refs: list[RepoRef],
    token: str | None,
    *,
    workers: int = 8,
    want_readme: bool = True,
) -> tuple[list[RepoFacts], bool]:
    """Fetch facts for every ref in parallel.

    Returns ``(facts_list, was_partial)``. ``facts_list`` is the same length
    as ``refs`` and preserves order. ``was_partial`` is ``True`` if any task
    ended via :class:`RateLimitError` — the caller should surface this to the
    user and exit 2.
    """
    if not refs:
        return [], False

    if workers < 1:
        workers = 1

    # Pool of clients — each worker owns one connection.
    clients = [GitHubClient(token) for _ in range(workers)]

    calls_per_ref = 2 if want_readme else 1
    try:
        ok, msg = budget_gate(clients[0], len(refs), calls_per_ref)
    except Exception as e:
        # Probe itself failed — proceed unguarded. The caller (cli.py) is
        # responsible for any user-visible warning. The ``ok=True`` means
        # "don't refuse to start".
        ok, msg = True, f"budget probe threw ({e}); proceeding unguarded"

    if not ok:
        for c in clients:
            c.close()
        raise RuntimeError(msg)

    results: list[RepoFacts | None] = [None] * len(refs)
    rate_limited = threading.Event()
    rate_limit_msg = ""

    def _task(idx: int) -> None:
        ref = refs[idx]
        worker_id = idx % workers
        client = clients[worker_id]
        try:
            results[idx] = fetch_facts(client, ref, want_readme=want_readme)
        except RateLimitError as e:
            nonlocal_msg = (
                f"rate limit hit; reset={e.reset} retry_after={e.retry_after}"
            )
            rate_limited.set()
            rate_limit_msg_set(nonlocal_msg)
            results[idx] = RepoFacts(
                owner=ref.owner,
                repo=ref.repo,
                exists=False,
                error=f"rate limited; reset={e.reset}",
            )
        except Exception as e:
            results[idx] = RepoFacts(
                owner=ref.owner,
                repo=ref.repo,
                exists=False,
                error=f"worker error: {e}",
            )

    msg_lock = threading.Lock()

    def rate_limit_msg_set(s: str) -> None:
        nonlocal rate_limit_msg
        with msg_lock:
            rate_limit_msg = s

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_task, i) for i in range(len(refs))]
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception:
                pass

    for c in clients:
        c.close()

    final = []
    for i, r in enumerate(results):
        if r is None:
            # Shouldn't happen — but never silently drop.
            ref = refs[i]
            final.append(RepoFacts(
                owner=ref.owner,
                repo=ref.repo,
                exists=False,
                error="no result produced",
            ))
        else:
            final.append(r)

    partial = rate_limited.is_set()
    return final, partial


# ----- Deep fetchers (security & quality) ---------------------------------
#
# All of these are *additional* calls on top of ``fetch_all``. The fast
# default path (no ``--deep`` flag) never reaches them; an orchestrator
# who wants them runs ``fetch_security_facts`` / ``fetch_quality_facts``
# after ``fetch_all`` returns. This keeps the unauthenticated 60-req/hr
# budget intact for the common case.
#
# Every primitive fetcher below is deliberately *partial*: it returns
# what it could, leaves the rest empty, and never raises for a 404.
# That's the contract the pure layer relies on to map missing data to
# ``unchecked`` rather than guessing.

# Files we look for in the repo tree for security/quality signals.
_SECURITY_MD_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
_CHANGELOG_PATHS = (
    "CHANGELOG.md", "CHANGELOG", "CHANGES.md", "HISTORY.md",
    "docs/CHANGELOG.md", ".github/CHANGELOG.md",
)
_DEPENDABOT_PATHS = (".github/dependabot.yml", ".github/dependabot.yaml")
_RENOVATE_PATHS = (
    "renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json",
    ".github/renovate.json", ".github/renovate.json5",
)

# Manifest file basenames we scan for, with a per-ecosystem parser hint.
_MANIFEST_BASENAMES = (
    "package.json", "pyproject.toml", "setup.py", "requirements.txt",
    "Cargo.toml", "go.mod",
)

def _default_branch_of(
    client: GitHubClient, owner: str, repo: str, fallback: str | None = None
) -> str | None:
    """Return the repo's default branch name, or ``fallback`` on failure.

    Endpoint: ``GET /repos/{owner}/{repo}``. We only read one field.
    """
    try:
        status, _, data = client.get_json(f"/repos/{owner}/{repo}")
    except Exception:
        return fallback
    if status != 200 or not isinstance(data, dict):
        return fallback
    name = data.get("default_branch")
    return name if isinstance(name, str) and name else fallback


def _fetch_branch_protection(
    client: GitHubClient, owner: str, repo: str, branch: str
) -> dict | None:
    """Return the raw protection payload, or ``None`` if not protected /
    unreachable.

    GitHub returns 404 both for "not protected" and for "no permission
    to view protection". The pure layer cannot distinguish those, so we
    treat 404 as "no protection payload available" and let the assessor
    decide whether to flag it as fail or unchecked.
    """
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/branches/{branch}/protection"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return None
    if status == 200 and isinstance(data, dict):
        return data
    return None


def _fetch_security_policy(
    client: GitHubClient, owner: str, repo: str
) -> bool | None:
    """Return whether a ``SECURITY.md`` exists at any conventional path.

    Returns:
        ``True`` if a 200 was seen at one of the conventional paths,
        ``False`` if every lookup returned 404, ``None`` if the fetcher
        could not run (network error before any lookup finished).
    """
    seen_404 = 0
    tried = 0
    for path in _SECURITY_MD_PATHS:
        tried += 1
        try:
            status, _, _ = client.get_raw(
                f"/repos/{owner}/{repo}/contents/{path}"
            )
        except (RateLimitError, HTTPStatusError):
            raise
        except Exception:
            return None
        if status == 200:
            return True
        if status == 404:
            seen_404 += 1
        else:
            # 403, 451, etc. — treat as "couldn't tell".
            return None
    if seen_404 == tried:
        return False
    return None


def _fetch_releases(
    client: GitHubClient, owner: str, repo: str, per_page: int = 10
) -> list[dict]:
    """Return up to ``per_page`` most recent releases (raw GitHub objects).

    Empty list if the endpoint returns 404 (no releases) or any error.
    """
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/releases?per_page={per_page}"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return []
    if status != 200 or not isinstance(data, list):
        return []
    return data


def _list_workflow_paths(
    client: GitHubClient, owner: str, repo: str
) -> list[str]:
    """Return the paths of all files under ``.github/workflows/``.

    Returns an empty list if the directory is missing or unreadable.
    """
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/contents/.github/workflows"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return []
    if status != 200 or not isinstance(data, list):
        return []
    return [
        entry["path"]
        for entry in data
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    ]


def _fetch_workflow_contents(
    client: GitHubClient, owner: str, repo: str, paths: list[str]
) -> dict[str, str]:
    """Return a ``path -> decoded YAML text`` map for the given paths.

    Skips paths that 404; empty entries are preserved as ``""``. A path
    that 404s is omitted (so the assessor can tell apart "this workflow
    exists but is empty" from "this workflow could not be fetched").
    """
    out: dict[str, str] = {}
    for path in paths:
        try:
            status, _, body = client.get_raw(
                f"/repos/{owner}/{repo}/contents/{path}"
            )
        except (RateLimitError, HTTPStatusError):
            raise
        except Exception:
            continue
        if status != 200:
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = body.decode("latin-1", errors="replace")
            except Exception:
                continue
        # The /contents/ endpoint answers `Accept: application/vnd.github+json`
        # with a JSON ENVELOPE whose `content` is base64 — not the file body.
        # Handing that envelope to a manifest parser yields zero dependencies
        # and therefore a silent FALSE ALL-CLEAR, which is the worst failure a
        # supply-chain check can have. Unwrap it. Caught 2026-08-24 by the
        # fresh-user simulation on ossf/scorecard: go.mod has 296 requires and
        # the tool reported 0.
        text = _unwrap_contents_envelope(text)
        out[path] = text
    return out


def _fetch_tree_top_levels(
    client: GitHubClient,
    owner: str,
    repo: str,
    ref: str | None,
    depth: int = 2,
) -> list[dict]:
    """Return a flat list of tree entries down to ``depth``.

    Uses ``/git/trees/{ref}?recursive={depth}``. GitHub caps recursion at
    depth 2 for unauthenticated callers; that's exactly what we want.
    """
    target = ref or "HEAD"
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/git/trees/{target}?recursive={depth}"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return []
    if status != 200 or not isinstance(data, dict):
        return []
    tree = data.get("tree")
    if not isinstance(tree, list):
        return []
    return [entry for entry in tree if isinstance(entry, dict)]


def _fetch_contributors(
    client: GitHubClient, owner: str, repo: str, per_page: int = 100
) -> list[dict]:
    """Return up to ``per_page`` contributors as raw GitHub objects."""
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/contributors?per_page={per_page}"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return []
    if status != 200 or not isinstance(data, list):
        return []
    return data


def _fetch_commit_activity(
    client: GitHubClient, owner: str, repo: str
) -> list[dict]:
    """Return the ``/stats/commit_activity`` payload.

    GitHub returns 202 with an empty body when stats haven't been
    computed yet; we treat that as "no data" and return ``[]``.
    """
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/stats/commit_activity"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return []
    if status != 200 or not isinstance(data, list):
        return []
    return data


def _fetch_recent_commits(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    sha: str | None = None,
    per_page: int = 100,
) -> list[dict]:
    """Return the most recent commits on the default branch (or ``sha``).

    The 100-commit cap matches what we use elsewhere; deeper history is
    not needed for bus-factor or contributor-concentration analysis.
    """
    path = f"/repos/{owner}/{repo}/commits?per_page={per_page}"
    if sha:
        path += f"&sha={sha}"
    try:
        status, _, data = client.get_json(path)
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return []
    if status != 200 or not isinstance(data, list):
        return []
    return data


def _fetch_head_sha(
    client: GitHubClient, owner: str, repo: str, branch: str | None
) -> str | None:
    """Return the HEAD SHA for ``branch`` (defaulting to the default branch).

    Uses ``/git/ref/heads/{branch}`` rather than ``/commits/{branch}``
    because it returns the SHA in a single line and is cheaper.
    """
    target = branch or "HEAD"
    try:
        if target == "HEAD":
            # ``HEAD`` is not valid for the git/refs API. Fall back to
            # the default branch on the repo metadata.
            status, _, data = client.get_json(f"/repos/{owner}/{repo}")
            if status != 200 or not isinstance(data, dict):
                return None
            target = data.get("default_branch")
            if not target:
                return None
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/git/ref/heads/{target}"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    obj = data.get("object") or {}
    sha = obj.get("sha")
    return sha if isinstance(sha, str) else None


def _fetch_check_runs(
    client: GitHubClient, owner: str, repo: str, sha: str
) -> str | None:
    """Return the *latest* check-run conclusion on ``sha``, or ``None``.

    Returns:
        ``"success"`` | ``"failure"`` | ``"neutral"`` | ``"cancelled"`` |
        ``"timed_out"`` | ``"action_required"`` | ``"skipped"`` |
        ``None`` if there were no check-runs or the endpoint failed.
    """
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/commits/{sha}/check-runs?per_page=10"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    runs = data.get("check_runs")
    if not isinstance(runs, list) or not runs:
        return None
    # Pick the most recent by ``started_at``/``completed_at``.
    def _ts(r: dict) -> str:
        return str(r.get("completed_at") or r.get("started_at") or "")

    latest = max(runs, key=_ts)
    conclusion = latest.get("conclusion")
    return conclusion if isinstance(conclusion, str) else None


def _fetch_tags(
    client: GitHubClient, owner: str, repo: str, per_page: int = 30
) -> list[str]:
    """Return up to ``per_page`` tag names (most recent first)."""
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/tags?per_page={per_page}"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return []
    if status != 200 or not isinstance(data, list):
        return []
    return [
        entry["name"]
        for entry in data
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    ]


def _fetch_changelog_presence(
    client: GitHubClient, owner: str, repo: str
) -> bool | None:
    """Return whether any conventional CHANGELOG file is present.

    Mirrors :func:`_fetch_security_policy`: ``True`` on a 200, ``False``
    if every path 404'd, ``None`` if the fetcher could not run.
    """
    seen_404 = 0
    tried = 0
    for path in _CHANGELOG_PATHS:
        tried += 1
        try:
            status, _, _ = client.get_raw(
                f"/repos/{owner}/{repo}/contents/{path}"
            )
        except (RateLimitError, HTTPStatusError):
            raise
        except Exception:
            return None
        if status == 200:
            return True
        if status == 404:
            seen_404 += 1
        else:
            return None
    if seen_404 == tried:
        return False
    return None


def _fetch_dependency_update_configs(
    client: GitHubClient, owner: str, repo: str
) -> tuple[bool | None, bool | None]:
    """Return ``(has_dependabot_config, has_renovate_config)``.

    Each is ``True`` / ``False`` / ``None`` per the same convention as
    :func:`_fetch_security_policy`.
    """
    def _one(paths: tuple[str, ...]) -> bool | None:
        seen_404 = 0
        tried = 0
        for path in paths:
            tried += 1
            try:
                status, _, _ = client.get_raw(
                    f"/repos/{owner}/{repo}/contents/{path}"
                )
            except (RateLimitError, HTTPStatusError):
                raise
            except Exception:
                return None
            if status == 200:
                return True
            if status == 404:
                seen_404 += 1
            else:
                return None
        if seen_404 == tried:
            return False
        return None

    try:
        dep = _one(_DEPENDABOT_PATHS)
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        dep = None
    try:
        ren = _one(_RENOVATE_PATHS)
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        ren = None
    return dep, ren


def _unwrap_contents_envelope(text: str) -> str:
    """Return the real file text from a GitHub /contents/ response.

    The endpoint returns a JSON object with base64 ``content`` when asked for
    JSON. If ``text`` is that envelope, decode and return the file body;
    otherwise return ``text`` unchanged, so a raw response still works.
    """
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return text
    try:
        payload = json.loads(stripped)
    except (ValueError, TypeError):
        return text
    if not isinstance(payload, dict):
        return text
    if payload.get("encoding") != "base64" or "content" not in payload:
        return text
    try:
        raw = base64.b64decode(payload["content"])
    except Exception:
        return text
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def _fetch_manifest_contents(
    client: GitHubClient, owner: str, repo: str, tree_entries: list[dict]
) -> dict[str, str]:
    """Return ``path -> content`` for every manifest in the tree.

    We restrict to the *top* 2 levels of the repo tree to bound the
    fan-out: a deep ``node_modules/`` never gets pulled. ``tree_entries``
    should already be a flat list from :func:`_fetch_tree_top_levels`.
    """
    candidates: list[str] = []
    seen: set[str] = set()
    for entry in tree_entries:
        if entry.get("type") != "blob":
            continue
        path = entry.get("path", "")
        if not isinstance(path, str) or not path:
            continue
        # Depth = number of path components; only top-level manifests
        # and the well-known second-level ones (src/foo/package.json,
        # apps/bar/setup.py) are picked up. Cap at depth 4 to bound work.
        parts = path.split("/")
        if len(parts) > 4:
            continue
        basename = parts[-1]
        if basename in _MANIFEST_BASENAMES and basename not in seen:
            seen.add(basename)
            candidates.append(path)

    out: dict[str, str] = {}
    for path in candidates:
        try:
            status, _, body = client.get_raw(
                f"/repos/{owner}/{repo}/contents/{path}"
            )
        except (RateLimitError, HTTPStatusError):
            raise
        except Exception:
            continue
        if status != 200:
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = body.decode("latin-1", errors="replace")
            except Exception:
                continue
        # The /contents/ endpoint answers `Accept: application/vnd.github+json`
        # with a JSON ENVELOPE whose `content` is base64 — NOT the file body.
        # Feeding that envelope to a manifest parser yields zero dependencies
        # and therefore a silent FALSE ALL-CLEAR, the worst failure a
        # supply-chain check can have. Caught 2026-08-24 by the fresh-user
        # simulation: ossf/scorecard go.mod has 296 requires, tool said 0.
        text = _unwrap_contents_envelope(text)
        out[path] = text
    return out


def _fetch_issue_response_hours(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    max_issues: int = 10,
    state: str = "all",
) -> list[float]:
    """Return hours-to-first-response for up to ``max_issues`` recent issues.

    Stops as soon as the cap is reached; a slow caller won't drag the
    whole run down. Empty list if the endpoint or any per-issue call
    fails — the assessor maps empty to ``unchecked``.
    """
    try:
        status, _, data = client.get_json(
            f"/repos/{owner}/{repo}/issues?state={state}&per_page={max_issues}"
        )
    except (RateLimitError, HTTPStatusError):
        raise
    except Exception:
        return []
    if status != 200 or not isinstance(data, list):
        return []

    out: list[float] = []
    for issue in data:
        if not isinstance(issue, dict):
            continue
        # Pull requests show up in the issues endpoint; skip them.
        if "pull_request" in issue:
            continue
        created_at = issue.get("created_at")
        comments = issue.get("comments", 0)
        if not created_at or not comments:
            continue
        try:
            issue_no = int(issue.get("number"))
        except (TypeError, ValueError):
            continue
        try:
            cstatus, _, cdata = client.get_json(
                f"/repos/{owner}/{repo}/issues/{issue_no}/comments?per_page=1"
            )
        except (RateLimitError, HTTPStatusError):
            raise
        except Exception:
            continue
        if cstatus != 200 or not isinstance(cdata, list) or not cdata:
            continue
        first = cdata[0]
        first_at = first.get("created_at") if isinstance(first, dict) else None
        if not first_at:
            continue
        # Cheap ISO-8601 → datetime; both endpoints use the same shape.
        try:
            from datetime import datetime as _dt_cls, timezone as _tz
            t_issue = _dt_cls.fromisoformat(created_at.replace("Z", "+00:00"))
            t_resp = _dt_cls.fromisoformat(first_at.replace("Z", "+00:00"))
            if t_issue.tzinfo is None:
                t_issue = t_issue.replace(tzinfo=_tz.utc)
            if t_resp.tzinfo is None:
                t_resp = t_resp.replace(tzinfo=_tz.utc)
            delta = (t_resp - t_issue).total_seconds() / 3600.0
        except Exception:
            continue
        if delta < 0:
            continue
        out.append(delta)
        if len(out) >= max_issues:
            break
    return out


# ----- Aggregate deep fetchers --------------------------------------------
#
# ``fetch_deep_facts`` is the single round-tripped fetcher for the entire
# deep battery: the security assessor's checks AND the quality assessor's
# checks, fetched at most once per (client, owner, repo, facts, now).
#
# ``fetch_security_facts`` and ``fetch_quality_facts`` are thin wrappers
# around it — kept exported because tests monkeypatch them at the cli
# level. Memoisation is internal to ``fetch_deep_facts``: the two
# wrappers, called back-to-back by ``cli._run_deep``, hand back the same
# cached instance, so only ONE round of network calls happens per repo
# (down from two before the merge).
#
# Memoisation key is ``(id(client), owner, repo, id(facts) or 0, now)``:
# every worker in a parallel run has its own ``GitHubClient`` instance
# (so id collisions across workers cannot happen), every ``RepoFacts``
# is the unique output of ``fetch_all`` for one repo, and ``now`` is a
# single UTC datetime captured once per ``run()`` invocation. The cache
# lives only for the duration of one CLI run — never across runs.
_DEEP_FACTS_CACHE: dict = {}


def fetch_deep_facts(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    facts: RepoFacts | None = None,
    now: datetime | None = None,
) -> DeepFacts:
    """Fetch everything the security AND quality assessors need — once.

    Performs the **union** of the call sequences the two previous
    fetchers ran, with no duplicates: ``/repos/{owner}/{repo}`` (only if
    no ``facts`` was supplied), ``/releases``, ``/git/trees``, ``/contributors``,
    ``/stats/commit_activity``, ``/branches/{branch}/protection``,
    ``/contents/.github/workflows`` (listing + each file), manifest
    ``/contents/`` reads, dependabot / renovate / SECURITY.md /
    CHANGELOG.md / ``/tags`` / ``/commits`` / ``/git/ref/heads/{branch}``
    / ``/commits/{sha}/check-runs`` / ``/issues`` (+ ``/issues/{n}/comments``
    per issue), and the README-length derivation from the existing facts.

    Order is the union of the two previous sequences, with the
    quality-battery's ``head_sha`` / ``check-runs`` fetch (which the
    security sequence did not include) preserved.

    Args:
        client: A :class:`GitHubClient` (one connection per worker).
        owner: GitHub owner.
        repo: GitHub repo name.
        facts: An existing :class:`RepoFacts` from
            :func:`fetch_repo_metadata` / :func:`fetch_all`. If supplied,
            we skip re-fetching ``/repos/{owner}/{repo}`` to avoid
            burning rate-limit on the default branch. Optional.
        now: UTC timestamp to record as ``fetched_at``. Defaults to
            ``datetime.now(timezone.utc)`` here. In a normal run ``cli``
            captures the clock once and passes it down, so every module below
            it stays a pure function of the timestamp it is handed.

    Returns:
        A :class:`DeepFacts` instance (the security and quality
        assessors' input). Every field is populated to the best of the
        fetcher's ability; a field that remains ``None`` / empty means
        the data was not obtainable, which the pure assessors map to
        ``unchecked`` — never to ``pass``.

    Notes:
        Memoised: a second call with the same args returns the cached
        instance. ``fetch_security_facts`` and ``fetch_quality_facts``
        rely on this to avoid doubling the network traffic when both
        are called for one repo.
    """
    cache_key = (
        id(client),
        owner,
        repo,
        id(facts) if facts is not None else 0,
        now,
    )
    cached = _DEEP_FACTS_CACHE.get(cache_key)
    if cached is not None:
        return cached

    deep = DeepFacts(
        owner=owner, repo=repo,
        fetched_at=now or datetime.now(timezone.utc),
    )
    try:
        # Default branch — reuse the existing facts if provided.
        if facts is not None and isinstance(getattr(facts, "default_branch", None), str):
            deep.default_branch = facts.default_branch
        else:
            deep.default_branch = _default_branch_of(client, owner, repo)

        # --- security-specific fetches ---------------------------------

        # SECURITY.md presence.
        deep.has_security_policy = _fetch_security_policy(client, owner, repo)

        # Branch protection on the default branch.
        if deep.default_branch:
            deep.branch_protection = _fetch_branch_protection(
                client, owner, repo, deep.default_branch
            )

        # 52-week commit activity.
        deep.commit_activity_weeks = _fetch_commit_activity(client, owner, repo)

        # Dependabot / renovate presence.
        deep.has_dependabot_config, deep.has_renovate_config = (
            _fetch_dependency_update_configs(client, owner, repo)
        )

        # --- shared fetches (same data, same semantics) ----------------

        # Recent releases.
        deep.releases = _fetch_releases(client, owner, repo)

        # Repo tree (top 2 levels).
        deep.tree_entries = _fetch_tree_top_levels(
            client, owner, repo, deep.default_branch
        )

        # Workflow files (paths + contents).
        deep.workflow_paths = _list_workflow_paths(client, owner, repo)
        deep.workflow_files = _fetch_workflow_contents(
            client, owner, repo, deep.workflow_paths,
        )

        # Contributors. Always fetched: the quality assessor's
        # ``_check_contributor_concentration`` falls back to the
        # ``/contributors`` aggregate only when ``recent_commits`` is
        # empty, so a populated ``contributors`` is harmless when
        # ``recent_commits`` is also populated, and necessary when it
        # isn't. The security assessor's ``_check_contributors``
        # always needs this.
        deep.contributors = _fetch_contributors(client, owner, repo)

        # Manifest files (capped by tree depth).
        deep.manifests = _fetch_manifest_contents(
            client, owner, repo, deep.tree_entries,
        )

        # --- quality-specific fetches ---------------------------------

        # Tags.
        deep.tags = _fetch_tags(client, owner, repo)

        # CHANGELOG.md presence.
        deep.has_changelog = _fetch_changelog_presence(client, owner, repo)

        # Recent commits on the default branch.
        deep.recent_commits = _fetch_recent_commits(client, owner, repo)

        # Issue responsiveness — bounded.
        deep.issue_response_hours = _fetch_issue_response_hours(
            client, owner, repo,
        )

        # README length (reuse from facts if available — already paid
        # for by the fast path).
        if facts is not None and isinstance(getattr(facts, "readme_text", None), str):
            deep.readme_length = len(facts.readme_text)

        # Check-runs: needs the HEAD SHA on the default branch.
        deep.head_sha = _fetch_head_sha(client, owner, repo, deep.default_branch)
        if deep.head_sha:
            deep.latest_check_conclusion = _fetch_check_runs(
                client, owner, repo, deep.head_sha,
            )
    except RateLimitError as e:
        deep.error = f"rate limited; reset={e.reset}"
    except HTTPStatusError as e:
        deep.error = f"http {e.status}"
    except Exception as e:
        deep.error = f"deep fetch failed: {e}"

    _DEEP_FACTS_CACHE[cache_key] = deep
    return deep


def fetch_security_facts(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    facts: RepoFacts | None = None,
    now: datetime | None = None,
) -> SecurityFacts:
    """Thin wrapper around :func:`fetch_deep_facts`.

    Kept exported because the test suite (and any external caller)
    references it. Internally delegates to :func:`fetch_deep_facts`,
    which is memoised, so calling this AND
    :func:`fetch_quality_facts` for the same ``(client, owner, repo,
    facts, now)`` still triggers only one round of API calls.
    """
    return fetch_deep_facts(client, owner, repo, facts=facts, now=now)


def fetch_quality_facts(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    facts: RepoFacts | None = None,
    now: datetime | None = None,
) -> QualityFacts:
    """Thin wrapper around :func:`fetch_deep_facts`.

    Kept exported because the test suite (and any external caller)
    references it. See :func:`fetch_security_facts` for the memoisation
    contract that prevents doubling the network traffic.
    """
    return fetch_deep_facts(client, owner, repo, facts=facts, now=now)

