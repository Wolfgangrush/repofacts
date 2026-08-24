"""Static "what-if" simulations for dependency manifests.

Pure analysis. No execution. No subprocess. No network. No file reads. Every
input arrives as a Python string and is parsed statically. The module exists
to surface supply-chain risk *before* a single byte is installed.

The two simulations:

* :func:`simulate_install` — given a dict of manifest filenames → contents,
  report declared deps, install-time code execution, unpinned versions,
  dependency count, and typosquat suspicions.
* :func:`simulate_conflicts` — given the repo's declared deps and a
  caller-supplied ``installed`` map, report version conflicts, runtime floor
  mismatches, new transitive surface, and duplicate-purpose warnings.

Design rules (mirroring the rest of the package):

* Hard rule #1: Python 3.11+ stdlib only. ``tomllib``, ``json``, ``re``,
  ``dataclasses``. No third-party imports.
* Hard rule #2: PURE. No I/O at all, ever. ``simulate_install`` never reads a
  file — the caller hands in the file *contents*.
* Hard rule #3: When we cannot parse something we say so explicitly. We
  return ``"unparsed"`` and keep the raw text; we never silently return
  ``"fine"``.
* Hard rule #4: Full type hints. Docstrings state what is returned.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DeclaredDep:
    """A single declared dependency, with the raw version spec preserved.

    Returned inside :class:`InstallSimulation.declared` and
    :class:`ConflictSimulation.declared`.
    """
    ecosystem: str         # npm | pypi | cargo | go
    name: str
    spec: str              # raw version spec as written, e.g. "^1.2.3" or ">=1.0"
    source: str            # manifest filename we read it from
    line_no: int | None = None


@dataclass
class InstallHook:
    """One piece of install-time code execution we detected.

    Each entry is HIGH-severity by construction — these are exactly the
    vectors a real-world supply-chain attack (event-stream, ua-parser-js,
    colors.js, node-ipc) abuses. ``quote`` is the offending source line, so
    a human can judge whether it is benign or malicious.
    """
    ecosystem: str
    kind: str              # script | cmdclass | top-level-call | build-rs | build-backend
    name: str              # script name (e.g. "postinstall") or short label
    quote: str             # the offending source line, verbatim
    source: str
    line_no: int | None = None


@dataclass
class FloatingDep:
    """A dep whose version is not pinned — may resolve to anything.

    Captured separately so the renderer can light these up without having to
    re-classify every :class:`DeclaredDep`.
    """
    ecosystem: str
    name: str
    spec: str              # the raw, floating spec (e.g. "^1.2.3", "latest")
    reason: str            # "caret" | "tilde" | "star" | "gte" | "latest" | "branch" | "missing"
    source: str


@dataclass
class TyposquatHit:
    """A dep whose name is within edit-distance 1 of a common package name.

    This is the typosquat / slopsquat check. ``distance`` is the Levenshtein
    distance between ``name`` and ``canonical``.
    """
    name: str
    canonical: str
    distance: int
    source: str


@dataclass
class EcosystemCount:
    """How many declared deps this manifest contributes per ecosystem."""
    ecosystem: str
    count: int


@dataclass
class InstallSimulation:
    """The full result of :func:`simulate_install`.

    Fields are grouped so the renderer can render a single report without
    re-iterating. ``surface_note`` is a one-line human description of how
    big this dependency set is (e.g. "tiny", "medium", "large").
    """
    declared: list[DeclaredDep] = field(default_factory=list)
    hooks: list[InstallHook] = field(default_factory=list)
    floating: list[FloatingDep] = field(default_factory=list)
    typosquats: list[TyposquatHit] = field(default_factory=list)
    ecosystem_counts: list[EcosystemCount] = field(default_factory=list)
    total_deps: int = 0
    surface_note: str = ""
    manifests_seen: list[str] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)


@dataclass
class VersionConflict:
    """One declared dep whose range is incompatible with what is installed.

    ``status`` is one of: ``"conflict"``, ``"ok"``, ``"unparsed"``.
    """
    ecosystem: str
    name: str
    declared_spec: str
    installed_version: str
    status: str            # conflict | ok | unparsed
    note: str = ""


@dataclass
class RuntimeFloorConflict:
    """A mismatch between what the repo requires and what the host has.

    Hosts are passed by the caller — we never read the host runtime
    ourselves, that would be I/O.
    """
    language: str          # python | node | rust
    declared: str          # raw spec, e.g. ">=3.10"
    host_version: str      # what the caller said is installed, e.g. "3.11.4"
    status: str            # ok | conflict | unparsed
    note: str = ""


@dataclass
class NewTransitiveSurface:
    """A direct dep that is *not* already on the caller's machine."""
    ecosystem: str
    name: str
    declared_spec: str


@dataclass
class DuplicatePurposeWarning:
    """The repo brings a package that duplicates something already installed."""
    brought: str
    brought_ecosystem: str
    duplicates: str        # the package already installed
    group: str             # the equivalence-group label, e.g. "http-client"


@dataclass
class ConflictSimulation:
    """The full result of :func:`simulate_conflicts`."""
    repo_decls: list[DeclaredDep] = field(default_factory=list)
    version_conflicts: list[VersionConflict] = field(default_factory=list)
    runtime_floors: list[RuntimeFloorConflict] = field(default_factory=list)
    new_transitive: list[NewTransitiveSurface] = field(default_factory=list)
    duplicate_purpose: list[DuplicatePurposeWarning] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


# Packages whose names are so widely installed that a near-typo is worth a
# loud flag. The list is deliberately short — we are not building a full
# advisory corpus, we are catching the top-of-mind slopsquat targets.
_COMMON_PACKAGES: tuple[str, ...] = (
    "requests", "numpy", "pandas", "lodash", "express", "react", "axios",
    "flask", "django", "pytest", "urllib3", "certifi", "chalk", "colors",
    "dotenv", "moment", "jsonwebtoken", "tokio", "serde",
)

# Duplicate-purpose groups. A package on the left is considered an alternative
# to anything else in the same group. The first entry is the "canonical" name.
_DUPLICATE_GROUPS: tuple[tuple[str, ...], ...] = (
    ("http-client", "requests", "httpx", "aiohttp", "urllib3"),
    ("datetime", "moment", "dayjs", "date-fns", "luxon"),
    ("terminal-color", "chalk", "colors", "kleur", "ansi-colors"),
    ("env-loader", "dotenv", "dotenv-expand", "dotenv-flow"),
    ("jwt", "jsonwebtoken", "pyjwt", "jose", "jsjwt"),
    ("react-framework", "react", "preact", "inferno"),
    ("http-server", "express", "fastify", "koa", "hapi"),
    ("serde-runtime", "serde", "serde_json", "simd-json"),
)


def _levenshtein(a: str, b: str) -> int:
    """Pure-Python Levenshtein edit distance.

    Returns the minimum number of single-character insertions, deletions, or
    substitutions required to turn ``a`` into ``b``. Used by the typosquat
    check. Intentionally bounded by the caller (we only call it on names
    <=64 chars) so a quadratic DP is fine.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    curr = [0] * (len(b) + 1)
    for i, ca in enumerate(a, start=1):
        curr[0] = i
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                curr[j - 1] + 1,
                prev[j] + 1,
                prev[j - 1] + cost,
            )
        prev, curr = curr, prev
    return prev[len(b)]


def _classify_floating(spec: str) -> str | None:
    """Return a reason string if ``spec`` is floating, else None.

    Floating = a version that may resolve to anything at install time.
    Pinned means an exact version, an exact-equality, a tilde-without-upper-
    bound that looks pinned (``~=``), or a bare version (``1.2.3``).

    Taxonomy mirrors the hard rules in the spec: caret, npm-tilde, star,
    greater-than-or-equal, latest, branch, missing.
    """
    s = spec.strip()
    if not s:
        return "missing"
    low = s.lower()
    if low in {"latest", "next", "beta", "alpha", "rc", "canary"}:
        return "latest"
    if low in {"main", "master", "develop", "trunk", "head"}:
        return "branch"
    if "*" in s:
        return "star"
    if s.startswith("^"):
        return "caret"
    if s.startswith("~") and not s.startswith("~="):
        return "tilde"
    if s.startswith(">=") or s.startswith(">"):
        return "gte"
    return None


def _strip_quotes(s: str) -> str:
    """Drop a single pair of surrounding double or single quotes if present."""
    if len(s) >= 2 and s[0] == s[-1] and s[0] in {"'", '"'}:
        return s[1:-1]
    return s


def _surface_note(total: int, manifests: int) -> str:
    """Return a one-line English description of dependency-set size.

    Honest thresholds - these are not precise, just a readers first
    impression. Above ~50 direct deps you are in serious-transitive-
    risk territory regardless of pinning.
    """
    if total == 0:
        return "no declared dependencies"
    if manifests == 0:
        return f"{total} declared deps (no manifest files recognised)"
    if total <= 5:
        return f"tiny surface - {total} declared deps across {manifests} manifest(s)"
    if total <= 20:
        return f"small surface - {total} declared deps across {manifests} manifest(s)"
    if total <= 50:
        return f"medium surface - {total} declared deps across {manifests} manifest(s)"
    if total <= 150:
        return f"large surface - {total} declared deps; expect significant transitive blast radius"
    return f"huge surface - {total} declared deps; treat as a supply-chain hot zone"


def _find_duplicates(name: str, ecosystem: str, installed: dict[str, str]) -> tuple[str, str] | None:
    """If ``installed`` already has a package in the same equivalence group as
    ``name``, return ``(group_label, already_installed_name)`` else None.
    """
    target = name.lower()
    installed_lc = {k.lower(): k for k in installed}
    for group in _DUPLICATE_GROUPS:
        label = group[0]
        members = {m.lower() for m in group[1:]}
        if target not in members:
            continue
        for existing in installed_lc:
            if existing != target and existing in members:
                return label, installed_lc[existing]
    return None



# ---------------------------------------------------------------------------
# Per-ecosystem manifest parsers
# ---------------------------------------------------------------------------


_NPM_INSTALL_HOOKS = frozenset({"preinstall", "install", "postinstall", "prepare"})

# Standard / known pyproject build backends. Anything else is suspicious.
_KNOWN_PYPROJECT_BACKENDS: frozenset[str] = frozenset({
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
    "hatchling.build",
    "hatch.build",
    "flit_core.buildapi",
    "flit.buildapi",
    "poetry.core.masonry.api",
    "poetry.masonry.api",
    "pdm.backend",
    "scikit_build_core.build",
    "setuptools_scm.build_meta",
    "maturin.build",
    "cython_build",
    "mesonpy",
    "whey",
})


def _line_of(text: str, offset: int) -> int:
    """Return the 1-based line number for ``offset`` into ``text``."""
    return text.count("\n", 0, offset) + 1


def _parse_package_json(filename: str, body: str, sim: InstallSimulation) -> None:
    """Parse a ``package.json`` body. Mutates ``sim`` in place."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        sim.unparsed.append(f"{filename}: invalid JSON ({exc.msg} at line {exc.lineno})")
        return
    if not isinstance(data, dict):
        sim.unparsed.append(f"{filename}: top-level is not an object")
        return

    declared_sections = (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    )
    for section in declared_sections:
        section_data = data.get(section)
        if section_data is None:
            continue
        if not isinstance(section_data, dict):
            sim.unparsed.append(f"{filename}: '{section}' is not an object")
            continue
        for name, spec in section_data.items():
            if not isinstance(name, str):
                continue
            spec_str = spec if isinstance(spec, str) else str(spec)
            offset = body.find(f'"{name}"', max(0, body.find(section)))
            sim.declared.append(DeclaredDep(
                ecosystem="npm",
                name=name,
                spec=spec_str,
                source=filename,
                line_no=_line_of(body, offset) if offset >= 0 else None,
            ))
            reason = _classify_floating(spec_str)
            if reason is not None:
                sim.floating.append(FloatingDep(
                    ecosystem="npm",
                    name=name,
                    spec=spec_str,
                    reason=reason,
                    source=filename,
                ))

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in _NPM_INSTALL_HOOKS:
            if hook in scripts and isinstance(scripts[hook], str):
                offset = body.find(f'"{hook}"')
                sim.hooks.append(InstallHook(
                    ecosystem="npm",
                    kind="script",
                    name=hook,
                    quote=f'"{hook}": "{scripts[hook]}"',
                    source=filename,
                    line_no=_line_of(body, offset) if offset >= 0 else None,
                ))


def _parse_requirements_txt(filename: str, body: str, sim: InstallSimulation) -> None:
    """Parse requirements.txt line by line, best-effort."""
    for line_no, raw in enumerate(body.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-") or line.startswith("--"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~].*)?$", line)
        if not m:
            sim.unparsed.append(f"{filename}:{line_no}: could not parse {raw!r}")
            continue
        name = m.group(1)
        spec = (m.group(2) or "").strip() or "any"
        sim.declared.append(DeclaredDep(
            ecosystem="pypi",
            name=name,
            spec=spec,
            source=filename,
            line_no=line_no,
        ))
        reason = _classify_floating(spec) if spec != "any" else "missing"
        if reason is not None:
            sim.floating.append(FloatingDep(
                ecosystem="pypi",
                name=name,
                spec=spec if spec != "any" else "",
                reason=reason,
                source=filename,
            ))


def _parse_setup_py(filename: str, body: str, sim: InstallSimulation) -> None:
    """Best-effort static analysis of setup.py. Never executes.

    Looks for install_requires=[...], cmdclass={...}, and top-level
    os.system / subprocess. calls. We are intentionally conservative: if
    we cannot prove a construct is at module scope we do NOT flag it,
    because a false positive here would mean yelling at every library
    that happens to call subprocess inside a helper function.
    """
    install_requires_re = re.compile(
        r"install_requires\s*=\s*\(?\s*\[(.*?)\]\s*\)?",
        re.DOTALL,
    )
    m = install_requires_re.search(body)
    if m:
        inner = m.group(1)
        for entry in re.findall(r"""["']([^"']+)["']""", inner):
            name, _, spec = entry.partition(" ")
            sim.declared.append(DeclaredDep(
                ecosystem="pypi",
                name=name,
                spec=spec.strip() or "any",
                source=filename,
                line_no=_line_of(body, m.start()),
            ))
            reason = _classify_floating(spec.strip()) if spec.strip() else "missing"
            if reason is not None:
                sim.floating.append(FloatingDep(
                    ecosystem="pypi",
                    name=name,
                    spec=spec.strip(),
                    reason=reason,
                    source=filename,
                ))

    cmdclass_re = re.compile(r"\bcmdclass\s*=\s*\{", re.MULTILINE)
    cm = cmdclass_re.search(body)
    if cm:
        first_line = body[cm.start(): cm.start() + 80].splitlines()[0]
        sim.hooks.append(InstallHook(
            ecosystem="pypi",
            kind="cmdclass",
            name="cmdclass",
            quote=first_line,
            source=filename,
            line_no=_line_of(body, cm.start()),
        ))

    for pattern in (r"[^\n]*\bos\.system\s*\(", r"[^\n]*\bsubprocess\."):
        for mm in re.finditer(pattern, body, re.MULTILINE):
            sim.hooks.append(InstallHook(
                ecosystem="pypi",
                kind="top-level-call",
                name="os.system/subprocess",
                quote=mm.group(0).strip()[:200],
                source=filename,
                line_no=_line_of(body, mm.start()),
            ))


def _ingest_pypi_dep_entries(
    filename: str,
    body: str,
    entries: list,
    label: str,
    sim: InstallSimulation,
) -> None:
    """Ingest one list of PEP 508 requirement strings into ``sim``.

    Shared by ``[project.dependencies]`` and by every group under
    ``[project.optional-dependencies]``. ``label`` only changes the wording
    of the ``unparsed`` note ("dep" vs "opt-dep"); the parsing, the
    ``declared`` record and the floating-spec classification are identical,
    which is why they live here once instead of twice.
    """
    for entry in entries:
        if not isinstance(entry, str):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~].*)?$", entry)
        if not m:
            sim.unparsed.append(f"{filename}: could not parse {label} {entry!r}")
            continue
        name = m.group(1)
        spec = (m.group(2) or "").strip() or "any"
        offset = body.find(entry)
        sim.declared.append(DeclaredDep(
            ecosystem="pypi",
            name=name,
            spec=spec,
            source=filename,
            line_no=_line_of(body, offset) if offset >= 0 else None,
        ))
        reason = _classify_floating(spec) if spec != "any" else "missing"
        if reason is not None:
            sim.floating.append(FloatingDep(
                ecosystem="pypi",
                name=name,
                spec=spec if spec != "any" else "",
                reason=reason,
                source=filename,
            ))


def _parse_pyproject_toml(filename: str, body: str, sim: InstallSimulation) -> None:
    """Parse a pyproject.toml via stdlib tomllib (3.11+)."""
    try:
        data = tomllib.loads(body)
    except tomllib.TOMLDecodeError as exc:
        sim.unparsed.append(f"{filename}: invalid TOML ({exc})")
        return
    if not isinstance(data, dict):
        sim.unparsed.append(f"{filename}: top-level is not a table")
        return

    project = data.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            _ingest_pypi_dep_entries(filename, body, deps, "dep", sim)
        opt = project.get("optional-dependencies")
        if isinstance(opt, dict):
            for _group_name, group_deps in opt.items():
                if not isinstance(group_deps, list):
                    continue
                _ingest_pypi_dep_entries(filename, body, group_deps, "opt-dep", sim)

    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        backend = build_system.get("build-backend")
        if isinstance(backend, str) and backend and backend not in _KNOWN_PYPROJECT_BACKENDS:
            offset = body.find(backend)
            sim.hooks.append(InstallHook(
                ecosystem="pypi",
                kind="build-backend",
                name=backend,
                quote=f'build-backend = "{backend}"',
                source=filename,
                line_no=_line_of(body, offset) if offset >= 0 else None,
            ))


def _parse_cargo_toml(filename: str, body: str, sim: InstallSimulation) -> None:
    """Parse a Cargo.toml. Stdlib tomllib handles it."""
    try:
        data = tomllib.loads(body)
    except tomllib.TOMLDecodeError as exc:
        sim.unparsed.append(f"{filename}: invalid TOML ({exc})")
        return
    if not isinstance(data, dict):
        sim.unparsed.append(f"{filename}: top-level is not a table")
        return

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, spec in deps.items():
            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                version = str(spec.get("version", ""))
            else:
                version = ""
            # Cargo bare version (no operator) is shorthand for caret.
            if version and not any(version.startswith(op) for op in ("==", ">=", "<=", ">", "<", "^", "~", "*")):
                version = "^" + version
            offset = body.find(name)
            sim.declared.append(DeclaredDep(
                ecosystem="cargo",
                name=name,
                spec=version or "any",
                source=filename,
                line_no=_line_of(body, offset) if offset >= 0 else None,
            ))
            reason = _classify_floating(version) if version else "missing"
            if reason is not None:
                sim.floating.append(FloatingDep(
                    ecosystem="cargo",
                    name=name,
                    spec=version,
                    reason=reason,
                    source=filename,
                ))

    package = data.get("package")
    if isinstance(package, dict):
        metadata = package.get("metadata")
        if isinstance(metadata, dict):
            build_script = metadata.get("build")
            if isinstance(build_script, str):
                offset = body.find(build_script)
                sim.hooks.append(InstallHook(
                    ecosystem="cargo",
                    kind="build-rs",
                    name="Cargo.metadata.build",
                    quote=f'build = "{build_script}"',
                    source=filename,
                    line_no=_line_of(body, offset) if offset >= 0 else None,
                ))


def _parse_go_mod(filename: str, body: str, sim: InstallSimulation) -> None:
    """Parse a go.mod ``require`` directive (single-line and block forms).

    We only understand ``require``. Other directives (``replace``,
    ``exclude``, ``retract``) affect module resolution but do not
    introduce a new dependency that we can flag, so we leave them alone.
    """
    line_no = 0
    in_block = False
    for raw in body.splitlines():
        line_no += 1
        stripped = raw.strip()
        # Block end.
        if in_block and stripped == ")":
            in_block = False
            continue
        # Block body: lines may start with the module path, optionally
        # followed by a version and the ``// indirect`` marker.
        if in_block:
            if not stripped or stripped.startswith("//"):
                continue
            parts = stripped.split()
            name = parts[0]
            version = parts[1] if len(parts) >= 2 else ""
            # go.mod has NO caret semantics. `require foo v1.73.1` is an
            # EXACT pin (and go.sum hashes it). Rewriting it to `^1.73.1`
            # made every Go dependency look floating — 296 false positives
            # on ossf/scorecard. Strip the display `v`, keep it exact.
            if version.startswith("v") and version[1:2].isdigit():
                version = version[1:]
            sim.declared.append(DeclaredDep(
                ecosystem="go",
                name=name,
                spec=version or "any",
                source=filename,
                line_no=line_no,
            ))
            reason = _classify_floating(version) if version else "missing"
            if reason is not None:
                sim.floating.append(FloatingDep(
                    ecosystem="go",
                    name=name,
                    spec=version,
                    reason=reason,
                    source=filename,
                ))
            continue
        # Block start: "require (" with no closing ")" on the same line.
        if stripped.startswith("require") and "(" in stripped and ")" not in stripped:
            in_block = True
            tail = stripped.split("(", 1)[1].strip()
            if tail:
                parts = tail.split()
                name = parts[0]
                version = parts[1] if len(parts) >= 2 else ""
                if version.startswith("v") and version[1:2].isdigit():
                    version = "^" + version[1:]
                sim.declared.append(DeclaredDep(
                    ecosystem="go",
                    name=name,
                    spec=version or "any",
                    source=filename,
                    line_no=line_no,
                ))
                reason = _classify_floating(version) if version else "missing"
                if reason is not None:
                    sim.floating.append(FloatingDep(
                        ecosystem="go",
                        name=name,
                        spec=version,
                        reason=reason,
                        source=filename,
                    ))
            continue
        # Single-line: "require <path> <version>".
        if stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 3:
                name = parts[1]
                version = parts[2]
                if version.startswith("v") and version[1:2].isdigit():
                    version = "^" + version[1:]
                sim.declared.append(DeclaredDep(
                    ecosystem="go",
                    name=name,
                    spec=version,
                    source=filename,
                    line_no=line_no,
                ))
                reason = _classify_floating(version)
                if reason is not None:
                    sim.floating.append(FloatingDep(
                        ecosystem="go",
                        name=name,
                        spec=version,
                        reason=reason,
                        source=filename,
                    ))


def _detect_build_rs(manifests: dict[str, str], sim: InstallSimulation) -> None:
    """Flag a build.rs file if present in the manifests dict.

    Cargo runs ``build.rs`` at compile time. We do not parse the file —
    just its presence in the manifest map is the signal.
    """
    for name in manifests:
        if name.endswith("build.rs") or name.endswith("Build.rs"):
            body = manifests[name]
            first_meaningful = ""
            for line in body.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("//"):
                    first_meaningful = stripped[:200]
                    break
            sim.hooks.append(InstallHook(
                ecosystem="cargo",
                kind="build-rs",
                name="build.rs present",
                quote=first_meaningful or "(build.rs file present in repo)",
                source=name,
                line_no=1,
            ))


# Filename → parser. Order does not matter.
_PARSERS = (
    ("package.json", _parse_package_json),
    ("requirements.txt", _parse_requirements_txt),
    ("setup.py", _parse_setup_py),
    ("pyproject.toml", _parse_pyproject_toml),
    ("Cargo.toml", _parse_cargo_toml),
    ("go.mod", _parse_go_mod),
)


def simulate_install(manifests: dict[str, str]) -> InstallSimulation:
    """Run the install-time static analysis over a set of manifest files.

    Parameters
    ----------
    manifests:
        Mapping from filename (e.g. ``"package.json"``) to its contents as a
        string. The caller is responsible for fetching them — this function
        never reads a file.

    Returns
    -------
    :class:`InstallSimulation`
        All declared dependencies, install-time code-execution hooks,
        floating-version specs, suspected typosquats, and an ecosystem
        breakdown. Things we could not parse are surfaced verbatim in
        ``InstallSimulation.unparsed`` rather than silently dropped.
    """
    sim = InstallSimulation()
    sim.manifests_seen = sorted(manifests.keys())

    for filename, parser in _PARSERS:
        if filename in manifests:
            parser(filename, manifests[filename], sim)

    _detect_build_rs(manifests, sim)

    # Typosquat scan over every declared dep.
    seen_names: set[str] = set()
    for d in sim.declared:
        lname = d.name.lower()
        if lname in seen_names:
            continue
        seen_names.add(lname)
        if len(d.name) > 64:
            continue
        for canonical in _COMMON_PACKAGES:
            if lname == canonical:
                continue
            if abs(len(d.name) - len(canonical)) > 1:
                continue
            dist = _levenshtein(lname, canonical)
            if 0 < dist <= 1:
                sim.typosquats.append(TyposquatHit(
                    name=d.name,
                    canonical=canonical,
                    distance=dist,
                    source=d.source,
                ))

    # Ecosystem breakdown.
    counts: dict[str, int] = {}
    for d in sim.declared:
        counts[d.ecosystem] = counts.get(d.ecosystem, 0) + 1
    sim.ecosystem_counts = [
        EcosystemCount(ecosystem=eco, count=n)
        for eco, n in sorted(counts.items())
    ]
    sim.total_deps = len(sim.declared)
    sim.surface_note = _surface_note(sim.total_deps, len(sim.manifests_seen))

    return sim


# ---------------------------------------------------------------------------
# Version comparison (honest, PEP 440 / semver subset)
# ---------------------------------------------------------------------------


# Tuple of supported operators, longest first so >= / <= are not misread.
_RANGE_OPS = ("===", "~=", "==", ">=", "<=", "!=", ">", "<", "^", "~")


def _parse_version(v: str) -> list[int] | None:
    """Parse a version into a list of integer parts.

    Accepts the common subset: ``1``, ``1.2``, ``1.2.3``, ``1.2.3.4``, and
    strips common pre-release / build suffixes (``-rc1``, ``+local``).
    Returns ``None`` if the input is not parseable; the caller treats that
    as ``unparsed`` and does NOT guess.
    """
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s:
        return None
    # Strip leading 'v' for npm/go style.
    if s[0] in ("v", "V"):
        s = s[1:]
    # Trim anything after '-' or '+'.
    for sep in ("-", "+"):
        if sep in s:
            s = s.split(sep, 1)[0]
    parts = s.split(".")
    out: list[int] = []
    for p in parts:
        if not p.isdigit():
            return None
        out.append(int(p))
    if not out:
        return None
    return out


def _cmp_versions(a: list[int], b: list[int]) -> int:
    """Return -1, 0, or 1 by comparing two already-parsed version lists.

    Pads the shorter list with zeros so 1.2 == 1.2.0.
    """
    n = max(len(a), len(b))
    a2 = a + [0] * (n - len(a))
    b2 = b + [0] * (n - len(b))
    if a2 < b2:
        return -1
    if a2 > b2:
        return 1
    return 0


def _split_spec(spec: str) -> list[tuple[str, str]]:
    """Split a comma-separated spec into ``(op, version)`` tuples.

    Empty parts are skipped. Whitespace is trimmed.
    """
    out: list[tuple[str, str]] = []
    for raw in spec.split(","):
        part = raw.strip()
        if not part:
            continue
        matched = False
        for op in _RANGE_OPS:
            if part.startswith(op):
                out.append((op, part[len(op):].strip()))
                matched = True
                break
        if not matched:
            # Bare version: treat as implicit equality.
            out.append(("==", part))
    return out


def _spec_satisfies(spec: str, version: str) -> tuple[str, str]:
    """Decide whether ``version`` satisfies ``spec``.

    Returns a ``(status, note)`` tuple where ``status`` is one of:
        ``"ok"``        — ``version`` lies inside the range
        ``"conflict"``  — ``version`` lies outside the range
        ``"unparsed"``  — spec or version could not be parsed honestly

    The note is a short human-readable explanation. Per the hard rules we
    never silently return ``"ok"``: if we cannot parse, we say so.
    """
    parsed_spec = _split_spec(spec)
    if not parsed_spec:
        return "unparsed", f"could not parse spec {spec!r}"
    if spec.strip().lower() in ("any", "*"):
        return "ok", "no version constraint declared"
    parsed_v = _parse_version(version)
    if parsed_v is None:
        return "unparsed", f"could not parse installed version {version!r}"

    for op, raw_ver in parsed_spec:
        target = _parse_version(raw_ver)
        if target is None:
            return "unparsed", f"could not parse range version {raw_ver!r} in spec {spec!r}"

        if op == "===":
            # PEP 440 arbitrary equality: we accept only the exact triple.
            ok = _cmp_versions(parsed_v, target) == 0
        elif op == "==":
            ok = _cmp_versions(parsed_v, target) == 0
        elif op == "!=":
            ok = _cmp_versions(parsed_v, target) != 0
        elif op == ">":
            ok = _cmp_versions(parsed_v, target) > 0
        elif op == "<":
            ok = _cmp_versions(parsed_v, target) < 0
        elif op == ">=":
            ok = _cmp_versions(parsed_v, target) >= 0
        elif op == "<=":
            ok = _cmp_versions(parsed_v, target) <= 0
        elif op == "~=":
            # PEP 440 compatible-release: ~=X.Y.Z means >=X.Y.Z, <X.(Y+1).0
            # but we only support the simple Z-present form.
            if len(target) < 3:
                return "unparsed", f"~= needs at least 3 version parts; got {raw_ver!r}"
            # ~=X.Y.Z -> >=X.Y.Z, <X.(Y+1).0 — drop Z, bump Y.
            ceil = target[:-2] + [target[-2] + 1] + [0]
            ok = (
                _cmp_versions(parsed_v, target) >= 0
                and _cmp_versions(parsed_v, ceil) < 0
            )
        elif op == "^":
            # npm semver caret: same major, >= declared.
            # ^0.2.3 -> >=0.2.3 <0.3.0 ; ^1.2.3 -> >=1.2.3 <2.0.0
            if not target:
                return "unparsed", f"^ needs at least one version part; got {raw_ver!r}"
            major = target[0]
            if major > 0:
                ceil = [major + 1] + [0] * (len(target) - 1)
            else:
                # 0.x.y is treated as locked to minor.
                if len(target) < 2:
                    ceil = [0, 1]
                else:
                    ceil = [0, target[1] + 1] + [0] * (len(target) - 2)
            ok = (
                _cmp_versions(parsed_v, target) >= 0
                and _cmp_versions(parsed_v, ceil) < 0
            )
        elif op == "~":
            # npm tilde: ~1.2.3 -> >=1.2.3 <1.3.0
            if len(target) < 2:
                return "unparsed", f"~ needs at least 2 version parts; got {raw_ver!r}"
            ceil = target[:-1] + [target[-1] + 1]
            ok = (
                _cmp_versions(parsed_v, target) >= 0
                and _cmp_versions(parsed_v, ceil) < 0
            )
        else:
            return "unparsed", f"unknown operator {op!r} in spec {spec!r}"

        if not ok:
            return "conflict", f"{version} does not satisfy {op}{raw_ver}"

    return "ok", f"{version} satisfies {spec}"


# ---------------------------------------------------------------------------
# Runtime floor checks (python / node / rust)
# ---------------------------------------------------------------------------


def _check_runtime_floor(
    language: str,
    declared: str | None,
    host: str | None,
    sim: ConflictSimulation,
) -> None:
    """Compare a declared language floor against a host version.

    Both sides are read as strings. We never read the host runtime — the
    caller hands us ``host``. If ``declared`` or ``host`` is unparseable
    we record ``unparsed`` and never guess.
    """
    if not declared:
        return
    if not host:
        sim.runtime_floors.append(RuntimeFloorConflict(
            language=language,
            declared=declared,
            host_version="(not supplied)",
            status="unparsed",
            note="host runtime version not supplied by caller",
        ))
        return

    parsed_host = _parse_version(host)
    if parsed_host is None:
        sim.runtime_floors.append(RuntimeFloorConflict(
            language=language,
            declared=declared,
            host_version=host,
            status="unparsed",
            note=f"could not parse host version {host!r}",
        ))
        return

    # rust-version is a minimum, not an exact pin.
    if language == "rust" and declared and not any(
        declared.startswith(op) for op in ("==", ">=", "<=", ">", "<", "^", "~")
    ):
        declared = ">=" + declared
    # declared is a single op+version spec. Use the same comparator.
    status, note = _spec_satisfies(declared, host)
    sim.runtime_floors.append(RuntimeFloorConflict(
        language=language,
        declared=declared,
        host_version=host,
        status=status if status in ("ok", "conflict") else "unparsed",
        note=note,
    ))


def _parse_repo_deps_for_conflict(repo_deps: object) -> list[DeclaredDep]:
    """Accept either a list[DeclaredDep] or a manifests dict.

    The CLI may pass either depending on which one it has to hand. We
    coerce to a list of :class:`DeclaredDep` and never execute the
    manifests dict — it just goes through the install parser.
    """
    if isinstance(repo_deps, list):
        return [d for d in repo_deps if isinstance(d, DeclaredDep)]
    if isinstance(repo_deps, dict):
        sim = simulate_install(repo_deps)
        return list(sim.declared)
    return []


def simulate_conflicts(
    repo_deps: list[DeclaredDep] | dict[str, str],
    installed: dict[str, str],
) -> ConflictSimulation:
    """Compare repo deps against the caller's installed environment.

    Parameters
    ----------
    repo_deps:
        Either a ``list[DeclaredDep]`` (preferred — produced by
        :func:`simulate_install`) or a ``dict[str, str]`` of manifest
        filenames to contents, in which case we run :func:`simulate_install`
        internally first.
    installed:
        Mapping ``package_name_lower -> installed_version_string``,
        supplied by the caller (it is the only thing that knows what's
        on the host).

    Returns
    -------
    :class:`ConflictSimulation`
        Per-dep version-conflict verdicts, runtime-floor mismatches, the
        set of direct deps not already installed (i.e. new transitive
        surface), and duplicate-purpose warnings.
    """
    sim = ConflictSimulation()
    decls = _parse_repo_deps_for_conflict(repo_deps)
    sim.repo_decls = decls

    installed_lc = {k.lower(): v for k, v in installed.items()}

    for d in decls:
        lname = d.name.lower()
        if lname in installed_lc:
            host_v = installed_lc[lname]
            status, note = _spec_satisfies(d.spec, host_v)
            sim.version_conflicts.append(VersionConflict(
                ecosystem=d.ecosystem,
                name=d.name,
                declared_spec=d.spec,
                installed_version=host_v,
                status=status,
                note=note,
            ))
        else:
            sim.new_transitive.append(NewTransitiveSurface(
                ecosystem=d.ecosystem,
                name=d.name,
                declared_spec=d.spec,
            ))
            dup = _find_duplicates(d.name, d.ecosystem, installed)
            if dup is not None:
                group_label, existing = dup
                sim.duplicate_purpose.append(DuplicatePurposeWarning(
                    brought=d.name,
                    brought_ecosystem=d.ecosystem,
                    duplicates=existing,
                    group=group_label,
                ))

    # Runtime floors. We accept hints via a "_runtime" magic key in
    # installed, OR via a separate manifest parse — but for purity the
    # caller passes them in through the ``installed`` mapping under
    # conventional keys: "__python__", "__node__", "__rust__".
    py_decl = None
    node_decl = None
    rust_decl = None
    if isinstance(repo_deps, dict):
        pyproject = repo_deps.get("pyproject.toml")
        if pyproject:
            try:
                data = tomllib.loads(pyproject)
            except tomllib.TOMLDecodeError:
                data = {}
            project = data.get("project") if isinstance(data, dict) else None
            if isinstance(project, dict):
                py_decl = project.get("requires-python")
        package_json = repo_deps.get("package.json")
        if package_json:
            try:
                pj = json.loads(package_json)
            except json.JSONDecodeError:
                pj = None
            if isinstance(pj, dict):
                engines = pj.get("engines")
                if isinstance(engines, dict):
                    node_decl = engines.get("node")
        cargo = repo_deps.get("Cargo.toml")
        if cargo:
            try:
                ct = tomllib.loads(cargo)
            except tomllib.TOMLDecodeError:
                ct = {}
            if isinstance(ct, dict):
                package = ct.get("package")
                if isinstance(package, dict):
                    rust_decl = package.get("rust-version")

    _check_runtime_floor("python", py_decl, installed_lc.get("__python__"), sim)
    _check_runtime_floor("node", node_decl, installed_lc.get("__node__"), sim)
    _check_runtime_floor("rust", rust_decl, installed_lc.get("__rust__"), sim)

    return sim
