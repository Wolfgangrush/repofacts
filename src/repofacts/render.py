"""Output renderers: table · summary line · --json · --markdown.

The critical guarantee here is security gate 8.2 from the test plan:
**the GitHub token never appears in any output format**. We scrub token-
shaped strings from every string field before serialisation.

None of these functions touch the network, read a clock beyond the values
passed in, or do I/O beyond writing to stdout (which is the caller's job).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Optional

from .models import Assessment, Finding, Skip


# ----- Token redaction ----------------------------------------------------

# GitHub PAT/OAuth shapes:
#   ghp_xxx, gho_xxx, ghu_xxx, ghs_xxx, ghr_xxx   (≥36 alnum chars)
# Also catch tokens that may be embedded in URLs.
_TOKEN_PATTERNS = [
    re.compile(r"gh[poushr]_[A-Za-z0-9]{36,}"),
    re.compile(r"x-access-token:[^@\s]+@"),
]

# A single sentinel substitution for all redactions.
_REDACTED = "[REDACTED]"


def _scrub(s: str | None) -> str | None:
    """Replace any token-shaped substring in ``s`` with ``[REDACTED]``.

    Returns ``None`` unchanged. Always returns a new string when ``s`` is
    non-None and contained a token-shaped substring; otherwise ``s``
    itself.
    """
    if s is None:
        return s
    out = s
    for pat in _TOKEN_PATTERNS:
        out = pat.sub(_REDACTED, out)
    return out


def _scrub_list(items: list[str] | None) -> list[str]:
    """Apply :func:`_scrub` to every entry in a list of strings."""
    if not items:
        return []
    return [(_scrub(x) or "") for x in items]


# ----- Table -------------------------------------------------------------


def _verdict_sort_key(a: Assessment) -> tuple:
    """STOP first, CAUTION next, OK last; alphabetical full-name for ties."""
    rank = {"STOP": 0, "CAUTION": 1, "OK": 2}
    return (rank.get(a.verdict, 9), a.ref.full_name.lower())


#: Status → short label for the deep tables. ``unchecked`` is preserved
#: verbatim; we never fold it into ``pass``.
_STATUS_LABEL = {
    "pass": "pass",
    "fail": "FAIL",
    "warn": "warn",
    "info": "info",
    "unchecked": "unchecked",
}


def _format_security_section(security_report: Any) -> list[str]:
    """Render the SECURITY block from a :class:`SecurityReport`-like object.

    Each finding is rendered as one row of ``name | status | severity |
    reason``. ``unchecked`` findings are always printed — never omitted,
    never shown as a pass.
    """
    lines: list[str] = ["  SECURITY:"]
    findings = getattr(security_report, "findings", None) or []
    for fnd in findings:
        if not isinstance(fnd, Finding):
            continue
        status = _STATUS_LABEL.get(fnd.status, fnd.status)
        severity = fnd.severity or ""
        reason = _scrub(fnd.reason) or ""
        lines.append(
            f"    - {fnd.name}  [{status}]  {severity}  {reason}".rstrip()
        )
    if len(findings) == 0:
        lines.append("    (no security findings — fetch did not return a report)")
    return lines


def _format_quality_section(quality_report: Any) -> list[str]:
    """Render the QUALITY block from a :class:`QualityReport`-like object."""
    lines: list[str] = ["  QUALITY:"]
    findings = getattr(quality_report, "findings", None) or []
    for fnd in findings:
        if not isinstance(fnd, Finding):
            continue
        status = _STATUS_LABEL.get(fnd.status, fnd.status)
        reason = _scrub(fnd.reason) or ""
        lines.append(
            f"    - {fnd.name}  [{status}]  {reason}".rstrip()
        )
    if len(findings) == 0:
        lines.append("    (no quality findings — fetch did not return a report)")
    return lines


def _format_install_section(install_sim: Any) -> list[str]:
    """Render the INSTALL SIMULATION block from an :class:`InstallSimulation`.

    Surfaces declared dependency count, install-time code-execution
    findings (with the offending source line quoted), unpinned versions,
    and typosquat-proximity hits.
    """
    lines: list[str] = ["  INSTALL SIMULATION:"]
    total = getattr(install_sim, "total_deps", 0) or 0
    surface = _scrub(getattr(install_sim, "surface_note", "") or "") or ""
    lines.append(f"    - declared dependency count: {total}")
    if surface:
        lines.append(f"    - surface: {surface}")

    hooks = list(getattr(install_sim, "hooks", None) or [])
    if hooks:
        lines.append(f"    - install-time execution findings ({len(hooks)}):")
        for h in hooks:
            quote = _scrub(getattr(h, "quote", "") or "") or ""
            source = _scrub(getattr(h, "source", "") or "") or ""
            kind = getattr(h, "kind", "") or ""
            name = getattr(h, "name", "") or ""
            line_no = getattr(h, "line_no", None)
            loc = f"{source}:{line_no}" if source and line_no else (source or "—")
            lines.append(
                f"      * [{kind}/{name}] {loc}: \"{quote}\""
            )
    else:
        lines.append("    - install-time execution findings: 0")

    floating = list(getattr(install_sim, "floating", None) or [])
    if floating:
        sample = ", ".join(
            f"{_scrub(f.name) or ''}@{_scrub(f.spec) or ''}({f.reason})"
            for f in floating[:5]
        )
        more = "" if len(floating) <= 5 else f" (+{len(floating) - 5} more)"
        lines.append(f"    - unpinned versions: {len(floating)}  e.g. {sample}{more}")
    else:
        lines.append("    - unpinned versions: 0")

    typosquats = list(getattr(install_sim, "typosquats", None) or [])
    if typosquats:
        sample = ", ".join(
            f"{_scrub(t.name) or ''}~{_scrub(t.canonical) or ''}"
            f"(d={t.distance})"
            for t in typosquats[:5]
        )
        more = "" if len(typosquats) <= 5 else f" (+{len(typosquats) - 5} more)"
        lines.append(f"    - typosquat-proximity hits: {len(typosquats)}  {sample}{more}")
    else:
        lines.append("    - typosquat-proximity hits: 0")

    unparsed = list(getattr(install_sim, "unparsed", None) or [])
    if unparsed:
        sample = "; ".join(_scrub(u) or "" for u in unparsed[:3])
        more = "" if len(unparsed) <= 3 else f" (+{len(unparsed) - 3} more)"
        lines.append(f"    - unparsed manifest fragments: {len(unparsed)}  {sample}{more}")

    return lines


def _format_conflict_section(conflict_sim: Any) -> list[str]:
    """Render the CONFLICTS block from a :class:`ConflictSimulation`."""
    lines: list[str] = ["  CONFLICTS:"]
    version_conflicts = list(getattr(conflict_sim, "version_conflicts", None) or [])
    if version_conflicts:
        lines.append(
            f"    - version conflicts against installed packages ({len(version_conflicts)}):"
        )
        for vc in version_conflicts[:5]:
            note = _scrub(getattr(vc, "note", "") or "") or ""
            lines.append(
                f"      * {_scrub(vc.name) or ''} {vc.status}: declared "
                f"{_scrub(vc.declared_spec) or ''} vs installed "
                f"{_scrub(vc.installed_version) or ''}  {note}".rstrip()
            )
        if len(version_conflicts) > 5:
            lines.append(f"      (+{len(version_conflicts) - 5} more)")
    else:
        lines.append("    - version conflicts against installed packages: 0")

    new_transitive = list(getattr(conflict_sim, "new_transitive", None) or [])
    if new_transitive:
        sample = ", ".join(
            f"{_scrub(t.name) or ''}@{_scrub(t.declared_spec) or ''}"
            for t in new_transitive[:5]
        )
        more = "" if len(new_transitive) <= 5 else f" (+{len(new_transitive) - 5} more)"
        lines.append(f"    - new surface added ({len(new_transitive)}): {sample}{more}")
    else:
        lines.append("    - new surface added: 0")

    runtime_floors = list(getattr(conflict_sim, "runtime_floors", None) or [])
    if runtime_floors:
        for rf in runtime_floors[:3]:
            note = _scrub(getattr(rf, "note", "") or "") or ""
            lines.append(
                f"    - runtime floor: {rf.language} declared="
                f"{_scrub(rf.declared) or ''} host="
                f"{_scrub(rf.host_version) or ''} [{rf.status}] {note}".rstrip()
            )

    duplicates = list(getattr(conflict_sim, "duplicate_purpose", None) or [])
    if duplicates:
        lines.append(
            f"    - duplicate-purpose warnings: {len(duplicates)} "
            f"(e.g. {_scrub(duplicates[0].brought) or ''} duplicates "
            f"{_scrub(duplicates[0].duplicates) or ''})"
        )

    return lines


def _format_deep_block(
    assessment: Assessment, deep: Any
) -> list[str]:
    """Render one repo's full deep block under its table row."""
    lines: list[str] = []
    if getattr(deep, "fetch_error", None):
        lines.append(f"  (deep fetch error: {_scrub(deep.fetch_error) or ''})")
    if getattr(deep, "security_report", None) is not None:
        lines.extend(_format_security_section(deep.security_report))
    if getattr(deep, "quality_report", None) is not None:
        lines.extend(_format_quality_section(deep.quality_report))
    if getattr(deep, "install_sim", None) is not None:
        lines.extend(_format_install_section(deep.install_sim))
    if getattr(deep, "conflict_sim", None) is not None:
        lines.extend(_format_conflict_section(deep.conflict_sim))
    if not lines:
        lines.append("  (deep results missing — fetch failed)")
    return lines


def format_table(
    assessments: list[Assessment],
    skips: list[Skip],
    *,
    deep_by_full: Optional[dict[str, Any]] = None,
) -> str:
    """Render a fixed-width table of assessments plus a skipped list.

    When ``deep_by_full`` is provided (only ever on the ``--deep`` path),
    each repo row is followed by a SECURITY / QUALITY / INSTALL SIMULATION
    / CONFLICTS block listing the per-check verdicts and findings. When
    ``deep_by_full`` is ``None`` (the fast path), the output is byte-
    identical to the pre-deep renderer.
    """
    if not assessments and not skips:
        return "no repositories found"

    cols = ["verdict", "repo", "stars", "licence", "platform", "reason"]
    rows: list[list[str]] = []

    for a in sorted(assessments, key=_verdict_sort_key):
        rows.append([
            a.verdict,
            a.ref.full_name,
            "—" if a.facts.stars is None else str(a.facts.stars),
            a.licence_class,
            a.platform_check,
            _scrub("; ".join(a.reasons)) if a.reasons else "—",
        ])

    widths = [len(c) for c in cols]
    for r in rows:
        for i, cell in enumerate(r):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    sep = "  "
    out: list[str] = []
    out.append(sep.join(c.ljust(widths[i]) for i, c in enumerate(cols)))
    out.append(sep.join("-" * widths[i] for i in range(len(cols))))
    sorted_assessments = sorted(assessments, key=_verdict_sort_key)
    for r, a in zip(rows, sorted_assessments):
        out.append(sep.join(r[i].ljust(widths[i]) for i in range(len(cols))))
        if deep_by_full is not None:
            deep = deep_by_full.get(a.ref.full_name.lower())
            if deep is not None:
                out.append("")
                out.extend(_format_deep_block(a, deep))

    if skips:
        out.append("")
        out.append("skipped:")
        for s in skips:
            out.append(
                f"  {_scrub(s.raw) or ''} (line {s.line_no}): "
                f"{_scrub(s.reason) or ''}"
            )

    return "\n".join(out)


# ----- Summary line ------------------------------------------------------


def _deep_counts(deep_by_full: dict[str, Any]) -> dict[str, int]:
    """Tally the headline numbers we report in the deep summary tail.

    Returns a dict with the keys ``security_fail``, ``security_unchecked``,
    ``quality_fail``, ``quality_unchecked``, ``install_time_exec``,
    ``typosquat``. Zero values are returned explicitly so the summary
    can decide whether to print them.
    """
    out = {
        "security_fail": 0,
        "security_unchecked": 0,
        "quality_fail": 0,
        "quality_unchecked": 0,
        "install_time_exec": 0,
        "typosquat": 0,
    }
    for deep in deep_by_full.values():
        sec = getattr(deep, "security_report", None)
        if sec is not None:
            findings = getattr(sec, "findings", None) or []
            for fnd in findings:
                if getattr(fnd, "status", None) == "fail":
                    out["security_fail"] += 1
                elif getattr(fnd, "status", None) == "unchecked":
                    out["security_unchecked"] += 1
        qua = getattr(deep, "quality_report", None)
        if qua is not None:
            findings = getattr(qua, "findings", None) or []
            for fnd in findings:
                if getattr(fnd, "status", None) == "fail":
                    out["quality_fail"] += 1
                elif getattr(fnd, "status", None) == "unchecked":
                    out["quality_unchecked"] += 1
        inst = getattr(deep, "install_sim", None)
        if inst is not None:
            hooks = list(getattr(inst, "hooks", None) or [])
            # Only HIGH-severity hooks (script, cmdclass, top-level-call)
            # count as install-time execution findings; Cargo build-rs and
            # build-backends are flagged separately if at all.
            for h in hooks:
                kind = getattr(h, "kind", "") or ""
                if kind in ("script", "cmdclass", "top-level-call"):
                    out["install_time_exec"] += 1
            typos = list(getattr(inst, "typosquats", None) or [])
            out["typosquat"] += len(typos)
    return out


def format_summary(
    assessments: list[Assessment],
    skips: list[Skip],
    *,
    deep_by_full: Optional[dict[str, Any]] = None,
) -> str:
    """One-line summary, the headline of the report.

    Example::

        repofacts: 15 checked · 1 missing · 3 dead>1y · 2 no-licence
                   · 1 AGPL · 1 platform-mismatch · 0 STOP · 4 CAUTION

    With ``--deep`` (deep_by_full provided)::

        repofacts: 15 checked · ... · 0 STOP · 4 CAUTION
                   · 4 security-fail · 2 install-time-exec · 1 typosquat

    The exit code is the caller's job, not the summary's, but the counts
    give the user what they need at a glance.
    """
    n_checked = len(assessments)
    n_missing = sum(1 for a in assessments if not a.facts.exists)
    n_dead = sum(
        1 for a in assessments
        if any("last push" in r for r in a.reasons)
    )
    # A repo that does not exist has no licence *because it does not exist*.
    # Counting it under "no-licence" double-counts it against "missing" and
    # inflates the licence problem. Only count repos that actually exist.
    n_no_licence = sum(
        1 for a in assessments
        if a.licence_class == "NONE" and getattr(a.facts, "exists", False)
    )
    n_agpl = sum(1 for a in assessments if a.licence_class == "NETWORK_COPYLEFT")
    n_platform = sum(
        1 for a in assessments
        if a.platform_check == "checked_conflict"
    )
    n_forks = sum(
        1 for a in assessments
        if any(r.startswith("low-star fork of") for r in a.reasons)
    )
    n_archived_stale = sum(
        1 for a in assessments
        if any("archived," in r and "last push" in r for r in a.reasons)
    )
    n_stop = sum(1 for a in assessments if a.verdict == "STOP")
    n_caution = sum(1 for a in assessments if a.verdict == "CAUTION")
    n_skipped = len(skips)

    parts: list[str] = [f"{n_checked} checked"]
    if n_skipped:
        parts.append(f"{n_skipped} skipped")
    if n_missing:
        parts.append(f"{n_missing} missing")
    if n_dead:
        parts.append(f"{n_dead} dead>1y")
    if n_archived_stale:
        parts.append(f"{n_archived_stale} archived-stale")
    if n_no_licence:
        parts.append(f"{n_no_licence} no-licence")
    if n_agpl:
        parts.append(f"{n_agpl} AGPL")
    if n_platform:
        parts.append(f"{n_platform} platform-mismatch")
    if n_forks:
        parts.append(f"{n_forks} low-star-fork")
    parts.append(f"{n_stop} STOP")
    parts.append(f"{n_caution} CAUTION")

    if deep_by_full:
        dc = _deep_counts(deep_by_full)
        if dc["security_fail"]:
            parts.append(f"{dc['security_fail']} security-fail")
        if dc["security_unchecked"]:
            parts.append(f"{dc['security_unchecked']} security-unchecked")
        if dc["quality_fail"]:
            parts.append(f"{dc['quality_fail']} quality-fail")
        if dc["quality_unchecked"]:
            parts.append(f"{dc['quality_unchecked']} quality-unchecked")
        if dc["install_time_exec"]:
            parts.append(f"{dc['install_time_exec']} install-time-exec")
        if dc["typosquat"]:
            parts.append(f"{dc['typosquat']} typosquat")

    return "repofacts: " + " · ".join(parts)


# ----- JSON --------------------------------------------------------------


def _deep_to_json(deep: Any) -> dict[str, Any]:
    """Serialise one :class:`_DeepResults`-like object to a JSON-safe dict.

    Every string field passes through :func:`_scrub` so a leaked token
    inside any reason or quote cannot surface in the report. The
    structure is intentionally flat enough to be diffed by humans but
    nested enough to preserve each finding's status / severity / reason
    triple.
    """
    out: dict[str, Any] = {}

    if getattr(deep, "fetch_error", None):
        out["fetch_error"] = _scrub(deep.fetch_error)

    sec = getattr(deep, "security_report", None)
    if sec is not None:
        out["security"] = {
            "findings": [
                {
                    "name": fnd.name,
                    "status": fnd.status,
                    "severity": fnd.severity,
                    "reason": _scrub(fnd.reason) or "",
                }
                for fnd in (getattr(sec, "findings", None) or [])
                if isinstance(fnd, Finding)
            ],
        }
    else:
        out["security"] = None

    qua = getattr(deep, "quality_report", None)
    if qua is not None:
        out["quality"] = {
            "findings": [
                {
                    "name": fnd.name,
                    "status": fnd.status,
                    "severity": fnd.severity,
                    "reason": _scrub(fnd.reason) or "",
                }
                for fnd in (getattr(qua, "findings", None) or [])
                if isinstance(fnd, Finding)
            ],
        }
    else:
        out["quality"] = None

    inst = getattr(deep, "install_sim", None)
    if inst is not None:
        out["install_simulation"] = {
            "declared_dependency_count": getattr(inst, "total_deps", 0),
            "surface_note": _scrub(getattr(inst, "surface_note", "") or ""),
            "manifests_seen": _scrub_list(
                list(getattr(inst, "manifests_seen", None) or [])
            ),
            "hooks": [
                {
                    "ecosystem": h.ecosystem,
                    "kind": h.kind,
                    "name": _scrub(h.name) or "",
                    "quote": _scrub(h.quote) or "",
                    "source": _scrub(h.source) or "",
                    "line_no": h.line_no,
                }
                for h in (getattr(inst, "hooks", None) or [])
            ],
            "floating": [
                {
                    "ecosystem": f.ecosystem,
                    "name": _scrub(f.name) or "",
                    "spec": _scrub(f.spec) or "",
                    "reason": f.reason,
                    "source": _scrub(f.source) or "",
                }
                for f in (getattr(inst, "floating", None) or [])
            ],
            "typosquats": [
                {
                    "name": _scrub(t.name) or "",
                    "canonical": _scrub(t.canonical) or "",
                    "distance": t.distance,
                    "source": _scrub(t.source) or "",
                }
                for t in (getattr(inst, "typosquats", None) or [])
            ],
            "ecosystem_counts": [
                {"ecosystem": e.ecosystem, "count": e.count}
                for e in (getattr(inst, "ecosystem_counts", None) or [])
            ],
            "unparsed": [_scrub(u) or "" for u in (getattr(inst, "unparsed", None) or [])],
        }
    else:
        out["install_simulation"] = None

    conf = getattr(deep, "conflict_sim", None)
    if conf is not None:
        out["conflicts"] = {
            "version_conflicts": [
                {
                    "ecosystem": vc.ecosystem,
                    "name": _scrub(vc.name) or "",
                    "declared_spec": _scrub(vc.declared_spec) or "",
                    "installed_version": _scrub(vc.installed_version) or "",
                    "status": vc.status,
                    "note": _scrub(vc.note) or "",
                }
                for vc in (getattr(conf, "version_conflicts", None) or [])
            ],
            "runtime_floors": [
                {
                    "language": rf.language,
                    "declared": _scrub(rf.declared) or "",
                    "host_version": _scrub(rf.host_version) or "",
                    "status": rf.status,
                    "note": _scrub(rf.note) or "",
                }
                for rf in (getattr(conf, "runtime_floors", None) or [])
            ],
            "new_transitive": [
                {
                    "ecosystem": t.ecosystem,
                    "name": _scrub(t.name) or "",
                    "declared_spec": _scrub(t.declared_spec) or "",
                }
                for t in (getattr(conf, "new_transitive", None) or [])
            ],
            "duplicate_purpose": [
                {
                    "brought": _scrub(d.brought) or "",
                    "brought_ecosystem": d.brought_ecosystem,
                    "duplicates": _scrub(d.duplicates) or "",
                    "group": d.group,
                }
                for d in (getattr(conf, "duplicate_purpose", None) or [])
            ],
            "unparsed": [_scrub(u) or "" for u in (getattr(conf, "unparsed", None) or [])],
        }
    else:
        out["conflicts"] = None

    return out


def format_json(
    assessments: list[Assessment],
    skips: list[Skip],
    licence_as_of: str,
    *,
    partial: bool = False,
    token_source: str = "none",
    deep_by_full: Optional[dict[str, Any]] = None,
) -> str:
    """JSON output.

    Every free-form string field is scrubbed through :func:`_scrub` so a
    leaked token from any source — `description`, `error`, `reason` —
    cannot surface in the report.

    When ``deep_by_full`` is provided (only on the ``--deep`` path), the
    per-repo JSON object gains ``"security"``, ``"quality"``,
    ``"install_simulation"`` and ``"conflicts"`` keys carrying the same
    findings the table renderer shows. When ``deep_by_full`` is ``None``
    (the fast path), the JSON output is byte-identical to the pre-deep
    renderer.
    """
    assessments_out = []
    for a in assessments:
        item: dict[str, Any] = {
            "ref": {
                "owner": a.ref.owner,
                "repo": a.ref.repo,
                "raw_mention": _scrub(a.ref.raw_mention),
                "line_no": a.ref.line_no,
            },
            "verdict": a.verdict,
            "reasons": _scrub_list(a.reasons),
            "licence_class": a.licence_class,
            "platform_check": a.platform_check,
            "platform_notes": _scrub_list(a.platform_notes),
            "multiple_licence_files": a.multiple_licence_files,
            "claim_diffs": [
                {
                    "type": cd.claim_type,
                    "claimed": _scrub(cd.claimed_value),
                    "actual": _scrub(cd.actual_value),
                    "match": cd.match,
                    "raw": _scrub(cd.raw) or "",
                    "line_no": cd.line_no,
                }
                for cd in a.claim_diffs
            ],
            "facts": {
                "exists": a.facts.exists,
                "stars": a.facts.stars,
                "forks": a.facts.forks,
                "language": _scrub(a.facts.language),
                "description": _scrub(a.facts.description),
                "pushed_at": a.facts.pushed_at,
                "created_at": a.facts.created_at,
                "archived": a.facts.archived,
                "disabled": a.facts.disabled,
                "fork": a.facts.fork,
                "parent_full_name": _scrub(a.facts.parent_full_name),
                "license_spdx": _scrub(a.facts.license_spdx),
                "license_name": _scrub(a.facts.license_name),
                "readme_status": a.facts.readme_status,
                "multiple_licence_files_detected": a.multiple_licence_files,
                "moved_to": _scrub(a.facts.moved_to),
                "private": a.facts.private,
                "error": _scrub(a.facts.error),
            },
        }
        if deep_by_full is not None:
            deep = deep_by_full.get(a.ref.full_name.lower())
            if deep is not None:
                item["deep"] = _deep_to_json(deep)
            else:
                item["deep"] = None
        assessments_out.append(item)

    obj = {
        "version": "0.1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "licence_as_of_utc": licence_as_of,
        "partial": partial,
        "token_source": token_source,  # name only; never the token value
        "assessments": assessments_out,
        "skipped": [
            {
                "raw": _scrub(s.raw) or "",
                "reason": _scrub(s.reason) or "",
                "line_no": s.line_no,
            }
            for s in skips
        ],
    }
    return json.dumps(obj, indent=2, ensure_ascii=False)


# ----- Markdown ----------------------------------------------------------


def format_markdown(
    assessments: list[Assessment],
    skips: list[Skip],
    licence_as_of: str,
    *,
    deep_by_full: Optional[dict[str, Any]] = None,
) -> str:
    """Markdown output: a single table per repo, plus a Skipped section.

    When ``deep_by_full`` is provided (only on the ``--deep`` path),
    each repo gets an additional SECURITY / QUALITY / INSTALL SIMULATION
    / CONFLICTS section below its row. When ``deep_by_full`` is ``None``
    (the fast path), the Markdown output is byte-identical to the pre-
    deep renderer.
    """
    out: list[str] = []
    out.append("# repofacts report")
    out.append("")
    out.append(f"_licence as of {licence_as_of}_")
    out.append("")
    out.append("| verdict | repo | stars | licence | platform | reason |")
    out.append("| --- | --- | ---: | --- | --- | --- |")
    for a in sorted(assessments, key=lambda x: x.ref.full_name.lower()):
        stars = "—" if a.facts.stars is None else str(a.facts.stars)
        reason = "; ".join(a.reasons) if a.reasons else "—"
        out.append(
            f"| {a.verdict} | {a.ref.full_name} | {stars} | {a.licence_class} "
            f"| {a.platform_check} | {_scrub(reason) or ''} |"
        )

    if deep_by_full:
        out.append("")
        out.append("## Deep results")
        for a in sorted(assessments, key=lambda x: x.ref.full_name.lower()):
            deep = deep_by_full.get(a.ref.full_name.lower())
            if deep is None:
                continue
            out.append("")
            out.append(f"### {a.ref.full_name}")
            if getattr(deep, "fetch_error", None):
                out.append(
                    f"- _deep fetch error_: `{_scrub(deep.fetch_error) or ''}`"
                )
            sec = getattr(deep, "security_report", None)
            if sec is not None:
                out.append("")
                out.append("#### Security")
                for fnd in (getattr(sec, "findings", None) or []):
                    if not isinstance(fnd, Finding):
                        continue
                    out.append(
                        f"- `{fnd.name}` [{fnd.status}] {fnd.severity} — "
                        f"{_scrub(fnd.reason) or ''}"
                    )
            qua = getattr(deep, "quality_report", None)
            if qua is not None:
                out.append("")
                out.append("#### Quality")
                for fnd in (getattr(qua, "findings", None) or []):
                    if not isinstance(fnd, Finding):
                        continue
                    out.append(
                        f"- `{fnd.name}` [{fnd.status}] — "
                        f"{_scrub(fnd.reason) or ''}"
                    )
            inst = getattr(deep, "install_sim", None)
            if inst is not None:
                out.append("")
                out.append("#### Install simulation")
                out.append(
                    f"- declared dependency count: "
                    f"{getattr(inst, 'total_deps', 0)}"
                )
                hooks = list(getattr(inst, "hooks", None) or [])
                if hooks:
                    out.append(
                        f"- install-time execution findings: {len(hooks)}"
                    )
                    for h in hooks:
                        out.append(
                            f"  - `{h.kind}/{_scrub(h.name) or ''}` from "
                            f"`{_scrub(h.source) or ''}`: "
                            f"\"{_scrub(h.quote) or ''}\""
                        )
                floating = list(getattr(inst, "floating", None) or [])
                if floating:
                    out.append(f"- unpinned versions: {len(floating)}")
                typos = list(getattr(inst, "typosquats", None) or [])
                if typos:
                    out.append(f"- typosquat-proximity hits: {len(typos)}")
            conf = getattr(deep, "conflict_sim", None)
            if conf is not None:
                out.append("")
                out.append("#### Conflicts")
                vcs = list(getattr(conf, "version_conflicts", None) or [])
                if vcs:
                    out.append(
                        f"- version conflicts against installed packages: "
                        f"{len(vcs)}"
                    )
                    for vc in vcs[:5]:
                        out.append(
                            f"  - `{_scrub(vc.name) or ''}` [{vc.status}]: declared "
                            f"`{_scrub(vc.declared_spec) or ''}` vs installed "
                            f"`{_scrub(vc.installed_version) or ''}`"
                        )
                nts = list(getattr(conf, "new_transitive", None) or [])
                if nts:
                    out.append(f"- new surface added: {len(nts)}")

    if skips:
        out.append("")
        out.append("## Skipped")
        out.append("")
        for s in skips:
            out.append(
                f"- `{_scrub(s.raw) or ''}` (line {s.line_no}): "
                f"{_scrub(s.reason) or ''}"
            )

    return "\n".join(out)
