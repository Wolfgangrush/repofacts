"""Tests for the install/conflict simulation."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from repofacts.simulate import simulate_install  # noqa: E402

GO_MOD = """module github.com/ossf/scorecard/v5

go 1.24

require (
\tcloud.google.com/go/bigquery v1.73.1
\tcloud.google.com/go/pubsub v1.50.1
\tgithub.com/google/go-cmp v0.7.0 // indirect
)
"""


def test_go_mod_versions_are_exact_pins_not_floating():
    """go.mod has NO caret semantics — `require foo v1.73.1` is an exact pin.

    Rewriting it to `^1.73.1` and reporting it as unpinned produced 296 false
    positives on ossf/scorecard. A false alarm at that scale destroys trust in
    the tool, which falsifier #1 rates worse than a miss.
    """
    sim = simulate_install({"go.mod": GO_MOD})
    assert sim.total_deps == 3, sim.total_deps
    assert len(sim.floating) == 0, [f"{f.name}@{f.spec}" for f in sim.floating]


def test_go_mod_specs_do_not_gain_a_caret():
    sim = simulate_install({"go.mod": GO_MOD})
    specs = {d.name: d.spec for d in sim.declared}
    assert "^" not in specs["cloud.google.com/go/bigquery"], specs
    assert "1.73.1" in specs["cloud.google.com/go/bigquery"], specs


def test_npm_caret_really_is_floating():
    """The control: npm ^ genuinely IS a floating range and must still flag."""
    pkg = '{"dependencies": {"express": "^4.18.0", "left-pad": "1.3.0"}}'
    sim = simulate_install({"package.json": pkg})
    names = {f.name for f in sim.floating}
    assert "express" in names, names
    assert "left-pad" not in names, names
