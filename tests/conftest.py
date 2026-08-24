"""Put ``src/`` on the import path for every test file, in every order.

Without this, only the test modules that hand-rolled their own
``sys.path.insert`` were importable on their own; the rest passed solely
because an alphabetically-earlier module had already mutated ``sys.path``
in the same process. ``pytest tests/test_claims.py`` — an ordinary thing for
a contributor to run — failed at collection.

pytest imports ``conftest.py`` before collecting any test module, so this
runs first regardless of which files are selected.
"""
from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
