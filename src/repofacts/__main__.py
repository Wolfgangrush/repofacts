"""Entry point: ``python -m repofacts ...``.

Delegates straight to :func:`repofacts.cli.main`. Exit code is propagated.
"""
from __future__ import annotations

import sys

from .cli import main


if __name__ == "__main__":
    sys.exit(main())
