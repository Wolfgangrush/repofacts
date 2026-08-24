"""repofacts — verify the GitHub repos an AI recommended.

Package layout:
    ``models``  — plain dataclasses
    ``extract`` — text → refs (pure)
    ``github``  — the only network module
    ``rules``   — pure verdicts
    ``claims``  — pure claim diff
    ``render``  — table / JSON / Markdown
    ``cli``     — argparse + orchestration + exit codes

Public re-exports are kept minimal; callers should import from the
submodules when they want a specific thing.
"""

from __future__ import annotations

__version__ = "0.1.0"


__all__ = ["__version__"]
