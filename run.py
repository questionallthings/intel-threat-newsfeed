#!/usr/bin/env python3
"""The single command.

    python3 run.py

Fetches all 14 sources, updates the local database, regenerates
``newsfeed.html``, and opens it in your browser. No install step, no
configuration, no server.

Everything this accepts is documented by::

    python3 run.py --help

This file is a thin wrapper so the entry point is obvious in a directory
listing. ``python3 -m newsfeed`` does exactly the same thing.
"""

from __future__ import annotations

import sys

# Checked before importing anything else, so an old interpreter produces this
# message rather than a SyntaxError from a type annotation.
if sys.version_info < (3, 9):
    sys.exit(
        f"This tool needs Python 3.9 or newer; you are running "
        f"{sys.version_info.major}.{sys.version_info.minor}.\n"
        "Install a current Python from https://www.python.org/downloads/"
    )

from pathlib import Path  # noqa: E402

# Allows running as `python3 run.py` from any working directory, not just from
# inside the repository.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from newsfeed.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
