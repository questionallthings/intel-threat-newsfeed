"""Threat intelligence newsfeed aggregator.

Importing this package makes ``defusedxml`` importable, preferring a pip-installed
copy and falling back to the one vendored in ``vendor/``.

The fallback is why this tool runs from a single command with no install step.
``defusedxml`` is not optional: feeds are untrusted XML from fourteen different
publishers, and Python's stdlib ``xml.etree.ElementTree`` is vulnerable to
entity-expansion attacks ("billion laughs"), where a few hundred bytes of XML
expand to gigabytes in memory. A hostile or compromised feed should not be able
to take the machine down.

A pip-installed copy wins because it will be newer. The vendored copy exists so
the tool still works without network access or install rights.
"""

from __future__ import annotations

import sys
from pathlib import Path

__version__ = "1.0.0"

try:  # pragma: no cover - depends on the host environment
    import defusedxml  # noqa: F401
except ImportError:  # pragma: no cover
    _vendor = Path(__file__).resolve().parent.parent / "vendor"
    if _vendor.is_dir():
        sys.path.insert(0, str(_vendor))
