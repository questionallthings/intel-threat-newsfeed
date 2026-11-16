# Vendored dependencies

## defusedxml 0.7.1

Copyright (c) 2013 Christian Heimes <christian@python.org>. Licensed to the
Python Software Foundation under a contributor agreement; see
<https://www.python.org/psf/license> for the licence text.

Upstream: <https://github.com/tiran/defusedxml>

### Why it is here

This is what makes `python3 run.py` work with no install step. `newsfeed/__init__.py`
tries a pip-installed `defusedxml` first and falls back to this copy, so a user
with the package installed gets the newer one automatically.

It is not an optional dependency. Feeds are untrusted XML from fourteen separate
publishers, and the standard library's `xml.etree.ElementTree` is vulnerable to
entity-expansion attacks — a few hundred bytes of XML that expand to gigabytes
in memory. A hostile or compromised feed should not be able to take down the
machine reading it.

### Keeping it current

Vendoring a security library means this copy does not update itself. To refresh:

```bash
pip download --no-binary :all: --no-deps defusedxml
# unpack, then replace the defusedxml/ directory here with the new one
```

Then update the version in this file and in the README's licence section.

If you would rather not rely on a bundled copy, `pip install defusedxml` and the
installed version takes precedence — nothing here needs changing.
