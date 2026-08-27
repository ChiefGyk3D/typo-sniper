"""
Keep the manual scripts out of automated collection.

Everything in this directory is a walkthrough meant to be run by hand — several
need network access or an API key, and they report by printing rather than by
asserting. They are named ``test_*.py`` for historical reasons, which is enough
for pytest to try importing them and fail. CI runs ``tests/unit`` only, so this
matters to anyone who types ``pytest tests/`` and gets errors that say nothing
about the state of the code.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

collect_ignore_glob = ['test_*.py']
