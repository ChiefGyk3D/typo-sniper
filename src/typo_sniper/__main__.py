"""
Module entry point, so ``python -m typo_sniper`` works.

The installed console script ``typo-sniper`` is the usual way in; this exists
for running out of a checkout and for environments that would rather invoke an
interpreter than a script on PATH.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

from .cli import run

if __name__ == '__main__':
    run()
