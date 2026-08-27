"""
AI-assisted triage for Typo Sniper.

Optional and strictly additive: the scanner's detection and risk scoring are
deterministic and run identically with no AI configured. This layer explains
findings, it does not produce them.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

from .analyzer import AIAnalyzer
from .base import AIProvider, AIResult
from .providers import PROVIDERS, get_provider

__all__ = ['PROVIDERS', 'AIAnalyzer', 'AIProvider', 'AIResult', 'get_provider']
