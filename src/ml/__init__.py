"""
Learned triage for Typo Sniper.

Optional and strictly additive. Detection and the deterministic risk score are
unchanged with no model trained; this layer only reorders a list that a human
reads, using the operator's own past decisions about what was worth acting on.

Training needs scikit-learn; scoring does not. Models are stored as inspectable
JSON and are never unpickled.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

from .dataset import Dataset, build
from .features import FEATURE_NAMES, extract
from .labels import ACTED, DISMISSED, LabelStore
from .model import TriageModel, load, sklearn_available, train

__all__ = [
    'ACTED',
    'DISMISSED',
    'FEATURE_NAMES',
    'Dataset',
    'LabelStore',
    'TriageModel',
    'build',
    'extract',
    'load',
    'sklearn_available',
    'train',
]
