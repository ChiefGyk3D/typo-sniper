"""
Learned triage ranking.

A deliberate asymmetry runs through this module: **training needs scikit-learn,
scoring does not.**

The trained model is persisted as JSON — feature names, weights, intercept, and
the standardisation constants — and scoring is a dot product and a sigmoid,
written out in plain Python below. Three things follow from that:

  * A scanner host never installs scikit-learn. Only whoever trains does.
  * A model file is readable. You can open it and see that ``mail_posture``
    carries weight 1.8 and ``title_parked_words`` carries -2.1. For a tool whose
    output justifies takedown requests, "why did it rank this first" has to have
    an answer, and an inspectable linear model gives one.
  * **Nothing is ever unpickled.** ``pickle.load`` on a model file is arbitrary
    code execution, and model files get emailed around and committed to repos.
    JSON cannot execute.

That last point is why this is logistic regression rather than a gradient
boosted ensemble that would likely score a point or two higher. An opaque model
that has to be unpickled would trade away both the explanation and the safety
property, to rank a list that a human reads either way.

What the model is for
---------------------
It **ranks**. It does not score. The deterministic risk score stays the number
that appears in reports and takedown requests, for the same reason the LLM is
not allowed to produce one: that number has to be reproducible and explainable
from evidence, and a model fitted to one operator's judgements is neither. What
the model adds is ordering — learning that *this* operator consistently acts on
young domains with mail capability and ignores parked ones, and floating the
former to the top of a long list.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import json
import logging
import math
import time
from pathlib import Path
from typing import Any

from . import features
from .features import FEATURE_NAMES

MODEL_VERSION = 1
MODEL_FILENAME = 'triage_model.json'

logger = logging.getLogger(__name__)


class TriageModel:
    """A trained ranking model, loaded from JSON and scored in pure Python."""

    def __init__(self, payload: dict[str, Any]):
        self.feature_names: list[str] = list(payload.get('feature_names') or [])
        self.weights: list[float] = [float(w) for w in payload.get('weights') or []]
        self.intercept: float = float(payload.get('intercept') or 0.0)
        self.mean: list[float] = [float(m) for m in payload.get('mean') or []]
        self.scale: list[float] = [float(s) for s in payload.get('scale') or []]
        self.metadata: dict[str, Any] = payload.get('metadata') or {}

    @property
    def is_usable(self) -> bool:
        """Whether this model matches the current feature definition."""
        return (
            len(self.weights) == len(self.feature_names) == len(self.mean)
            == len(self.scale) == len(FEATURE_NAMES)
            and self.feature_names == list(FEATURE_NAMES)
        )

    def score(self, perm: dict[str, Any], monitored_domain: str) -> float:
        """
        Rank one permutation.

        Args:
            perm: Permutation record
            monitored_domain: The brand it was found against

        Returns:
            A value in [0, 1]: how much this resembles findings the operator
            has acted on. It is a ranking aid, not a risk score.
        """
        vector = features.extract(perm, monitored_domain)

        total = self.intercept
        for value, mean, scale, weight in zip(
            vector, self.mean, self.scale, self.weights, strict=True
        ):
            total += ((value - mean) / (scale or 1.0)) * weight

        # Sigmoid, guarded against overflow on extreme inputs
        if total >= 0:
            return 1.0 / (1.0 + math.exp(-min(total, 60.0)))
        exponent = math.exp(max(total, -60.0))
        return exponent / (1.0 + exponent)

    def explain(self, perm: dict[str, Any], monitored_domain: str, top: int = 5):
        """
        The features that moved this particular score the most.

        Args:
            perm: Permutation record
            monitored_domain: The brand it was found against
            top: How many contributions to return

        Returns:
            List of (feature_name, signed_contribution), largest magnitude first
        """
        vector = features.extract(perm, monitored_domain)
        contributions = [
            (name, ((value - mean) / (scale or 1.0)) * weight)
            for name, value, mean, scale, weight in zip(
                self.feature_names, vector, self.mean, self.scale, self.weights,
                strict=True,
            )
        ]
        contributions.sort(key=lambda pair: abs(pair[1]), reverse=True)
        return contributions[:top]

    def influential_features(self, top: int = 10):
        """The features the model relies on overall, largest weight first."""
        ranked = sorted(
            zip(self.feature_names, self.weights, strict=False),
            key=lambda pair: abs(pair[1]), reverse=True,
        )
        return ranked[:top]


def model_path(state_dir: Path) -> Path:
    """Where the trained model lives."""
    return Path(state_dir) / MODEL_FILENAME


def load(state_dir: Path) -> TriageModel | None:
    """
    Load the trained model, if one exists and matches the current features.

    Args:
        state_dir: Directory holding scan state

    Returns:
        A usable TriageModel, or None
    """
    path = model_path(state_dir)
    if not path.exists():
        return None

    try:
        with open(path, encoding='utf-8') as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(
            f'Could not read the triage model ({type(e).__name__}); '
            f'ranking will fall back to the risk score'
        )
        return None

    model = TriageModel(payload)
    if not model.is_usable:
        # Features were added or reordered since training. Silently scoring
        # with a mismatched vector would produce plausible nonsense.
        logger.warning(
            'The stored triage model was trained on a different feature set '
            'and will not be used. Retrain with: typo_sniper.py --ml-train'
        )
        return None
    return model


def train(dataset, state_dir: Path) -> dict[str, Any]:
    """
    Fit a model on labelled history and write it as JSON.

    Args:
        dataset: Object with .vectors (list[list[float]]) and .targets (list[int])
        state_dir: Where to write the model

    Returns:
        A report describing the fit, including a cross-validated score

    Raises:
        ImportError: If scikit-learn is not installed
    """
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from sklearn.preprocessing import StandardScaler

    x = np.asarray(dataset.vectors, dtype=float)
    y = np.asarray(dataset.targets, dtype=int)

    scaler = StandardScaler().fit(x)
    x_scaled = scaler.transform(x)

    # L2-regularised and class-balanced: label sets here are small and usually
    # lopsided, since operators record the domains they acted on far more
    # reliably than the ones they waved past.
    # L2 is lbfgs's default across every supported scikit-learn version;
    # passing penalty= explicitly is deprecated from 1.8 on.
    estimator = LogisticRegression(
        C=1.0, class_weight='balanced', max_iter=2000, solver='lbfgs',
    )

    # Cross-validated before fitting on everything, so the reported score is
    # not the training score. On a small label set that difference is the
    # whole story.
    folds = max(2, min(5, int(min(np.bincount(y)))))
    try:
        scores = cross_val_score(
            estimator, x_scaled, y,
            cv=StratifiedKFold(n_splits=folds, shuffle=True, random_state=0),
            scoring='roc_auc',
        )
        cv_auc = float(scores.mean())
        cv_std = float(scores.std())
    except ValueError:
        cv_auc, cv_std = float('nan'), float('nan')

    estimator.fit(x_scaled, y)

    payload = {
        'version': MODEL_VERSION,
        'feature_names': list(FEATURE_NAMES),
        'weights': [float(w) for w in estimator.coef_[0]],
        'intercept': float(estimator.intercept_[0]),
        'mean': [float(m) for m in scaler.mean_],
        'scale': [float(s) for s in scaler.scale_],
        'metadata': {
            'trained_at': time.time(),
            'samples': len(y),
            'acted': int((y == 1).sum()),
            'dismissed': int((y == 0).sum()),
            'cv_folds': folds,
            'cv_roc_auc': cv_auc,
            'cv_roc_auc_std': cv_std,
            'monitored_domains': sorted(set(getattr(dataset, 'monitored_domains', []))),
        },
    }

    path = model_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, indent=2)

    model = TriageModel(payload)
    return {
        'path': str(path),
        'samples': payload['metadata']['samples'],
        'acted': payload['metadata']['acted'],
        'dismissed': payload['metadata']['dismissed'],
        'cv_roc_auc': cv_auc,
        'cv_roc_auc_std': cv_std,
        'cv_folds': folds,
        'influential_features': model.influential_features(),
    }


def sklearn_available() -> bool:
    """Whether the training dependency is installed."""
    import importlib.util
    return importlib.util.find_spec('sklearn') is not None
