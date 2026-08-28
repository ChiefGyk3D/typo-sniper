"""
Operator feedback, stored as training labels.

A learned model needs to know what a correct answer looks like, and for this
problem only the operator knows. Two domains can carry identical signals while
one is a competitor's legitimate product name and the other is bait; no amount
of DNS data settles that. So the label is a record of a human decision:

  * ``acted``     - worth acting on: escalated, reported, blocked, taken down
  * ``dismissed`` - looked at and judged not worth acting on

"Dismissed" is as valuable as "acted" and is the half operators forget to
record. A model trained only on confirmed-bad examples learns that everything
is bad.

Labels are stored separately from scan history and are never expired by the
history retention window. A judgement made once should not evaporate because
thirty scans have run since.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from .features import normalise_domain

ACTED = 'acted'
DISMISSED = 'dismissed'
VALID_LABELS = (ACTED, DISMISSED)

# Below this, a model is fitting noise. Reported rather than silently ignored.
MIN_LABELS_TO_TRAIN = 30
MIN_PER_CLASS = 8


class LabelStore:
    """Persist and query operator judgements."""

    def __init__(self, state_dir: Path):
        """
        Args:
            state_dir: Directory holding scan state; labels live alongside it
        """
        self.path = Path(state_dir) / 'labels.json'
        self.logger = logging.getLogger(__name__)
        self._labels: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with open(self.path, encoding='utf-8') as handle:
                data = json.load(handle)
            entries = data.get('labels', {})
            if isinstance(entries, dict):
                self._labels = {
                    k: v for k, v in entries.items()
                    if isinstance(v, dict) and v.get('label') in VALID_LABELS
                }
        except (OSError, json.JSONDecodeError) as e:
            # A corrupt label file must not stop a scan. It is training data,
            # not something the scan depends on.
            self.logger.warning(
                f'Could not read labels from {self.path} ({type(e).__name__}); '
                f'continuing with none'
            )

    def _save(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Write-then-rename: labels are training data an operator entered
            # by hand, and a crash mid-write must not truncate them.
            tmp = self.path.with_suffix(self.path.suffix + '.tmp')
            with open(tmp, 'w', encoding='utf-8') as handle:
                json.dump({'version': 1, 'labels': self._labels}, handle, indent=2)
            os.replace(tmp, self.path)
            return True
        except OSError as e:
            self.logger.error(f'Could not write labels: {type(e).__name__}')
            return False

    def set(
        self,
        domain: str,
        label: str,
        monitored_domain: str | None = None,
        note: str | None = None,
    ) -> bool:
        """
        Record a judgement about one domain.

        Args:
            domain: The permutation being judged
            label: One of 'acted' or 'dismissed'
            monitored_domain: The brand it was found against
            note: Optional free-text reason

        Returns:
            True if the label was stored

        Raises:
            ValueError: If the label is not recognised
        """
        if label not in VALID_LABELS:
            raise ValueError(
                f"Unknown label '{label}'; expected one of {', '.join(VALID_LABELS)}"
            )

        key = normalise_domain(domain)
        if not key:
            raise ValueError('A label needs a domain')

        previous = self._labels.get(key, {})
        self._labels[key] = {
            'label': label,
            'monitored_domain': normalise_domain(monitored_domain or
                                                 previous.get('monitored_domain') or ''),
            'note': (note or '').strip()[:500] or None,
            'labelled_at': time.time(),
            # Kept so a changed judgement is visible rather than silent
            'previous_label': previous.get('label'),
        }
        return self._save()

    def remove(self, domain: str) -> bool:
        """Delete a label. Returns True if one was present."""
        key = normalise_domain(domain)
        if key in self._labels:
            del self._labels[key]
            self._save()
            return True
        return False

    def get(self, domain: str) -> str | None:
        """The label for a domain, or None."""
        entry = self._labels.get(normalise_domain(domain))
        return entry.get('label') if entry else None

    def all(self) -> dict[str, dict[str, Any]]:
        """Every stored label, keyed by domain."""
        return dict(self._labels)

    def counts(self) -> dict[str, int]:
        """How many of each label are stored."""
        result = dict.fromkeys(VALID_LABELS, 0)
        for entry in self._labels.values():
            result[entry['label']] = result.get(entry['label'], 0) + 1
        return result

    def readiness(self, min_labels: int | None = None) -> tuple[bool, str]:
        """
        Whether there is enough labelled data to train.

        Args:
            min_labels: Total-label threshold. Defaults to
                MIN_LABELS_TO_TRAIN; the configurable ``ml_min_labels`` is
                passed through here so the setting is honoured in both
                directions, but the per-class floor always applies.

        Returns:
            Tuple of (ready, an explanation an operator can act on)
        """
        threshold = MIN_LABELS_TO_TRAIN if min_labels is None else max(int(min_labels), 1)
        counts = self.counts()
        total = sum(counts.values())
        acted, dismissed = counts.get(ACTED, 0), counts.get(DISMISSED, 0)

        if total < threshold:
            return False, (
                f'{total} of {threshold} labels needed to train. '
                f'Label findings with --label <domain>=acted|dismissed.'
            )
        if acted < MIN_PER_CLASS or dismissed < MIN_PER_CLASS:
            short = ACTED if acted < MIN_PER_CLASS else DISMISSED
            return False, (
                f'Need at least {MIN_PER_CLASS} of each label to train; '
                f"have {acted} acted and {dismissed} dismissed. A model cannot "
                f"learn a boundary from one side of it — more '{short}' needed."
            )
        return True, f'{total} labels ({acted} acted, {dismissed} dismissed)'
