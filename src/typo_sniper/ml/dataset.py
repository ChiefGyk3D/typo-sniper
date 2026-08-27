"""
Build a training set from scan history and operator labels.

The join is the interesting part. A label says "example-login.com was worth
acting on"; the features have to come from what the domain looked like when
that judgement was made, not from what it looks like now. A domain that has
since been taken down resolves nowhere today, and training on its current
state would teach the model that dead domains are the dangerous ones — an
inversion of the truth, learned from perfectly good labels.

So each label is matched against the **earliest** history snapshot containing
that domain, which is the closest available record to the state it was in when
it first warranted attention.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import logging
from dataclasses import dataclass, field
from typing import Any

from . import features
from .labels import ACTED, LabelStore

logger = logging.getLogger(__name__)


@dataclass
class Dataset:
    """Feature vectors paired with their labels."""

    vectors: list[list[float]] = field(default_factory=list)
    targets: list[int] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    monitored_domains: list[str] = field(default_factory=list)
    unmatched: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.targets)

    @property
    def class_counts(self) -> dict[str, int]:
        acted = sum(self.targets)
        return {'acted': acted, 'dismissed': len(self.targets) - acted}


def build(history, labels: LabelStore, monitored_domains: list[str]) -> Dataset:
    """
    Join labelled domains to their earliest recorded state.

    Args:
        history: ScanHistory instance
        labels: LabelStore holding operator judgements
        monitored_domains: Brands whose history should be searched

    Returns:
        A Dataset; domains with a label but no history land in .unmatched
    """
    dataset = Dataset()

    # domain -> (snapshot, monitored_domain), taking the oldest scan that saw it
    earliest: dict[str, tuple[dict[str, Any], str]] = {}

    for monitored in monitored_domains:
        scans = history.load(monitored)
        # load() returns newest first, so walking in reverse ends on the oldest
        for snapshot in reversed(scans):
            for domain, perm in (snapshot.get('permutations') or {}).items():
                key = features.normalise_domain(domain)
                if key and key not in earliest:
                    record = dict(perm)
                    record['domain'] = domain
                    earliest[key] = (record, monitored)

    for domain, entry in labels.all().items():
        match = earliest.get(domain)
        if match is None:
            # Labelled but never seen in a retained scan: either the label
            # predates the history window or the domain was labelled by hand.
            dataset.unmatched.append(domain)
            continue

        record, monitored = match
        dataset.vectors.append(features.extract(record, monitored))
        dataset.targets.append(1 if entry['label'] == ACTED else 0)
        dataset.domains.append(domain)
        dataset.monitored_domains.append(monitored)

    if dataset.unmatched:
        logger.info(
            f'{len(dataset.unmatched)} labelled domain(s) had no scan history '
            f'and were skipped'
        )

    return dataset
