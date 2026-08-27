"""Tests for the operator label store."""

import json

import pytest

from ml.labels import (
    ACTED,
    DISMISSED,
    MIN_LABELS_TO_TRAIN,
    MIN_PER_CLASS,
    LabelStore,
)


@pytest.fixture
def store(tmp_path):
    return LabelStore(tmp_path)


class TestStoringLabels:
    def test_round_trip(self, store):
        store.set('evil.com', ACTED, 'example.com')
        assert store.get('evil.com') == ACTED

    def test_domain_matching_is_canonical(self, store):
        store.set('  Evil.COM.  ', ACTED)
        assert store.get('evil.com') == ACTED
        assert store.get('EVIL.com') == ACTED

    def test_unknown_label_is_rejected(self, store):
        with pytest.raises(ValueError, match='Unknown label'):
            store.set('evil.com', 'maybe')

    def test_a_label_needs_a_domain(self, store):
        with pytest.raises(ValueError, match='needs a domain'):
            store.set('', ACTED)

    def test_relabelling_keeps_the_previous_judgement(self, store):
        """A changed decision should be visible, not silently overwritten."""
        store.set('evil.com', ACTED)
        store.set('evil.com', DISMISSED)
        entry = store.all()['evil.com']
        assert entry['label'] == DISMISSED
        assert entry['previous_label'] == ACTED

    def test_notes_are_bounded(self, store):
        store.set('evil.com', ACTED, note='x' * 5000)
        assert len(store.all()['evil.com']['note']) <= 500

    def test_removal(self, store):
        store.set('evil.com', ACTED)
        assert store.remove('evil.com') is True
        assert store.get('evil.com') is None
        assert store.remove('evil.com') is False

    def test_persists_across_instances(self, tmp_path):
        LabelStore(tmp_path).set('evil.com', ACTED)
        assert LabelStore(tmp_path).get('evil.com') == ACTED


class TestResilience:
    def test_corrupt_file_does_not_stop_a_scan(self, tmp_path, caplog):
        """Labels are training data; losing them must not fail the run."""
        (tmp_path / 'labels.json').write_text('{ not json')
        store = LabelStore(tmp_path)
        assert store.all() == {}
        assert 'labels' in caplog.text.lower()

    def test_entries_with_invalid_labels_are_dropped(self, tmp_path):
        (tmp_path / 'labels.json').write_text(json.dumps({
            'labels': {
                'good.com': {'label': ACTED},
                'bad.com': {'label': 'nonsense'},
                'malformed.com': 'not a dict',
            }
        }))
        assert set(LabelStore(tmp_path).all()) == {'good.com'}

    def test_missing_file_is_not_an_error(self, tmp_path):
        assert LabelStore(tmp_path / 'nope').all() == {}


class TestReadiness:
    def _fill(self, store, acted, dismissed):
        for i in range(acted):
            store.set(f'a{i}.com', ACTED)
        for i in range(dismissed):
            store.set(f'd{i}.com', DISMISSED)

    def test_not_ready_when_empty(self, store):
        ready, reason = store.readiness()
        assert ready is False
        assert str(MIN_LABELS_TO_TRAIN) in reason

    def test_not_ready_with_only_one_class(self, store):
        self._fill(store, MIN_LABELS_TO_TRAIN + 5, 0)
        ready, reason = store.readiness()
        assert ready is False
        assert 'one side of it' in reason

    def test_not_ready_when_a_class_is_too_thin(self, store):
        self._fill(store, MIN_LABELS_TO_TRAIN, MIN_PER_CLASS - 1)
        ready, _ = store.readiness()
        assert ready is False

    def test_ready_with_a_balanced_set(self, store):
        self._fill(store, MIN_LABELS_TO_TRAIN, MIN_LABELS_TO_TRAIN)
        ready, reason = store.readiness()
        assert ready is True
        assert 'acted' in reason and 'dismissed' in reason

    def test_counts(self, store):
        self._fill(store, 3, 2)
        assert store.counts() == {ACTED: 3, DISMISSED: 2}
