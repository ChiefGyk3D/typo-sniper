"""
Tests for dataset assembly and the trained model.

The property this file exists for: a model file is data, never code. Scoring
loads JSON and does arithmetic. Nothing here unpickles anything, because model
files get emailed around and committed, and pickle.load is arbitrary code
execution.
"""

import importlib.util
import json

import pytest

import ml
from ml import build
from ml.features import FEATURE_NAMES
from ml.labels import ACTED, DISMISSED, LabelStore
from ml.model import TriageModel, model_path
from state import ScanHistory

sklearn_missing = importlib.util.find_spec('sklearn') is None
needs_sklearn = pytest.mark.skipif(
    sklearn_missing, reason='training needs scikit-learn; scoring does not'
)


def make_perm(domain, *, bad, **extra):
    record = {
        'domain': domain,
        'fuzzer': 'combosquat',
        'risk_score': 85 if bad else 15,
        'created_days_ago': 5 if bad else 2500,
        'dns_a': ['203.0.113.1'] if bad else [],
        'dns_mx': ['mx.test'] if bad else [],
        'whois_registrant': 'REDACTED FOR PRIVACY' if bad else 'Acme Ltd',
        # The nested shape a live scan produces, so records written to history
        # exercise the same flattening the scanner's do.
        'mail_intel': {'posture': 'provisioned' if bad else 'none'},
        'threat_intel': {'http_probe': {
            'http_active': bad,
            'https_active': bad,
            'tls_verified': True,
            'title': 'Sign in to your account' if bad else 'Domain for sale',
        }},
    }
    record.update(extra)
    return record


def seeded(tmp_path, count=40):
    """A history and label set with a learnable separation."""
    history = ScanHistory(tmp_path)
    store = LabelStore(tmp_path)
    perms = []
    for i in range(count):
        bad = i % 2 == 0
        domain = f'{"secure-example" if bad else "exampleparts"}{i}.com'
        perms.append(make_perm(domain, bad=bad))
        store.set(domain, ACTED if bad else DISMISSED, 'example.com')
    history.record({
        'original_domain': 'example.com', 'scan_date': '2026-08-01',
        'registered_count': count, 'permutations': perms,
    })
    return history, store


class TestDatasetAssembly:
    def test_labels_join_to_history(self, tmp_path):
        history, store = seeded(tmp_path, 10)
        dataset = build(history, store, ['example.com'])
        assert len(dataset) == 10
        assert dataset.class_counts == {'acted': 5, 'dismissed': 5}

    def test_labels_without_history_are_reported_not_silently_dropped(self, tmp_path):
        history, store = seeded(tmp_path, 4)
        store.set('never-scanned.com', ACTED)
        dataset = build(history, store, ['example.com'])
        assert dataset.unmatched == ['never-scanned.com']
        assert len(dataset) == 4

    def test_features_come_from_the_earliest_snapshot(self, tmp_path):
        """
        The bug this guards against: a domain that has since been taken down
        resolves nowhere today. Training on its current state would teach the
        model that dead domains are the dangerous ones — an inversion learned
        from perfectly good labels.
        """
        history = ScanHistory(tmp_path)
        store = LabelStore(tmp_path)

        # First scan: live and dangerous. This is the state that was judged.
        history.record({
            'original_domain': 'example.com', 'scan_date': '2026-01-01',
            'permutations': [make_perm('evil.com', bad=True)],
        })
        # Later scan: taken down, resolving nowhere.
        history.record({
            'original_domain': 'example.com', 'scan_date': '2026-06-01',
            'permutations': [make_perm('evil.com', bad=False)],
        })
        store.set('evil.com', ACTED, 'example.com')

        dataset = build(history, store, ['example.com'])
        vector = dict(zip(FEATURE_NAMES, dataset.vectors[0], strict=True))
        assert vector['has_a_record'] == 1.0, 'used the taken-down state'
        assert vector['mail_posture'] > 0.0

    def test_no_labels_produces_an_empty_dataset(self, tmp_path):
        history, _ = seeded(tmp_path, 4)
        # A separate directory, so this store genuinely holds no labels
        assert len(build(history, LabelStore(tmp_path / 'empty'), ['example.com'])) == 0


class TestScoringWithoutSklearn:
    """The scoring path must work on a host with no ML dependencies."""

    def _model(self, weights=None):
        n = len(FEATURE_NAMES)
        return TriageModel({
            'feature_names': list(FEATURE_NAMES),
            'weights': weights or [0.1] * n,
            'intercept': 0.0,
            'mean': [0.0] * n,
            'scale': [1.0] * n,
        })

    def test_score_is_a_probability(self, tmp_path):
        score = self._model().score(make_perm('evil.com', bad=True), 'example.com')
        assert 0.0 <= score <= 1.0

    def test_extreme_weights_do_not_overflow(self):
        n = len(FEATURE_NAMES)
        huge = TriageModel({
            'feature_names': list(FEATURE_NAMES), 'weights': [1e6] * n,
            'intercept': 1e9, 'mean': [0.0] * n, 'scale': [1.0] * n,
        })
        tiny = TriageModel({
            'feature_names': list(FEATURE_NAMES), 'weights': [-1e6] * n,
            'intercept': -1e9, 'mean': [0.0] * n, 'scale': [1.0] * n,
        })
        perm = make_perm('evil.com', bad=True)
        assert huge.score(perm, 'example.com') == pytest.approx(1.0)
        assert tiny.score(perm, 'example.com') == pytest.approx(0.0)

    def test_zero_scale_does_not_divide_by_zero(self):
        """A constant feature in the training set has zero variance."""
        n = len(FEATURE_NAMES)
        model = TriageModel({
            'feature_names': list(FEATURE_NAMES), 'weights': [0.1] * n,
            'intercept': 0.0, 'mean': [0.0] * n, 'scale': [0.0] * n,
        })
        assert 0.0 <= model.score(make_perm('evil.com', bad=True), 'example.com') <= 1.0

    def test_explain_returns_signed_contributions(self):
        contributions = self._model().explain(
            make_perm('evil.com', bad=True), 'example.com', top=4
        )
        assert len(contributions) == 4
        assert all(isinstance(name, str) for name, _ in contributions)
        # Ordered by magnitude
        magnitudes = [abs(v) for _, v in contributions]
        assert magnitudes == sorted(magnitudes, reverse=True)

    def test_influential_features_are_ranked_by_weight(self):
        weights = [0.0] * len(FEATURE_NAMES)
        weights[FEATURE_NAMES.index('mail_posture')] = -5.0
        top = self._model(weights).influential_features(1)
        assert top[0][0] == 'mail_posture'


class TestModelLoading:
    def test_absent_model_is_not_an_error(self, tmp_path):
        assert ml.load(tmp_path) is None

    def test_corrupt_model_degrades_to_none(self, tmp_path, caplog):
        model_path(tmp_path).write_text('{ not json')
        assert ml.load(tmp_path) is None
        assert 'model' in caplog.text.lower()

    def test_a_model_from_a_different_feature_set_is_refused(self, tmp_path, caplog):
        """Scoring a mismatched vector would produce plausible nonsense."""
        model_path(tmp_path).write_text(json.dumps({
            'feature_names': ['only', 'three', 'features'],
            'weights': [1.0, 1.0, 1.0], 'intercept': 0.0,
            'mean': [0.0] * 3, 'scale': [1.0] * 3,
        }))
        assert ml.load(tmp_path) is None
        assert 'retrain' in caplog.text.lower()


@needs_sklearn
class TestTraining:
    def test_learns_a_separable_problem(self, tmp_path):
        history, store = seeded(tmp_path, 40)
        report = ml.train(build(history, store, ['example.com']), tmp_path)

        assert report['samples'] == 40
        assert report['acted'] == 20
        assert report['dismissed'] == 20
        assert report['cv_roc_auc'] > 0.9

    def test_the_written_model_is_json_not_a_pickle(self, tmp_path):
        """A model file is data. pickle.load on one is code execution."""
        history, store = seeded(tmp_path, 40)
        ml.train(build(history, store, ['example.com']), tmp_path)

        raw = model_path(tmp_path).read_text()
        payload = json.loads(raw)  # would raise if it were a pickle
        assert set(payload) >= {'feature_names', 'weights', 'intercept',
                                'mean', 'scale', 'metadata'}
        assert payload['feature_names'] == list(FEATURE_NAMES)

    def test_a_trained_model_ranks_the_dangerous_side_higher(self, tmp_path):
        history, store = seeded(tmp_path, 40)
        ml.train(build(history, store, ['example.com']), tmp_path)
        model = ml.load(tmp_path)

        dangerous = model.score(make_perm('secure-example99.com', bad=True), 'example.com')
        benign = model.score(make_perm('exampleparts99.com', bad=False), 'example.com')
        assert dangerous > benign

    def test_metadata_records_what_it_was_trained_on(self, tmp_path):
        history, store = seeded(tmp_path, 40)
        ml.train(build(history, store, ['example.com']), tmp_path)

        meta = ml.load(tmp_path).metadata
        assert meta['samples'] == 40
        assert meta['monitored_domains'] == ['example.com']
        assert meta['trained_at'] > 0

    def test_round_trip_scoring_matches_across_a_reload(self, tmp_path):
        history, store = seeded(tmp_path, 40)
        ml.train(build(history, store, ['example.com']), tmp_path)
        perm = make_perm('evil.com', bad=True)
        assert ml.load(tmp_path).score(perm, 'example.com') == pytest.approx(
            ml.load(tmp_path).score(perm, 'example.com')
        )
