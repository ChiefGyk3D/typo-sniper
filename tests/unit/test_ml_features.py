"""
Tests for feature extraction.

Two properties matter more than any individual feature and are asserted
throughout: extraction is deterministic, and a vector built from a history
snapshot is identical to one built from the live scan record it came from.
A model trained on the second and scoring the first would be quietly wrong.
"""

import math

import pytest

from ml import features
from ml.features import FEATURE_COUNT, FEATURE_NAMES, extract


def perm(**overrides):
    base = {
        'domain': 'examp1e.com',
        'fuzzer': 'homoglyph',
        'risk_score': 70,
        'created_days_ago': 10,
        'dns_a': ['203.0.113.1'],
        'dns_mx': [],
    }
    base.update(overrides)
    return base


class TestVectorShape:
    def test_length_matches_the_declared_names(self):
        assert len(extract(perm(), 'example.com')) == FEATURE_COUNT
        assert len(FEATURE_NAMES) == FEATURE_COUNT

    def test_names_are_unique(self):
        assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)

    def test_extraction_is_deterministic(self):
        assert extract(perm(), 'example.com') == extract(perm(), 'example.com')

    def test_every_value_is_finite(self):
        vector = extract(perm(), 'example.com')
        assert all(math.isfinite(v) for v in vector)

    def test_values_are_bounded(self):
        """Unbounded features let one outlier dominate a linear model."""
        extreme = perm(
            domain='a' * 63 + '.com', risk_score=10_000,
            created_days_ago=10_000_000, dns_a=['1.2.3.4'] * 50,
            dns_mx=['mx'] * 50, certificates_found=10 ** 9,
        )
        assert all(0.0 <= v <= 1.0 for v in extract(extreme, 'example.com'))

    def test_empty_record_does_not_crash(self):
        assert len(extract({}, 'example.com')) == FEATURE_COUNT

    def test_missing_monitored_domain_does_not_crash(self):
        assert len(extract(perm(), '')) == FEATURE_COUNT


class TestSnapshotEquivalence:
    """A history snapshot must produce the same vector as the live record."""

    def test_http_fields_read_from_either_shape(self):
        live = perm(threat_intel={'http_probe': {
            'http_active': True, 'https_active': True,
            'tls_verified': True, 'title': 'Sign in',
        }})
        snapshot = perm(
            http_active=True, https_active=True,
            tls_verified=True, title='Sign in',
        )
        assert extract(live, 'example.com') == extract(snapshot, 'example.com')

    def test_mail_posture_reads_from_either_shape(self):
        live = perm(mail_intel={'posture': 'hardened'})
        snapshot = perm(mail_posture='hardened')
        assert extract(live, 'example.com') == extract(snapshot, 'example.com')

    def test_certificates_read_from_either_shape(self):
        live = perm(threat_intel={'certificate_transparency': {'certificates_found': 12}})
        snapshot = perm(certificates_found=12)
        assert extract(live, 'example.com') == extract(snapshot, 'example.com')

    def test_urlscan_reads_from_either_shape(self):
        live = perm(threat_intel={'urlscan': {'malicious': True}})
        snapshot = perm(urlscan_malicious=True)
        assert extract(live, 'example.com') == extract(snapshot, 'example.com')


def value(record, name, monitored='example.com'):
    return dict(zip(FEATURE_NAMES, extract(record, monitored), strict=True))[name]


class TestSignals:
    def test_dns_sentinels_are_not_counted_as_records(self):
        """!ServFail is a failed lookup, not an address."""
        assert value(perm(dns_a=['!ServFail']), 'has_a_record') == 0.0
        assert value(perm(dns_a=['!NXDOMAIN']), 'has_a_record') == 0.0
        assert value(perm(dns_a=['203.0.113.1']), 'has_a_record') == 1.0

    def test_a_failed_mail_lookup_scores_as_absent_not_as_evidence(self):
        assert value(perm(mail_posture='unknown'), 'mail_posture') == 0.0
        assert value(perm(mail_posture='none'), 'mail_posture') == 0.0
        assert value(perm(mail_posture='hardened'), 'mail_posture') == 1.0

    def test_mail_posture_is_ordered_by_deliberate_effort(self):
        postures = ['none', 'receive-only', 'partial', 'provisioned', 'hardened']
        scores = [value(perm(mail_posture=p), 'mail_posture') for p in postures]
        assert scores == sorted(scores)

    def test_younger_domains_score_higher(self):
        young = value(perm(created_days_ago=2), 'age_days_log')
        old = value(perm(created_days_ago=3000), 'age_days_log')
        assert young > old

    def test_unknown_age_is_not_treated_as_brand_new(self):
        assert value(perm(created_days_ago=None), 'age_days_log') == 0.0

    def test_invalid_tls_is_distinct_from_no_https(self):
        """A host answering on 443 with a bad certificate is its own state."""
        bad = perm(https_active=True, tls_verified=False)
        absent = perm(https_active=False, tls_verified=None)
        assert value(bad, 'tls_invalid') == 1.0
        assert value(absent, 'tls_invalid') == 0.0
        assert value(bad, 'tls_verified') == 0.0

    def test_credential_words_in_titles(self):
        assert value(perm(title='Sign in to your account'),
                     'title_credential_words') > 0
        assert value(perm(title='Acme Widgets'), 'title_credential_words') == 0

    def test_parked_pages_are_recognised(self):
        assert value(perm(title='This domain is for sale'),
                     'title_parked_words') > 0

    def test_punycode_is_flagged(self):
        assert value(perm(domain='xn--e1awd7f.com'), 'is_punycode') == 1.0
        assert value(perm(domain='example.com'), 'is_punycode') == 0.0

    def test_private_registrant_is_detected(self):
        for text in ('REDACTED FOR PRIVACY', 'Whois Guard', 'Data Protected'):
            assert value(perm(whois_registrant=text), 'registrant_is_private') == 1.0
        assert value(perm(whois_registrant='Acme Ltd'), 'registrant_is_private') == 0.0

    def test_brand_containment_is_detected(self):
        assert value(perm(domain='example-login.com'), 'shares_registrable_stem') == 1.0
        assert value(perm(domain='wholly-unrelated.com'), 'shares_registrable_stem') == 0.0

    def test_tld_match(self):
        assert value(perm(domain='example.com'), 'tld_matches_brand') == 1.0
        assert value(perm(domain='example.xyz'), 'tld_matches_brand') == 0.0


class TestEditDistance:
    @pytest.mark.parametrize('a,b,expected', [
        ('example', 'example', 0),
        ('example', 'examp1e', 1),
        ('example', 'exemple', 1),
        ('example', 'exampl', 1),
        ('', 'abc', 3),
        ('abc', '', 3),
        ('kitten', 'sitting', 3),
    ])
    def test_distances(self, a, b, expected):
        assert features._edit_distance(a, b) == expected

    def test_ratio_accounts_for_brand_length(self):
        """One edit in a short name is a bigger change than in a long one."""
        short = value(perm(domain='acmr.com'), 'edit_distance_ratio', 'acme.com')
        long = value(perm(domain='internationalbusines.com'),
                     'edit_distance_ratio', 'internationalbusiness.com')
        assert short > long


class TestEntropy:
    def test_uniform_string_has_no_entropy(self):
        assert features._entropy('aaaa') == 0.0

    def test_empty_string(self):
        assert features._entropy('') == 0.0

    def test_varied_string_has_more(self):
        assert features._entropy('abcd') > features._entropy('aaab')


class TestNormaliseDomain:
    @pytest.mark.parametrize('given,expected', [
        ('Example.COM', 'example.com'),
        ('  example.com  ', 'example.com'),
        ('example.com.', 'example.com'),
        ('.example.com', 'example.com'),
        (None, ''),
    ])
    def test_canonical_form(self, given, expected):
        assert features.normalise_domain(given) == expected
