"""Tests for the domain risk scoring model."""

from threat_intelligence import calculate_risk_score


class TestRiskScore:
    def test_bare_registration_scores_low(self):
        assert calculate_risk_score({}, {}) == 5

    def test_score_is_clamped_to_range(self):
        everything = {
            'created_days_ago': 1,
            'dns_mx': ['mx.evil.com'],
            'sounds_alike': True,
        }
        intel = {
            'urlscan': {'malicious': True, 'score': 100},
            'http_probe': {'https_active': True, 'redirects_to': 'https://x'},
            'certificate_transparency': {'certificates_found': 5},
        }
        assert calculate_risk_score(everything, intel) == 100
        assert calculate_risk_score({}, {}) >= 0

    def test_recent_registration_raises_score(self):
        """Registration age was previously never read, so it never scored."""
        fresh = calculate_risk_score({'created_days_ago': 5}, {})
        stale = calculate_risk_score({'created_days_ago': 3000}, {})
        assert fresh > stale
        assert fresh - stale == 25

    def test_recency_tiers_are_ordered(self):
        scores = [
            calculate_risk_score({'created_days_ago': d}, {})
            for d in (10, 60, 120, 900)
        ]
        assert scores == sorted(scores, reverse=True)

    def test_urlscan_score_does_not_saturate(self):
        """A score of 20 must not weigh the same as a score of 100."""
        low = calculate_risk_score({}, {'urlscan': {'score': 20}})
        high = calculate_risk_score({}, {'urlscan': {'score': 100}})
        assert low < high
        assert low < 100 and high < 100

    def test_urlscan_error_status_does_not_score(self):
        errored = calculate_risk_score({}, {'urlscan': {'status': 'rate_limited'}})
        assert errored == calculate_risk_score({}, {})

    def test_malformed_urlscan_score_is_survivable(self):
        assert calculate_risk_score({}, {'urlscan': {'score': 'n/a'}}) == 5
        assert calculate_risk_score({}, {'urlscan': {'score': None}}) == 5

    def test_mail_capability_raises_score(self):
        with_mx = calculate_risk_score({'dns_mx': ['mail.x.com']}, {})
        without = calculate_risk_score({}, {})
        assert with_mx - without == 15

    def test_https_outweighs_plain_http(self):
        https = calculate_risk_score({}, {'http_probe': {'https_active': True}})
        http = calculate_risk_score({}, {'http_probe': {'http_active': True}})
        assert https > http

    def test_none_threat_intel_sections_are_safe(self):
        intel = {'urlscan': None, 'http_probe': None, 'certificate_transparency': None}
        assert calculate_risk_score({}, intel) == 5

    def test_negative_age_is_ignored(self):
        """A clock-skewed future creation date must not score as fresh."""
        assert calculate_risk_score({'created_days_ago': -5}, {}) == 5
