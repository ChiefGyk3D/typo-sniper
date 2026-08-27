"""Tests for the domain risk scoring model."""

from typo_sniper.threat_intelligence import calculate_risk_score


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


class TestPageCollectionSignals:
    """
    What a page collects is the strongest signal the scanner produces.

    Registering a lookalike is cheap and ambiguous. Standing up a form that
    asks for a password is neither, and the score has to reflect that gap.
    """

    def _perm(self, page=None):
        return {
            'domain': 'examp1e.com',
            'created_days_ago': 400,
            'dns_a': ['203.0.113.1'],
        }, {'http_probe': {'https_active': True, 'tls_verified': True, 'page': page}}

    def test_a_credential_form_outweighs_a_plain_live_page(self):
        perm, plain = self._perm()
        _, phish = self._perm({'parse_ok': True, 'is_credential_form': True,
                               'has_password_input': True})
        assert calculate_risk_score(perm, phish) > calculate_risk_score(perm, plain) + 25

    def test_an_off_site_form_action_adds_on_top(self):
        perm, without = self._perm({'parse_ok': True, 'is_credential_form': True,
                                    'has_password_input': True})
        _, with_exfil = self._perm({'parse_ok': True, 'is_credential_form': True,
                                    'has_password_input': True,
                                    'external_form_action': True})
        assert calculate_risk_score(perm, with_exfil) > calculate_risk_score(perm, without)

    def test_a_brand_mention_alone_does_not_raise_the_score(self):
        """A fan page naming a brand is not a phishing kit."""
        perm, plain = self._perm()
        _, mentions = self._perm({'parse_ok': True, 'brand_mentioned': True,
                                  'form_count': 0})
        assert calculate_risk_score(perm, mentions) == calculate_risk_score(perm, plain)

    def test_a_brand_mention_beside_a_form_does_raise_it(self):
        _, form_only = self._perm({'parse_ok': True, 'form_count': 1})
        perm, both = self._perm({'parse_ok': True, 'form_count': 1,
                                 'brand_mentioned': True})
        assert calculate_risk_score(perm, both) > calculate_risk_score(perm, form_only)

    def test_a_parked_page_is_not_penalised(self):
        perm, plain = self._perm()
        _, parked = self._perm({'parse_ok': True, 'form_count': 0,
                                'is_credential_form': False})
        assert calculate_risk_score(perm, parked) == calculate_risk_score(perm, plain)

    def test_absent_page_analysis_changes_nothing(self):
        """The feature is additive: scores without it must be unchanged."""
        perm, plain = self._perm()
        _, missing = self._perm(None)
        assert calculate_risk_score(perm, missing) == calculate_risk_score(perm, plain)
