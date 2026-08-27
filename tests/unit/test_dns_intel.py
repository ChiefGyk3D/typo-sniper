"""Tests for SPF / DKIM / DMARC assessment and mail-capability scoring."""


import pytest

from typo_sniper.dns_intel import (
    DNSIntelligence,
    classify_mail_posture,
    score_mail_capability,
)

SPF_BASIC = 'v=spf1 ip4:203.0.113.0/24 -all'
SPF_WITH_PROVIDER = 'v=spf1 include:sendgrid.net include:_spf.google.com ~all'
DMARC_REJECT = 'v=DMARC1; p=reject; rua=mailto:dmarc@evil.com'
DMARC_NONE = 'v=DMARC1; p=none'
DKIM_KEY = 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ'


@pytest.fixture
def intel(config):
    return DNSIntelligence(config)


def stub_txt(intel, mapping, ok=True):
    """
    Make _query_txt answer from a name -> records mapping.

    ``ok=False`` simulates a failed lookup, which must be distinguishable from
    a domain that genuinely has no records.
    """
    async def fake(name):
        return mapping.get(name, []), ok
    intel._query_txt = fake
    # Bypass the dnspython availability check
    intel._resolver = object()
    return intel


class TestSPF:
    @pytest.mark.asyncio
    async def test_detects_spf(self, intel):
        stub_txt(intel, {'evil.com': ['some other record', SPF_BASIC]})
        result = await intel.check_spf('evil.com')
        assert result['present'] is True
        assert result['all_qualifier'] == '-'
        assert result['policy'] == 'fail'

    @pytest.mark.asyncio
    async def test_extracts_third_party_senders(self, intel):
        """An authorised bulk-mail provider points at campaign infrastructure."""
        stub_txt(intel, {'evil.com': [SPF_WITH_PROVIDER]})
        result = await intel.check_spf('evil.com')
        assert 'sendgrid.net' in result['includes']
        assert result['policy'] == 'softfail'

    @pytest.mark.asyncio
    async def test_absent_spf(self, intel):
        stub_txt(intel, {'evil.com': ['google-site-verification=abc']})
        assert await intel.check_spf('evil.com') is None

    @pytest.mark.asyncio
    async def test_no_records_at_all(self, intel):
        stub_txt(intel, {})
        assert await intel.check_spf('evil.com') is None


class TestDMARC:
    @pytest.mark.asyncio
    async def test_detects_enforcing_policy(self, intel):
        stub_txt(intel, {'_dmarc.evil.com': [DMARC_REJECT]})
        result = await intel.check_dmarc('evil.com')
        assert result['policy'] == 'reject'
        assert result['rua'] == ['mailto:dmarc@evil.com']

    @pytest.mark.asyncio
    async def test_detects_monitoring_only_policy(self, intel):
        stub_txt(intel, {'_dmarc.evil.com': [DMARC_NONE]})
        assert (await intel.check_dmarc('evil.com'))['policy'] == 'none'

    @pytest.mark.asyncio
    async def test_queries_the_dmarc_subdomain(self, intel):
        """DMARC lives at _dmarc.<domain>, not at the apex."""
        stub_txt(intel, {'evil.com': [DMARC_REJECT]})
        assert await intel.check_dmarc('evil.com') is None


class TestDKIM:
    @pytest.mark.asyncio
    async def test_finds_common_selector(self, intel):
        stub_txt(intel, {'google._domainkey.evil.com': [DKIM_KEY]})
        result = await intel.check_dkim('evil.com')
        assert result['selectors'] == ['google']

    @pytest.mark.asyncio
    async def test_finds_multiple_selectors(self, intel):
        stub_txt(intel, {
            'selector1._domainkey.evil.com': [DKIM_KEY],
            'selector2._domainkey.evil.com': [DKIM_KEY],
        })
        assert set((await intel.check_dkim('evil.com'))['selectors']) == {
            'selector1', 'selector2'
        }

    @pytest.mark.asyncio
    async def test_absent_returns_none(self, intel):
        stub_txt(intel, {})
        assert await intel.check_dkim('evil.com') is None

    @pytest.mark.asyncio
    async def test_can_be_disabled(self, intel):
        """DKIM probing costs one query per selector; it is opt-out."""
        intel.config.enable_dkim_probe = False
        stub_txt(intel, {'google._domainkey.evil.com': [DKIM_KEY]})
        assert await intel.check_dkim('evil.com') is None

    @pytest.mark.asyncio
    async def test_custom_selectors_are_used(self, intel):
        intel.config.dkim_selectors = ['corp2024']
        stub_txt(intel, {'corp2024._domainkey.evil.com': [DKIM_KEY]})
        assert (await intel.check_dkim('evil.com'))['selectors'] == ['corp2024']


class TestPostureClassification:
    @pytest.mark.parametrize('spf,dmarc,dkim,mx,expected', [
        (None, None, None, False, 'none'),
        (None, None, None, True, 'receive-only'),
        ({'present': True}, None, None, False, 'partial'),
        ({'present': True}, {'policy': 'none'}, None, False, 'provisioned'),
        ({'present': True}, {'policy': 'none'}, {'present': True}, True, 'provisioned'),
        ({'present': True}, {'policy': 'reject'}, {'present': True}, True, 'hardened'),
        ({'present': True}, {'policy': 'quarantine'}, {'present': True}, True, 'hardened'),
    ])
    def test_classification(self, spf, dmarc, dkim, mx, expected):
        assert classify_mail_posture(spf, dmarc, dkim, mx) == expected


class TestMailScoring:
    def test_no_data_scores_zero(self):
        assert score_mail_capability(None) == 0
        assert score_mail_capability({}) == 0

    def test_scores_rise_with_provisioning(self):
        scores = [
            score_mail_capability({'posture': p})
            for p in ('none', 'receive-only', 'partial', 'provisioned', 'hardened')
        ]
        assert scores == sorted(scores)
        assert scores[0] == 0

    def test_send_capable_outweighs_receive_only(self):
        """Receiving mail is passive; sending it is the phishing prerequisite."""
        assert (score_mail_capability({'posture': 'provisioned'})
                > score_mail_capability({'posture': 'receive-only'}) * 3)

    def test_bulk_sender_adds_points(self):
        plain = score_mail_capability({'posture': 'provisioned'})
        bulk = score_mail_capability({
            'posture': 'provisioned', 'spf': {'includes': ['sendgrid.net']}
        })
        assert bulk > plain

    def test_score_is_capped(self):
        assert score_mail_capability({
            'posture': 'hardened', 'spf': {'includes': ['a', 'b', 'c']}
        }) <= 25


class TestAnalyze:
    @pytest.mark.asyncio
    async def test_full_stack_is_hardened(self, intel):
        stub_txt(intel, {
            'evil.com': [SPF_WITH_PROVIDER],
            '_dmarc.evil.com': [DMARC_REJECT],
            'google._domainkey.evil.com': [DKIM_KEY],
        })
        report = await intel.analyze('evil.com', has_mx=True)
        assert report['posture'] == 'hardened'
        assert report['can_send'] is True
        assert report['can_receive'] is True

    @pytest.mark.asyncio
    async def test_bare_domain_has_no_mail_capability(self, intel):
        stub_txt(intel, {})
        report = await intel.analyze('parked.com', has_mx=False)
        assert report['posture'] == 'none'
        assert report['can_send'] is False

    @pytest.mark.asyncio
    async def test_mx_without_spf_is_receive_only(self, intel):
        stub_txt(intel, {})
        report = await intel.analyze('evil.com', has_mx=True)
        assert report['posture'] == 'receive-only'


class TestResolverAvailability:
    def test_missing_dnspython_degrades_quietly(self, config, monkeypatch):
        """The scan must continue without DNS intelligence, not crash."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **k):
            if name.startswith('dns.'):
                raise ImportError('no dnspython')
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, '__import__', fake_import)
        assert DNSIntelligence(config)._get_resolver() is None

    @pytest.mark.asyncio
    async def test_query_without_resolver_reports_failure(self, config, monkeypatch):
        """No resolver is a failed lookup, not a domain with no records."""
        intel = DNSIntelligence(config)
        monkeypatch.setattr(intel, '_get_resolver', lambda: None)
        assert await intel._query_txt('evil.com') == ([], False)


class TestPublicSuffixSplitting:
    """The PSL replaced a hardcoded list that covered ~40 of several thousand."""

    @pytest.mark.parametrize('domain,expected', [
        ('example.com', ('example', 'com')),
        ('example.co.uk', ('example', 'co.uk')),
        ('example.com.br', ('example', 'com.br')),
        ('example.com.au', ('example', 'com.au')),
        ('shop.example.org', ('example', 'org')),
        # Private suffixes the old hardcoded tuple got wrong
        ('example.github.io', ('example', 'github.io')),
    ])
    def test_split(self, domain, expected):
        from typo_sniper.enhanced_detection import ComboSquattingDetector

        assert ComboSquattingDetector.split_domain(domain) == expected

    def test_combosquats_stay_in_the_right_namespace(self):
        from typo_sniper.enhanced_detection import ComboSquattingDetector

        variants = ComboSquattingDetector.generate_combosquats(
            'example.com.br', ['login']
        )
        assert all(v.endswith('.com.br') for v in variants)


class TestCustomKeywords:
    def test_custom_keywords_are_included(self, config):
        from typo_sniper.enhanced_detection import generate_enhanced_permutations

        config.enable_combosquatting = True
        config.custom_keywords = ['vault']
        result = generate_enhanced_permutations('acme.com', config)
        assert 'acme-vault.com' in result
        assert 'acme-login.com' in result  # defaults still present

    def test_replace_mode_uses_only_custom_keywords(self, config):
        from typo_sniper.enhanced_detection import generate_enhanced_permutations

        config.enable_combosquatting = True
        config.custom_keywords = ['vault']
        config.replace_default_keywords = True
        result = generate_enhanced_permutations('acme.com', config)
        assert 'acme-vault.com' in result
        assert 'acme-login.com' not in result


class TestLookupFailureIsNotAFinding:
    """
    A failed DNS lookup must never be reported as "no mail capability".

    This is the same class of bug as treating a WHOIS timeout as "no
    registration date": a silent failure dressed up as a finding. It surfaced
    for real during development, where large TXT responses needing TCP were
    reported as domains having no SPF at all.
    """

    @pytest.mark.asyncio
    async def test_failed_lookup_yields_unknown_posture(self, intel):
        stub_txt(intel, {}, ok=False)
        report = await intel.analyze('evil.com', has_mx=False)
        assert report['posture'] == 'unknown'
        assert report['lookup_failed'] is True
        assert report['can_send'] is None  # not False

    @pytest.mark.asyncio
    async def test_successful_lookup_with_no_records_is_a_real_finding(self, intel):
        stub_txt(intel, {}, ok=True)
        report = await intel.analyze('parked.com', has_mx=False)
        assert report['posture'] == 'none'
        assert report['lookup_failed'] is False
        assert report['can_send'] is False

    @pytest.mark.asyncio
    async def test_spf_check_signals_failure(self, intel):
        stub_txt(intel, {}, ok=False)
        assert (await intel.check_spf('evil.com')) == {'unknown': True}

    @pytest.mark.asyncio
    async def test_dmarc_check_signals_failure(self, intel):
        stub_txt(intel, {}, ok=False)
        assert (await intel.check_dmarc('evil.com')) == {'unknown': True}

    def test_unknown_posture_scores_zero(self):
        """Neither credit nor penalty for something we could not measure."""
        assert score_mail_capability({'posture': 'unknown'}) == 0

    def test_unknown_is_reported_not_left_blank(self):
        from typo_sniper.exporters import format_threat_intel

        out = format_threat_intel({'mail_intel': {'posture': 'unknown'}})
        assert out['mail'] == 'Lookup failed'
