"""End-to-end scan pipeline tests with dnstwist and WHOIS stubbed out."""

import copy
from datetime import date, timedelta

import pytest

from typo_sniper.cache import Cache
from typo_sniper.scanner import DomainScanner

RECENT = (date.today() - timedelta(days=7)).isoformat()
OLD = (date.today() - timedelta(days=2500)).isoformat()

# What dnstwist returns, including the resolver-error sentinels that used to be
# counted as registrations and the *original entry for the monitored domain.
DNSTWIST_OUTPUT = [
    {'fuzzer': '*original', 'domain': 'example.com', 'dns_a': ['93.184.216.34']},
    {'fuzzer': 'omission', 'domain': 'exampe.com',
     'dns_a': ['203.0.113.1'], 'dns_mx': ['mail.exampe.com']},
    {'fuzzer': 'addition', 'domain': 'examplea.com', 'dns_a': ['203.0.113.2']},
    {'fuzzer': 'bitsquatting', 'domain': 'egample.com', 'dns_a': ['!ServFail']},
    {'fuzzer': 'homoglyph', 'domain': 'exarnple.com', 'dns_a': ['!NXDOMAIN']},
    {'fuzzer': 'insertion', 'domain': 'exzample.com', 'dns_a': []},
]

WHOIS_DATA = {
    'exampe.com': {'whois_created': [RECENT], 'whois_registrar': 'Fly By Night'},
    'examplea.com': {'whois_created': [OLD], 'whois_registrar': 'Old Reliable'},
}


@pytest.fixture
def scanner(config, tmp_path, monkeypatch):
    config.enable_urlscan = False
    config.enable_certificate_transparency = False
    config.enable_http_probe = False
    config.rate_limit_delay = 0

    s = DomainScanner(config, Cache(tmp_path / 'cache'))
    monkeypatch.setattr(s, '_run_dnstwist', lambda domain: copy.deepcopy(DNSTWIST_OUTPUT))
    monkeypatch.setattr(s, '_whois_lookup', lambda domain: dict(WHOIS_DATA.get(domain, {})))

    # Exercise the WHOIS path deterministically. Leaving RDAP live made these
    # tests depend on whether the environment could reach real registries:
    # they passed where RDAP was blocked and failed where it resolved.
    async def no_rdap(perms):
        return {p['domain'] for p in perms}

    monkeypatch.setattr(s, '_enrich_with_rdap', no_rdap)

    yield s
    s.close()


class TestScanDomain:
    @pytest.mark.asyncio
    async def test_only_resolving_permutations_are_reported(self, scanner):
        result = await scanner.scan_domain('example.com')
        assert sorted(p['domain'] for p in result['permutations']) == [
            'exampe.com', 'examplea.com'
        ]

    @pytest.mark.asyncio
    async def test_counts_exclude_the_original_and_sentinels(self, scanner):
        result = await scanner.scan_domain('example.com')
        assert result['registered_count'] == 2
        assert result['total_permutations'] == 5  # 6 minus the *original entry

    @pytest.mark.asyncio
    async def test_recency_is_computed_without_the_months_filter(self, scanner):
        """is_recent used to be set only when --months was passed."""
        result = await scanner.scan_domain('example.com')
        by_name = {p['domain']: p for p in result['permutations']}
        assert by_name['exampe.com']['is_recent'] is True
        assert by_name['examplea.com']['is_recent'] is False
        assert by_name['exampe.com']['created_days_ago'] == 7

    @pytest.mark.asyncio
    async def test_recent_domain_with_mail_outranks_an_old_one(self, scanner):
        result = await scanner.scan_domain('example.com')
        # Results are sorted by descending risk
        assert result['permutations'][0]['domain'] == 'exampe.com'
        assert (result['permutations'][0]['risk_score']
                > result['permutations'][1]['risk_score'])

    @pytest.mark.asyncio
    async def test_whois_counters_are_reported(self, scanner):
        result = await scanner.scan_domain('example.com')
        assert result['whois_succeeded'] == 2
        assert result['whois_failed'] == 0

    @pytest.mark.asyncio
    async def test_months_filter_narrows_results(self, scanner):
        scanner.config.months_filter = 3
        result = await scanner.scan_domain('example.com')
        assert [p['domain'] for p in result['permutations']] == ['exampe.com']
        assert result['filtered_count'] == 1

    @pytest.mark.asyncio
    async def test_whois_failure_is_recorded_not_hidden(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, '_whois_lookup', lambda domain: {})
        result = await scanner.scan_domain('example.com')
        assert result['whois_succeeded'] == 0
        assert result['whois_failed'] == 2
        assert all('created_days_ago' not in p for p in result['permutations'])

    @pytest.mark.asyncio
    async def test_dnstwist_failure_yields_an_empty_result(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, '_run_dnstwist', lambda domain: [])
        result = await scanner.scan_domain('example.com')
        assert result['registered_count'] == 0
        assert result['permutations'] == []

    @pytest.mark.asyncio
    async def test_dns_lists_are_cleaned_of_sentinels(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, '_run_dnstwist', lambda domain: [
            {'fuzzer': 'x', 'domain': 'a.com',
             'dns_a': ['203.0.113.9', '!Timeout'], 'dns_mx': ['!ServFail']},
        ])
        result = await scanner.scan_domain('example.com')
        perm = result['permutations'][0]
        assert perm['dns_a'] == ['203.0.113.9']
        assert perm['dns_mx'] == []

    @pytest.mark.asyncio
    async def test_soundalike_flag_is_applied_when_enabled(self, scanner):
        scanner.config.enable_soundalike = True
        result = await scanner.scan_domain('example.com')
        assert all('sounds_alike' in p for p in result['permutations'])

    @pytest.mark.asyncio
    async def test_whois_results_are_cached(self, scanner, tmp_path):
        scanner.config.use_cache = True
        await scanner.scan_domain('example.com')
        assert scanner.cache.get('whois:exampe.com') == WHOIS_DATA['exampe.com']


class TestRegistrationSourceSelection:
    """RDAP is tried first; WHOIS covers registries that publish no endpoint."""

    @pytest.fixture
    def scanner(self, config, tmp_path, monkeypatch):
        s = DomainScanner(config, Cache(tmp_path / 'cache'))
        monkeypatch.setattr(s, '_run_dnstwist',
                            lambda domain: copy.deepcopy(DNSTWIST_OUTPUT))
        yield s
        s.close()

    @pytest.mark.asyncio
    async def test_rdap_success_skips_whois(self, scanner, monkeypatch):
        whois_calls = []

        async def rdap_resolves_all(perms):
            for p in perms:
                p.update({'whois_created': [RECENT], 'registration_source': 'rdap'})
                scanner.lookup_sources['rdap'] += 1
                scanner.whois_succeeded += 1
            return set()

        monkeypatch.setattr(scanner, '_enrich_with_rdap', rdap_resolves_all)
        monkeypatch.setattr(scanner, '_whois_lookup',
                            lambda d: whois_calls.append(d) or {})

        result = await scanner.scan_domain('example.com')

        assert whois_calls == []
        assert result['lookup_sources']['rdap'] == 2
        assert all(p['registration_source'] == 'rdap'
                   for p in result['permutations'])

    @pytest.mark.asyncio
    async def test_whois_covers_what_rdap_cannot(self, scanner, monkeypatch):
        async def rdap_resolves_one(perms):
            perms[0].update({'whois_created': [RECENT], 'registration_source': 'rdap'})
            scanner.lookup_sources['rdap'] += 1
            scanner.whois_succeeded += 1
            return {p['domain'] for p in perms[1:]}

        monkeypatch.setattr(scanner, '_enrich_with_rdap', rdap_resolves_one)
        monkeypatch.setattr(
            scanner, '_whois_lookup',
            lambda d: {'whois_created': [OLD], 'whois_registrar': 'Fallback Registrar'},
        )

        result = await scanner.scan_domain('example.com')
        sources = {p['domain']: p.get('registration_source')
                   for p in result['permutations']}

        assert 'rdap' in sources.values()
        assert 'whois' in sources.values()

    @pytest.mark.asyncio
    async def test_fallback_can_be_disabled(self, scanner, monkeypatch):
        """--no-whois-fallback must not silently fall through."""
        scanner.config.whois_fallback = False
        whois_calls = []

        async def rdap_resolves_nothing(perms):
            return {p['domain'] for p in perms}

        monkeypatch.setattr(scanner, '_enrich_with_rdap', rdap_resolves_nothing)
        monkeypatch.setattr(scanner, '_whois_lookup',
                            lambda d: whois_calls.append(d) or {})

        await scanner.scan_domain('example.com')
        assert whois_calls == []

    @pytest.mark.asyncio
    async def test_rdap_disabled_uses_whois_only(self, scanner, monkeypatch):
        scanner.config.use_rdap = False
        rdap_calls = []

        async def should_not_run(perms):
            rdap_calls.append(perms)
            return set()

        monkeypatch.setattr(scanner, '_enrich_with_rdap', should_not_run)
        monkeypatch.setattr(scanner, '_whois_lookup',
                            lambda d: {'whois_created': [OLD]})

        result = await scanner.scan_domain('example.com')
        assert rdap_calls == []
        assert result['lookup_sources']['whois'] == 2
