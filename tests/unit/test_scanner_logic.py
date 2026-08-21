"""Tests for scanner result processing that does not require network access."""

from datetime import date, timedelta

import pytest

from cache import Cache
from scanner import DomainScanner


@pytest.fixture
def scanner(config, tmp_path):
    s = DomainScanner(config, Cache(tmp_path / 'cache'))
    yield s
    s.close()


class TestMergePermutations:
    def test_drops_the_original_domain(self):
        """The monitored domain is the asset, not a typosquat."""
        perms = [
            {'domain': 'example.com', 'fuzzer': '*original', 'dns_a': ['1.1.1.1']},
            {'domain': 'exarnple.com', 'fuzzer': 'homoglyph', 'dns_a': ['2.2.2.2']},
        ]
        merged = DomainScanner._merge_permutations(None, 'example.com', perms, [])
        assert [p['domain'] for p in merged] == ['exarnple.com']

    def test_deduplicates_across_sources(self):
        dnstwist = [{'domain': 'exa.com', 'fuzzer': 'omission', 'dns_a': ['1.1.1.1']}]
        enhanced = [{'domain': 'exa.com', 'fuzzer': 'enhanced', 'dns_a': ['1.1.1.1']}]
        merged = DomainScanner._merge_permutations(None, 'example.com', dnstwist, enhanced)
        assert len(merged) == 1
        # The dnstwist entry carries richer DNS data and must win
        assert merged[0]['fuzzer'] == 'omission'

    def test_is_case_insensitive(self):
        perms = [
            {'domain': 'Exa.com', 'fuzzer': 'a'},
            {'domain': 'exa.com', 'fuzzer': 'b'},
        ]
        merged = DomainScanner._merge_permutations(None, 'example.com', perms, [])
        assert len(merged) == 1


class TestParseIsoDate:
    @pytest.mark.parametrize('value,expected', [
        ('2026-01-15', date(2026, 1, 15)),
        ('2026-01-15T10:30:00', date(2026, 1, 15)),
        ('2026-01-15 10:30:00', date(2026, 1, 15)),
        ('15-Jan-2026', date(2026, 1, 15)),
        ('2026.01.15', date(2026, 1, 15)),
    ])
    def test_parses_common_whois_formats(self, value, expected):
        assert DomainScanner._parse_iso_date(value) == expected

    @pytest.mark.parametrize('value', ['not a date', '', None, 42, 'before 1990'])
    def test_returns_none_for_unparseable(self, value):
        assert DomainScanner._parse_iso_date(value) is None


class TestRegistrationAge:
    def test_sets_age_and_recent_flag(self, scanner):
        recent = (date.today() - timedelta(days=10)).isoformat()
        perm = {'domain': 'x.com', 'whois_created': [recent]}
        scanner._annotate_registration_age(perm)
        assert perm['created_days_ago'] == 10
        assert perm['is_recent'] is True

    def test_old_domain_is_not_recent(self, scanner):
        old = (date.today() - timedelta(days=1000)).isoformat()
        perm = {'domain': 'x.com', 'whois_created': [old]}
        scanner._annotate_registration_age(perm)
        assert perm['created_days_ago'] == 1000
        assert perm['is_recent'] is False

    def test_recency_window_is_configurable(self, scanner):
        scanner.config.recent_days = 5
        perm = {'domain': 'x.com',
                'whois_created': [(date.today() - timedelta(days=10)).isoformat()]}
        scanner._annotate_registration_age(perm)
        assert perm['is_recent'] is False

    def test_uses_earliest_creation_date(self, scanner):
        """Registrars sometimes report several dates; the first registration wins."""
        perm = {'domain': 'x.com', 'whois_created': ['2020-06-01', '2015-01-01']}
        scanner._annotate_registration_age(perm)
        expected = (date.today() - date(2015, 1, 1)).days
        assert perm['created_days_ago'] == expected

    def test_missing_whois_leaves_age_unset(self, scanner):
        perm = {'domain': 'x.com'}
        scanner._annotate_registration_age(perm)
        assert 'created_days_ago' not in perm


class TestDateFilter:
    def test_keeps_only_recent_domains(self, scanner):
        perms = [
            {'domain': 'new.com', 'created_days_ago': 20},
            {'domain': 'old.com', 'created_days_ago': 400},
        ]
        kept = scanner._filter_by_date(perms, months=3)
        assert [p['domain'] for p in kept] == ['new.com']

    def test_excludes_domains_with_unknown_age(self, scanner):
        """Without a creation date, recency cannot be proven either way."""
        kept = scanner._filter_by_date([{'domain': 'unknown.com'}], months=3)
        assert kept == []


class TestWhoisCircuitBreaker:
    def test_opens_after_repeated_failures(self, scanner, monkeypatch):
        monkeypatch.setattr(
            scanner, '_whois_query',
            lambda domain: (_ for _ in ()).throw(TimeoutError('blocked')),
        )
        scanner.config.whois_retry_delay = 0

        for i in range(DomainScanner.WHOIS_FAILURE_THRESHOLD):
            assert scanner._whois_lookup(f'd{i}.com') == {}

        assert scanner._whois_circuit_open is True

    def test_recovers_after_a_success(self, scanner, monkeypatch):
        scanner._whois_circuit_open = True
        scanner._whois_consecutive_failures = 20
        monkeypatch.setattr(scanner, '_whois_query', lambda domain: {'whois_org': 'ok'})

        assert scanner._whois_lookup('good.com') == {'whois_org': 'ok'}
        assert scanner._whois_circuit_open is False
        assert scanner._whois_consecutive_failures == 0
