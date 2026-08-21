"""Tests for domain validation, DNS sentinel handling, and output sanitisation."""

import pytest

from utils import (
    clean_dns_records,
    is_registered,
    parse_fuzzer_name,
    safe_url,
    sanitize_filename,
    sanitize_spreadsheet_value,
    truncate_string,
    validate_domain,
)


class TestValidateDomain:
    @pytest.mark.parametrize('domain', [
        'example.com',
        'sub.example.com',
        'example.co.uk',
        'xn--bcher-kva.de',       # punycode
        'a-b.example.org',
        'EXAMPLE.COM',
    ])
    def test_accepts_valid(self, domain):
        assert validate_domain(domain) is True

    @pytest.mark.parametrize('domain', [
        '',
        'localhost',              # single label
        'example',
        '-bad.com',               # label starts with hyphen
        'bad-.com',               # label ends with hyphen
        'example..com',           # empty label
        'example.123',            # numeric TLD
        'exa mple.com',           # space
        'a' * 64 + '.com',        # label over 63 chars
        ('a' * 60 + '.') * 5 + 'com',  # over 253 chars total
        None,
    ])
    def test_rejects_invalid(self, domain):
        assert validate_domain(domain) is False

    def test_accepts_unicode_idn(self):
        assert validate_domain('bücher.de') is True


class TestCleanDnsRecords:
    def test_strips_dnstwist_error_sentinels(self):
        assert clean_dns_records(['!ServFail']) == []
        assert clean_dns_records(['!NXDOMAIN', '!Timeout']) == []

    def test_keeps_real_addresses(self):
        assert clean_dns_records(['1.2.3.4', '!ServFail']) == ['1.2.3.4']

    def test_handles_scalar_and_empty(self):
        assert clean_dns_records('1.2.3.4') == ['1.2.3.4']
        assert clean_dns_records(None) == []
        assert clean_dns_records([]) == []


class TestIsRegistered:
    def test_sentinel_only_is_not_registered(self):
        """A resolver failure must never be counted as a registration."""
        assert is_registered({'dns_a': ['!ServFail']}) is False

    def test_real_address_is_registered(self):
        assert is_registered({'dns_a': ['93.184.216.34']}) is True

    def test_ipv6_only_is_registered(self):
        assert is_registered({'dns_aaaa': ['2606:2800::1']}) is True

    def test_no_records_is_not_registered(self):
        assert is_registered({'domain': 'x.com'}) is False


class TestSanitizeSpreadsheetValue:
    @pytest.mark.parametrize('payload', [
        '=cmd|" /C calc"!A0',
        '+1+1',
        '-1+1',
        '@SUM(1:9)',
        '\tinjected',
        '\rinjected',
    ])
    def test_neutralises_formula_prefixes(self, payload):
        result = sanitize_spreadsheet_value(payload)
        assert result.startswith("'")
        assert result[1:] == payload

    def test_leaves_normal_values_alone(self):
        assert sanitize_spreadsheet_value('Acme Corp') == 'Acme Corp'
        assert sanitize_spreadsheet_value('') == ''
        assert sanitize_spreadsheet_value(42) == 42
        assert sanitize_spreadsheet_value(None) is None


class TestSafeUrl:
    @pytest.mark.parametrize('url', [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'vbscript:msgbox(1)',
        'file:///etc/passwd',
        '',
        None,
        123,
    ])
    def test_rejects_dangerous_schemes(self, url):
        assert safe_url(url) is None

    def test_allows_http_and_https(self):
        assert safe_url('https://urlscan.io/result/x/') == 'https://urlscan.io/result/x/'
        assert safe_url('http://example.com') == 'http://example.com'


class TestMiscHelpers:
    def test_sanitize_filename(self):
        assert sanitize_filename('a/b:c*.txt') == 'a_b_c_.txt'
        assert sanitize_filename('...') == 'unnamed'
        assert len(sanitize_filename('x' * 300)) <= 200

    def test_truncate_string(self):
        assert truncate_string('hello', 10) == 'hello'
        assert truncate_string('x' * 20, 10) == 'x' * 7 + '...'

    def test_parse_fuzzer_name(self):
        assert parse_fuzzer_name('homoglyph') == 'Homoglyph'
        assert parse_fuzzer_name('unknown-code') == 'Unknown-Code'
