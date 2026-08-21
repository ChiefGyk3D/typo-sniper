"""Tests for threat intelligence response handling."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from threat_intelligence import _TITLE_RE, ThreatIntelligence


class FakeResponse:
    """Minimal stand-in for an aiohttp response."""

    def __init__(self, status=200, json_data=None, content_type='application/json'):
        self.status = status
        self._json = json_data
        self.headers = {'Content-Type': content_type}

    async def json(self):
        if self._json is None:
            raise ValueError('no json')
        return self._json


@pytest.fixture
def intel(config):
    return ThreatIntelligence(config)


class TestTitleExtraction:
    @pytest.mark.parametrize('html,expected', [
        ('<title>Hello</title>', 'Hello'),
        ('<TITLE>Upper</TITLE>', 'Upper'),
        ('<title lang="en">Attrs</title>', 'Attrs'),
        ('<title>multi\nline</title>', 'multi\nline'),
    ])
    def test_matches_real_world_markup(self, html, expected):
        """The old pattern missed attributes and newlines."""
        assert _TITLE_RE.search(html).group(1) == expected

    def test_no_title(self):
        assert _TITLE_RE.search('<html><body>x</body></html>') is None


class TestCertificateTransparencyParsing:
    @pytest.mark.asyncio
    async def test_picks_the_newest_certificate(self, intel):
        certs = [
            {'common_name': 'old.com', 'not_before': '2020-01-01', 'issuer_name': 'A'},
            {'common_name': 'new.com', 'not_before': '2026-01-01', 'issuer_name': 'B'},
        ]
        out = await intel._parse_ct_response('x.com', FakeResponse(json_data=certs))
        assert out['certificates_found'] == 2
        assert out['most_recent']['common_name'] == 'new.com'

    @pytest.mark.asyncio
    async def test_deduplicates_names(self, intel):
        certs = [{'common_name': 'a.com', 'not_before': '2026-01-01'}] * 5
        out = await intel._parse_ct_response('x.com', FakeResponse(json_data=certs))
        assert out['all_names'] == ['a.com']

    @pytest.mark.asyncio
    async def test_html_error_page_is_not_treated_as_data(self, intel):
        out = await intel._parse_ct_response(
            'x.com', FakeResponse(content_type='text/html'))
        assert out == {'certificates_found': 0, 'status': 'no_certificates'}

    @pytest.mark.asyncio
    async def test_non_200_is_reported(self, intel):
        out = await intel._parse_ct_response('x.com', FakeResponse(status=503))
        assert out['status'] == 'http_503'

    @pytest.mark.asyncio
    async def test_empty_result(self, intel):
        out = await intel._parse_ct_response('x.com', FakeResponse(json_data=[]))
        assert out['certificates_found'] == 0


class TestValidationCaching:
    @pytest.mark.asyncio
    async def test_key_is_validated_only_once_per_process(self, config):
        config.enable_urlscan = True
        config.urlscan_api_key = 'cached-test-key'
        ThreatIntelligence._validated_keys.discard('cached-test-key')

        calls = []

        def make(ti):
            session = MagicMock()
            ctx = MagicMock()
            ctx.__aenter__ = AsyncMock(return_value=FakeResponse(status=200))
            ctx.__aexit__ = AsyncMock(return_value=False)
            session.get = MagicMock(side_effect=lambda *a, **k: (calls.append(1), ctx)[1])
            ti.session = session
            return ti

        await make(ThreatIntelligence(config)).validate_api_keys()
        await make(ThreatIntelligence(config)).validate_api_keys()

        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_missing_key_raises(self, config):
        config.enable_urlscan = True
        config.urlscan_api_key = None
        with pytest.raises(ValueError, match='API key is not set'):
            await ThreatIntelligence(config).validate_api_keys()

    @pytest.mark.asyncio
    async def test_disabled_urlscan_skips_validation(self, config):
        config.enable_urlscan = False
        await ThreatIntelligence(config).validate_api_keys()


class TestHttpProbeDisabled:
    @pytest.mark.asyncio
    async def test_returns_none_when_disabled(self, config):
        config.enable_http_probe = False
        assert await ThreatIntelligence(config).http_probe('x.com') is None


class TestAnalyzeDomain:
    @pytest.mark.asyncio
    async def test_all_sources_disabled_still_returns_a_report(self, config):
        config.enable_urlscan = False
        config.enable_certificate_transparency = False
        config.enable_http_probe = False

        report = await ThreatIntelligence(config).analyze_domain('x.com')
        assert report['domain'] == 'x.com'
        assert report['urlscan'] is None
        # Timestamp must be timezone-aware (utcnow() was deprecated)
        assert datetime.fromisoformat(report['timestamp']).tzinfo is not None


class TestTlsProbeFallback:
    """The probe validates certificates first and records the outcome."""

    @pytest.mark.asyncio
    async def test_verified_https_is_marked_verified(self, intel, monkeypatch):
        calls = []

        async def fake_fetch(url, verify_tls):
            calls.append(verify_tls)
            return {'status': 200, 'redirects_to': None, 'title': None}

        monkeypatch.setattr(intel, '_fetch', fake_fetch)
        result = await intel._probe_scheme('https://evil.com')

        assert result['tls_verified'] is True
        assert calls == [True]  # no unverified retry when the first attempt works

    @pytest.mark.asyncio
    async def test_falls_back_unverified_and_flags_it(self, intel, monkeypatch):
        calls = []

        async def fake_fetch(url, verify_tls):
            calls.append(verify_tls)
            if verify_tls:
                return None
            return {'status': 200, 'redirects_to': None, 'title': None}

        monkeypatch.setattr(intel, '_fetch', fake_fetch)
        result = await intel._probe_scheme('https://evil.com')

        assert result['tls_verified'] is False
        assert calls == [True, False]

    @pytest.mark.asyncio
    async def test_fallback_can_be_disabled(self, intel, monkeypatch):
        intel.config.http_allow_invalid_certs = False
        calls = []

        async def fake_fetch(url, verify_tls):
            calls.append(verify_tls)
            return None

        monkeypatch.setattr(intel, '_fetch', fake_fetch)

        assert await intel._probe_scheme('https://evil.com') is None
        assert calls == [True]  # never retried without verification

    @pytest.mark.asyncio
    async def test_plain_http_is_not_retried(self, intel, monkeypatch):
        calls = []

        async def fake_fetch(url, verify_tls):
            calls.append(verify_tls)
            return None

        monkeypatch.setattr(intel, '_fetch', fake_fetch)

        assert await intel._probe_scheme('http://evil.com') is None
        assert calls == [True]
