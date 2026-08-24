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


class TestCertificateHandling:
    """Certificates are always validated; a failure is recorded, not bypassed."""

    @pytest.mark.asyncio
    async def test_rejected_certificate_is_reported_not_retried(self, intel):
        """A cert failure must never trigger an unverified refetch."""
        import ssl as ssl_mod

        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=ssl_mod.SSLError('bad cert'))
        ctx.__aexit__ = AsyncMock(return_value=False)

        calls = []
        session = MagicMock()
        session.get = MagicMock(side_effect=lambda *a, **k: (calls.append(k), ctx)[1])
        intel.session = session

        result = await intel._probe_scheme('https://evil.com')

        assert result['tls_verified'] is False
        assert result['title'] is None       # no body read over an unverified channel
        assert len(calls) == 1               # exactly one attempt, no insecure retry
        # Verification is never disabled on any call
        assert all(c.get('ssl') is None for c in calls)

    @pytest.mark.asyncio
    async def test_unreachable_host_returns_none(self, intel):
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=OSError('connection refused'))
        ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get = MagicMock(return_value=ctx)
        intel.session = session

        assert await intel._probe_scheme('https://evil.com') is None

    @pytest.mark.asyncio
    async def test_plain_http_has_no_tls_verdict(self, intel):
        response = MagicMock()
        response.status = 200
        response.history = None
        response.url = 'http://evil.com'
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=response)
        ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get = MagicMock(return_value=ctx)
        intel.session = session
        intel._read_title = AsyncMock(return_value=None)

        result = await intel._probe_scheme('http://evil.com')
        assert result['tls_verified'] is None
