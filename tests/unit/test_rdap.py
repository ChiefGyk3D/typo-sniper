"""Tests for the RDAP client and response parsing.

Fixtures mirror real registry responses (RFC 7483 domain objects, RFC 7095
jCards). Live RDAP endpoints are not contacted.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from typo_sniper.rdap import RDAPClient

# A representative registry response: Verisign/PIR-style domain object
DOMAIN_RESPONSE = {
    "objectClassName": "domain",
    "ldhName": "eff.org",
    "status": ["client transfer prohibited", "server delete prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1990-10-10T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-10-09T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2025-09-08T18:22:11Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "MarkMonitor Inc."],
                ],
            ],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["email", {}, "text", "abuse@markmonitor.com"],
                        ],
                    ],
                }
            ],
        },
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Jane Doe"],
                    ["org", {}, "text", "Electronic Frontier Foundation"],
                    ["email", {}, "text", "hostmaster@eff.org"],
                    [
                        "adr",
                        {},
                        "text",
                        ["", "", "815 Eddy St", "San Francisco", "CA", "94109", "US"],
                    ],
                ],
            ],
        },
    ],
    "nameservers": [
        {"ldhName": "NS1.EFF.ORG"},
        {"ldhName": "NS2.EFF.ORG."},
    ],
}

BOOTSTRAP_RESPONSE = {
    "version": "1.0",
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]],
        [["co.uk"], ["https://rdap.nominet.uk/uk/"]],
        # Some entries list http before https; https must win
        [["dev"], ["http://rdap.example/", "https://rdap.example/"]],
    ],
}


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status = status
        self._payload = payload
        self.headers = {'Content-Type': 'application/rdap+json'}

    async def json(self, content_type=None):
        if self._payload is None:
            raise ValueError('no json')
        return self._payload

    async def text(self):
        return ''


def make_session(response):
    """Build a mock aiohttp session whose GET yields `response`."""
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=response)
    ctx.__aexit__ = AsyncMock(return_value=False)
    session = MagicMock()
    session.get = MagicMock(return_value=ctx)
    return session


@pytest.fixture
def client(config):
    return RDAPClient(make_session(FakeResponse(payload=BOOTSTRAP_RESPONSE)), config)


class TestParseDomainResponse:
    @pytest.fixture
    def parsed(self):
        return RDAPClient.parse(DOMAIN_RESPONSE)

    def test_extracts_registration_dates(self, parsed):
        assert parsed['whois_created'] == ['1990-10-10']
        assert parsed['whois_expires'] == ['2030-10-09']
        assert parsed['whois_updated'] == ['2025-09-08']

    def test_extracts_registrar(self, parsed):
        assert parsed['whois_registrar'] == 'MarkMonitor Inc.'

    def test_extracts_registrant_and_org(self, parsed):
        assert parsed['whois_registrant'] == 'Jane Doe'
        assert parsed['whois_org'] == 'Electronic Frontier Foundation'

    def test_extracts_country_from_jcard_address(self, parsed):
        assert parsed['whois_country'] == 'US'

    def test_collects_emails_including_nested_abuse_contact(self, parsed):
        assert 'hostmaster@eff.org' in parsed['whois_emails']
        assert 'abuse@markmonitor.com' in parsed['whois_emails']

    def test_normalises_nameservers(self, parsed):
        """Lowercased with the root trailing dot removed."""
        assert parsed['whois_name_servers'] == ['ns1.eff.org', 'ns2.eff.org']

    def test_records_its_source(self, parsed):
        """Reports must be able to say where registration data came from."""
        assert parsed['registration_source'] == 'rdap'

    def test_preserves_status_codes(self, parsed):
        assert 'client transfer prohibited' in parsed['whois_status']

    def test_output_matches_the_whois_key_shape(self, parsed):
        """Exporters and scoring must not care which source answered."""
        for key in (
            'whois_created', 'whois_updated', 'whois_expires', 'whois_registrant',
            'whois_org', 'whois_registrar', 'whois_emails', 'whois_name_servers',
            'whois_status', 'whois_country',
        ):
            assert key in parsed


class TestParseEdgeCases:
    def test_empty_response(self):
        parsed = RDAPClient.parse({})
        assert parsed['whois_created'] == []
        assert parsed['whois_registrar'] is None

    def test_missing_vcard(self):
        parsed = RDAPClient.parse({'entities': [{'roles': ['registrar']}]})
        assert parsed['whois_registrar'] is None

    def test_registrar_falls_back_to_iana_id(self):
        parsed = RDAPClient.parse({
            'entities': [{
                'roles': ['registrar'],
                'publicIds': [{'identifier': '292'}],
            }]
        })
        assert parsed['whois_registrar'] == 'IANA 292'

    def test_malformed_events_are_skipped(self):
        parsed = RDAPClient.parse({
            'events': [
                'not a dict',
                {'eventAction': 'registration'},
                {'eventDate': '2020-01-01T00:00:00Z'},
                {'eventAction': 'registration', 'eventDate': 'not-a-date'},
                {'eventAction': 'registration', 'eventDate': '2020-01-01T00:00:00Z'},
            ]
        })
        assert parsed['whois_created'] == ['2020-01-01']

    def test_status_string_is_wrapped(self):
        parsed = RDAPClient.parse({'status': 'active'})
        assert parsed['whois_status'] == ['active']

    def test_org_given_as_list(self):
        parsed = RDAPClient.parse({
            'entities': [{
                'roles': ['registrant'],
                'vcardArray': ['vcard', [['org', {}, 'text', ['Acme', 'Security']]]],
            }]
        })
        assert parsed['whois_org'] == 'Acme Security'

    @pytest.mark.parametrize('value,expected', [
        ('2024-03-05T12:00:00Z', '2024-03-05'),
        ('2024-03-05T12:00:00+00:00', '2024-03-05'),
        ('2024-03-05', '2024-03-05'),
        ('garbage', None),
        (None, None),
        (12345, None),
    ])
    def test_timestamp_parsing(self, value, expected):
        assert RDAPClient._parse_timestamp(value) == expected

    def test_timezone_is_normalised_to_utc(self):
        """A late-evening local time must not roll the date backwards."""
        assert RDAPClient._parse_timestamp('2024-03-05T23:30:00-05:00') == '2024-03-06'


class TestBootstrap:
    @pytest.mark.asyncio
    async def test_indexes_tlds(self, client):
        mapping = await client._load_bootstrap()
        assert mapping['com'] == 'https://rdap.verisign.com/com/v1/'
        assert mapping['org'] == 'https://rdap.publicinterestregistry.org/rdap/'

    @pytest.mark.asyncio
    async def test_prefers_https_endpoints(self, client):
        mapping = await client._load_bootstrap()
        assert mapping['dev'].startswith('https://')

    @pytest.mark.asyncio
    async def test_is_fetched_only_once(self, client):
        await client._load_bootstrap()
        await client._load_bootstrap()
        assert client.session.get.call_count == 1

    @pytest.mark.asyncio
    async def test_endpoint_resolution(self, client):
        assert await client.endpoint_for('example.com') == 'https://rdap.verisign.com/com/v1/'
        assert await client.endpoint_for('sub.example.org') is not None

    @pytest.mark.asyncio
    async def test_multi_label_suffix_wins_over_bare_tld(self, client):
        """co.uk must route to Nominet, not to a generic .uk service."""
        assert await client.endpoint_for('example.co.uk') == 'https://rdap.nominet.uk/uk/'

    @pytest.mark.asyncio
    async def test_unknown_tld_has_no_endpoint(self, client):
        assert await client.endpoint_for('example.invalidtld') is None

    @pytest.mark.asyncio
    async def test_bootstrap_failure_degrades_quietly(self, config):
        """A blocked or failing IANA fetch must not break the scan."""
        client = RDAPClient(make_session(FakeResponse(status=403)), config)
        mapping = await client._load_bootstrap()
        # Falls back to the hardcoded extras rather than raising
        assert isinstance(mapping, dict)
        assert await client.endpoint_for('example.com') is None


class TestLookup:
    @pytest.mark.asyncio
    async def test_returns_parsed_data(self, config):
        client = RDAPClient(make_session(FakeResponse(payload=BOOTSTRAP_RESPONSE)), config)
        await client._load_bootstrap()
        client.session = make_session(FakeResponse(payload=DOMAIN_RESPONSE))

        result = await client.lookup('eff.org')
        assert result['whois_created'] == ['1990-10-10']

    @pytest.mark.asyncio
    async def test_404_means_unregistered(self, config):
        client = RDAPClient(make_session(FakeResponse(payload=BOOTSTRAP_RESPONSE)), config)
        await client._load_bootstrap()
        client.session = make_session(FakeResponse(status=404))

        assert await client.lookup('nonexistent.com') is None

    @pytest.mark.asyncio
    async def test_no_endpoint_returns_none(self, config):
        client = RDAPClient(make_session(FakeResponse(payload=BOOTSTRAP_RESPONSE)), config)
        assert await client.lookup('example.invalidtld') is None

    @pytest.mark.asyncio
    async def test_network_failure_returns_none(self, config):
        client = RDAPClient(make_session(FakeResponse(payload=BOOTSTRAP_RESPONSE)), config)
        await client._load_bootstrap()

        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(side_effect=OSError('connection refused'))
        ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get = MagicMock(return_value=ctx)
        client.session = session

        assert await client.lookup('eff.org') is None
