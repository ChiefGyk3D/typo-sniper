"""
RDAP (Registration Data Access Protocol) client.

RDAP is the IETF successor to WHOIS (RFC 7482/7483). It matters here for three
reasons:

  * It speaks HTTPS on port 443. Port 43, which WHOIS needs, is blocked on many
    corporate networks and in most CI sandboxes, where it fails as a silent
    timeout rather than a clear error.
  * It returns structured JSON with ISO-8601 timestamps, instead of free-form
    text whose date format varies per registry.
  * It is a normal HTTP request, so it shares the scanner's existing aiohttp
    session and concurrency limits rather than occupying a worker thread.

WHOIS remains available as a fallback for registries that do not publish an
RDAP endpoint.
"""

import asyncio
import logging
from datetime import date, datetime, timezone
from typing import Any

import aiohttp

# IANA's authoritative map of TLD -> RDAP service base URL (RFC 7484)
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Registries that do not publish to the IANA bootstrap file but do serve RDAP
EXTRA_ENDPOINTS = {
    'ai': 'https://rdap.identitydigital.services/rdap/',
    'io': 'https://rdap.identitydigital.services/rdap/',
    'sh': 'https://rdap.identitydigital.services/rdap/',
}


class RDAPClient:
    """Look up domain registration data over RDAP."""

    def __init__(self, session: aiohttp.ClientSession, config, cache=None):
        """
        Args:
            session: Shared aiohttp session
            config: Configuration object
            cache: Optional Cache for the bootstrap registry and lookups
        """
        self.session = session
        self.config = config
        self.cache = cache
        self.logger = logging.getLogger(__name__)
        self._bootstrap: dict[str, str] | None = None
        self._bootstrap_lock = asyncio.Lock()

    # -- bootstrap ---------------------------------------------------------

    async def _load_bootstrap(self) -> dict[str, str]:
        """
        Fetch and index IANA's TLD -> RDAP endpoint map.

        Returns:
            Mapping of lowercase TLD to RDAP base URL (trailing slash included)
        """
        async with self._bootstrap_lock:
            if self._bootstrap is not None:
                return self._bootstrap

            # The registry changes rarely; a cached copy avoids one request per run
            if self.cache:
                cached = self.cache.get('rdap:bootstrap')
                if cached and isinstance(cached, dict) and cached.get('map'):
                    self._bootstrap = cached['map']
                    return self._bootstrap

            mapping: dict[str, str] = {}
            try:
                timeout = aiohttp.ClientTimeout(total=self.config.rdap_timeout)
                async with self.session.get(BOOTSTRAP_URL, timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        for entry in data.get('services', []):
                            if len(entry) < 2:
                                continue
                            tlds, urls = entry[0], entry[1]
                            https = [u for u in urls if u.startswith('https://')]
                            base = (https or urls or [None])[0]
                            if not base:
                                continue
                            if not base.endswith('/'):
                                base += '/'
                            for tld in tlds:
                                mapping[tld.lower().lstrip('.')] = base
                    else:
                        self.logger.warning(
                            f"RDAP bootstrap returned HTTP {response.status}"
                        )
            except Exception as e:
                self.logger.warning(f"Could not load RDAP bootstrap registry: {e}")

            for tld, base in EXTRA_ENDPOINTS.items():
                mapping.setdefault(tld, base)

            self._bootstrap = mapping

            if self.cache and mapping:
                # Refreshed weekly: new TLDs appear rarely
                self.cache.set('rdap:bootstrap', {'map': mapping}, ttl=604800)

            self.logger.debug(f"RDAP bootstrap loaded: {len(mapping)} TLDs")
            return mapping

    async def endpoint_for(self, domain: str) -> str | None:
        """
        Resolve the RDAP base URL that serves a domain's TLD.

        Args:
            domain: Domain name

        Returns:
            Base URL, or None when the registry publishes no RDAP service
        """
        bootstrap = await self._load_bootstrap()
        labels = domain.lower().rstrip('.').split('.')

        # Try the longest suffix first so that multi-label registries
        # (e.g. "co.uk") win over the bare TLD when both are published.
        # The range must reach the final label, otherwise a plain
        # "example.com" never gets matched against the "com" entry.
        for i in range(len(labels)):
            suffix = '.'.join(labels[i:])
            if suffix in bootstrap:
                return bootstrap[suffix]

        return None

    # -- lookup ------------------------------------------------------------

    async def lookup(self, domain: str) -> dict[str, Any] | None:
        """
        Fetch registration data for a domain.

        Args:
            domain: Domain to look up

        Returns:
            Normalised registration dictionary, or None if RDAP could not
            answer (no endpoint, network failure, or an unregistered domain)
        """
        base = await self.endpoint_for(domain)
        if not base:
            self.logger.debug(f"No RDAP endpoint published for {domain}")
            return None

        url = f"{base}domain/{domain}"
        timeout = aiohttp.ClientTimeout(total=self.config.rdap_timeout)

        for attempt in range(2):
            try:
                async with self.session.get(
                    url,
                    timeout=timeout,
                    headers={'Accept': 'application/rdap+json'},
                    allow_redirects=True,
                ) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        return self.parse(data)

                    if response.status == 404:
                        # Authoritative: the registry has no such registration
                        self.logger.debug(f"RDAP reports {domain} unregistered")
                        return None

                    if response.status == 429 and attempt == 0:
                        await asyncio.sleep(2)
                        continue

                    self.logger.debug(f"RDAP HTTP {response.status} for {domain}")
                    return None

            except asyncio.TimeoutError:
                self.logger.debug(f"RDAP timeout for {domain}")
                return None
            except Exception as e:
                self.logger.debug(f"RDAP lookup failed for {domain}: {e}")
                return None

        return None

    # -- parsing -----------------------------------------------------------

    @staticmethod
    def parse(data: dict[str, Any]) -> dict[str, Any]:
        """
        Convert an RDAP domain response into the scanner's registration shape.

        The output keys match those produced by the WHOIS path so that
        exporters, risk scoring, and the diff engine stay source-agnostic.

        Args:
            data: Parsed RDAP JSON

        Returns:
            Normalised registration dictionary
        """
        events = RDAPClient._parse_events(data.get('events') or [])
        registrar, registrant, org, emails, country = RDAPClient._parse_entities(
            data.get('entities') or []
        )

        name_servers = []
        for ns in data.get('nameservers') or []:
            name = ns.get('ldhName') or ns.get('unicodeName')
            if name:
                name_servers.append(str(name).lower().rstrip('.'))

        status = data.get('status') or []
        if isinstance(status, str):
            status = [status]

        return {
            'whois_created': events.get('registration', []),
            'whois_updated': events.get('last changed', []),
            'whois_expires': events.get('expiration', []),
            'whois_registrant': registrant,
            'whois_org': org,
            'whois_registrar': registrar,
            'whois_emails': emails,
            'whois_name_servers': name_servers,
            'whois_status': list(status),
            'whois_country': country,
            'registration_source': 'rdap',
        }

    @staticmethod
    def _parse_events(events: list) -> dict[str, list[str]]:
        """Index RDAP events by action, as ISO date strings."""
        out: dict[str, list[str]] = {}

        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get('eventAction', '')).lower()
            raw = event.get('eventDate')
            if not action or not raw:
                continue

            parsed = RDAPClient._parse_timestamp(raw)
            if parsed:
                out.setdefault(action, []).append(parsed)

        return out

    @staticmethod
    def _parse_timestamp(value: Any) -> str | None:
        """Normalise an RDAP timestamp to an ISO date string."""
        if isinstance(value, datetime):
            return value.date().isoformat()
        if isinstance(value, date):
            return value.isoformat()
        if not isinstance(value, str):
            return None

        text = value.strip()
        try:
            # RDAP mandates RFC 3339; "Z" needs translating for fromisoformat
            dt = datetime.fromisoformat(text.replace('Z', '+00:00'))
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc)
            return dt.date().isoformat()
        except ValueError:
            pass

        try:
            return date.fromisoformat(text[:10]).isoformat()
        except ValueError:
            return None

    @staticmethod
    def _parse_entities(entities: list):
        """
        Extract registrar, registrant, organisation, emails and country.

        Returns:
            Tuple of (registrar, registrant, org, emails, country)
        """
        registrar = registrant = org = country = None
        emails: list[str] = []

        for entity in entities:
            if not isinstance(entity, dict):
                continue

            roles = [str(r).lower() for r in (entity.get('roles') or [])]
            fields = RDAPClient._parse_vcard(entity.get('vcardArray'))

            for address in fields.get('emails', []):
                if address not in emails:
                    emails.append(address)

            if 'registrar' in roles:
                registrar = fields.get('fn') or registrar
                # Registrars also publish an IANA ID; prefer the human name
                if not registrar:
                    for pid in entity.get('publicIds') or []:
                        if isinstance(pid, dict) and pid.get('identifier'):
                            registrar = f"IANA {pid['identifier']}"
                            break

            if 'registrant' in roles:
                registrant = fields.get('fn') or registrant
                org = fields.get('org') or org
                country = fields.get('country') or country

            # Nested entities carry the registrar's abuse contacts
            nested = entity.get('entities')
            if nested:
                sub = RDAPClient._parse_entities(nested)
                for address in sub[3]:
                    if address not in emails:
                        emails.append(address)

        return registrar, registrant, org, emails, country

    @staticmethod
    def _parse_vcard(vcard: Any) -> dict[str, Any]:
        """
        Pull useful fields out of a jCard array (RFC 7095).

        A jCard looks like ["vcard", [["fn", {}, "text", "Example Inc"], ...]].
        """
        out: dict[str, Any] = {'emails': []}

        if not isinstance(vcard, list) or len(vcard) < 2:
            return out
        if not isinstance(vcard[1], list):
            return out

        for entry in vcard[1]:
            if not isinstance(entry, list) or len(entry) < 4:
                continue

            name = str(entry[0]).lower()
            value = entry[3]

            if name == 'fn' and isinstance(value, str) and value.strip():
                out['fn'] = value.strip()
            elif name == 'org':
                # org may be a string or a structured list
                if isinstance(value, list):
                    value = ' '.join(str(v) for v in value if v)
                if isinstance(value, str) and value.strip():
                    out['org'] = value.strip()
            elif name == 'email' and isinstance(value, str) and '@' in value:
                out['emails'].append(value.strip())
            elif name == 'adr' and isinstance(value, list) and len(value) >= 7:
                # jCard address: [pobox, ext, street, locality, region, code, country]
                candidate = value[6]
                if isinstance(candidate, str) and candidate.strip():
                    out['country'] = candidate.strip()

        return out
