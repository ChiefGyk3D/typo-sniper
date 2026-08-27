"""
Domain scanning module for Typo Sniper.

Handles domain permutation generation, WHOIS lookups, and DNS queries.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import asyncio
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from typing import Any

import aiohttp
import dnstwist
import whois

from cache import Cache
from config import Config
from enhanced_detection import SoundAlikeDetector, generate_enhanced_permutations
from rdap import RDAPClient
from threat_intelligence import ThreatIntelligence, calculate_risk_score
from utils import clean_dns_records, is_registered


class DomainScanner:
    """Scans domains for typosquatting variants with WHOIS enrichment."""

    # Consecutive WHOIS failures after which retries are abandoned
    WHOIS_FAILURE_THRESHOLD = 10

    def __init__(self, config: Config, cache: Cache):
        """
        Initialize the domain scanner.

        Args:
            config: Configuration object
            cache: Cache object for storing WHOIS data
        """
        self.config = config
        self.cache = cache
        self.logger = logging.getLogger(__name__)
        self.executor = ThreadPoolExecutor(max_workers=config.max_workers)
        # Per-run WHOIS outcome counters, surfaced in the scan result so a
        # totally failed WHOIS stage cannot be mistaken for "no data found".
        self.whois_succeeded = 0
        self.whois_failed = 0
        # When WHOIS is systemically unavailable (egress to TCP/43 blocked, or
        # the resolver is hard rate-limiting), retrying every domain three
        # times turns a fast failure into a many-minute stall. After this many
        # consecutive failures, fall back to a single attempt per domain.
        self._whois_consecutive_failures = 0
        self._whois_circuit_open = False
        # Per-run counts of where registration data actually came from
        self.lookup_sources = {'rdap': 0, 'whois': 0, 'none': 0}

    def close(self) -> None:
        """Shut down the worker thread pool."""
        self.executor.shutdown(wait=False)

    def __enter__(self) -> 'DomainScanner':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    async def scan_domain(self, domain: str) -> dict[str, Any]:
        """
        Scan a domain for typosquatting variants.

        Args:
            domain: The domain to scan

        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"Starting scan for: {domain}")
        
        # Generate permutations using dnstwist
        permutations = await self._get_permutations(domain)
        
        # Add enhanced detection permutations
        if self.config.debug_mode:
            self.logger.debug(f"Calling enhanced detection for {domain}...")
        enhanced_perms = await self._get_enhanced_permutations(domain)
        
        # Merge permutations, dropping the original domain and any duplicate
        # that enhanced detection also produced
        all_permutations = self._merge_permutations(domain, permutations, enhanced_perms)

        # Keep only permutations that genuinely resolve. dnstwist reports
        # resolver failures as sentinel strings ("!ServFail", "!NXDOMAIN"),
        # which would otherwise be counted as registrations.
        registered = [p for p in all_permutations if is_registered(p)]

        # Normalise the DNS lists so downstream consumers never see sentinels
        for perm in registered:
            for key in ('dns_a', 'dns_aaaa', 'dns_mx', 'dns_ns'):
                if key in perm:
                    perm[key] = clean_dns_records(perm[key])

        self.logger.info(
            f"Found {len(registered)} registered permutations for {domain} "
            f"({len(permutations)} from dnstwist, {len(enhanced_perms)} from enhanced detection)"
        )

        whois_before = self.whois_succeeded

        # Registration data: RDAP first (HTTPS, structured JSON), falling back
        # to WHOIS only for registries that publish no RDAP endpoint.
        needs_whois = registered
        if self.config.use_rdap:
            unresolved = await self._enrich_with_rdap(registered)
            needs_whois = [p for p in registered if p['domain'] in unresolved]
            if needs_whois and not self.config.whois_fallback:
                self.logger.info(
                    f"{len(needs_whois)} domains unresolved by RDAP; "
                    f"WHOIS fallback is disabled"
                )
                needs_whois = []

        if needs_whois:
            await self._enrich_with_whois(needs_whois)

        enriched = registered

        # Derive registration age from the WHOIS data. This must happen before
        # risk scoring, which weights recently registered domains most heavily.
        for perm in enriched:
            self._annotate_registration_age(perm)

        # Flag permutations that are phonetically confusable with the original.
        # The detector existed but was never called, so enable_soundalike had
        # no effect on the output.
        if self.config.enable_soundalike:
            for perm in enriched:
                try:
                    perm['sounds_alike'] = SoundAlikeDetector.are_similar(
                        domain, perm['domain']
                    )
                except Exception:  # pragma: no cover - defensive
                    perm['sounds_alike'] = False

        # Add threat intelligence
        enriched = await self._add_threat_intelligence(enriched)

        # Apply date filters if configured
        if self.config.months_filter > 0:
            enriched = self._filter_by_date(enriched, self.config.months_filter)

        # Calculate risk scores if enabled
        if self.config.enable_risk_scoring:
            for perm in enriched:
                perm['risk_score'] = calculate_risk_score(perm, perm.get('threat_intel', {}))

            # Sort by risk score (highest first)
            enriched.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

        whois_ok = self.whois_succeeded - whois_before
        if registered and whois_ok == 0:
            self.logger.warning(
                f"No WHOIS data could be retrieved for any of the {len(registered)} "
                f"registered permutations of {domain}. Registration dates and "
                f"recency scoring will be missing from this report. Check outbound "
                f"access to RDAP endpoints (HTTPS) and WHOIS servers (TCP/43)."
            )

        return {
            'original_domain': domain,
            'scan_date': date.today().isoformat(),
            'total_permutations': len(all_permutations),
            'registered_count': len(registered),
            'filtered_count': len(enriched),
            'whois_succeeded': whois_ok,
            'whois_failed': len(registered) - whois_ok,
            'lookup_sources': dict(self.lookup_sources),
            'permutations': enriched
        }

    def _merge_permutations(
        self,
        domain: str,
        dnstwist_perms: list[dict[str, Any]],
        enhanced_perms: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Combine dnstwist and enhanced results into one deduplicated list.

        The original domain is dropped: it is the asset being protected, not a
        typosquat, and counting it inflated every registered_count by one.

        Args:
            domain: The original domain being scanned
            dnstwist_perms: Permutations from dnstwist
            enhanced_perms: Permutations from enhanced detection

        Returns:
            Deduplicated permutation list, dnstwist entries taking precedence
        """
        merged: dict[str, dict[str, Any]] = {}

        for perm in list(dnstwist_perms) + list(enhanced_perms):
            name = str(perm.get('domain', '')).lower().rstrip('.')
            if not name or name == domain.lower():
                continue
            if perm.get('fuzzer') == '*original':
                continue
            # dnstwist entries come first and carry richer DNS data, so an
            # enhanced duplicate must not overwrite them
            merged.setdefault(name, perm)

        return list(merged.values())

    def _annotate_registration_age(self, perm: dict[str, Any]) -> None:
        """
        Add ``created_days_ago`` and ``is_recent`` from WHOIS creation dates.

        Previously ``created_days_ago`` was never populated, so the recency
        component of the risk score never contributed, and ``is_recent`` was
        only set when --months was passed.

        Args:
            perm: Permutation dictionary, modified in place
        """
        earliest = None
        for date_str in perm.get('whois_created', []):
            parsed = self._parse_iso_date(date_str)
            if parsed and (earliest is None or parsed < earliest):
                earliest = parsed

        if earliest is None:
            return

        days_ago = (date.today() - earliest).days
        perm['created_days_ago'] = days_ago
        perm['is_recent'] = 0 <= days_ago <= self.config.recent_days

    @staticmethod
    def _parse_iso_date(value: Any) -> Any:
        """Parse a WHOIS date string into a ``date``, or None if unparseable."""
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, date):
            return value
        if not isinstance(value, str):
            return None

        text = value.strip()
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            pass

        for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%d-%b-%Y', '%Y.%m.%d'):
            try:
                return datetime.strptime(text, fmt).date()
            except ValueError:
                continue

        return None

    async def _get_permutations(self, domain: str) -> list[dict[str, Any]]:
        """
        Generate domain permutations using dnstwist.

        Args:
            domain: Domain to generate permutations for

        Returns:
            List of permutation dictionaries
        """
        loop = asyncio.get_event_loop()
        
        try:
            # Run dnstwist in thread pool to avoid blocking
            permutations = await loop.run_in_executor(
                self.executor,
                self._run_dnstwist,
                domain
            )
            return permutations
        except Exception as e:
            self.logger.error(f"Error generating permutations for {domain}: {e}")
            return []

    def _run_dnstwist(self, domain: str) -> list[dict[str, Any]]:
        """
        Run dnstwist synchronously (called from executor).

        Args:
            domain: Domain to scan

        Returns:
            List of permutation dictionaries
        """
        try:
            return dnstwist.run(
                domain=domain,
                registered=True,
                format='null',
                mxcheck=self.config.dnstwist_mxcheck,
                phash=self.config.dnstwist_phash,
                threads=self.config.dnstwist_threads,
            )
        except TypeError:
            # Older dnstwist releases do not accept every keyword; retry with
            # the options guaranteed to exist rather than losing the scan.
            self.logger.debug("dnstwist rejected an option, retrying with defaults")
            try:
                return dnstwist.run(
                    domain=domain,
                    registered=True,
                    format='null',
                    threads=self.config.dnstwist_threads,
                )
            except Exception as e:
                self.logger.error(f"dnstwist error for {domain}: {e}")
                return []
        except Exception as e:
            self.logger.error(f"dnstwist error for {domain}: {e}")
            return []
    
    async def _get_enhanced_permutations(self, domain: str) -> list[dict[str, Any]]:
        """
        Generate enhanced permutations (combo-squatting, IDN homographs, etc).
        
        Args:
            domain: Domain to generate permutations for
            
        Returns:
            List of enhanced permutation dictionaries
        """
        # Skip if all enhanced features are disabled
        if not any([self.config.enable_combosquatting, self.config.enable_idn_homograph]):
            return []
        
        loop = asyncio.get_event_loop()
        
        try:
            # Generate enhanced permutations
            if self.config.debug_mode:
                self.logger.debug(f"Generating enhanced permutations for {domain}...")
            
            enhanced_domains = await loop.run_in_executor(
                self.executor,
                generate_enhanced_permutations,
                domain,
                self.config
            )
            
            enhanced_domains = sorted(enhanced_domains)

            if not enhanced_domains:
                if self.config.debug_mode:
                    self.logger.debug(f"No enhanced permutations generated for {domain}")
                return []
            
            self.logger.info(f"Generated {len(enhanced_domains)} enhanced permutations, checking DNS...")
            
            # Check DNS for each enhanced permutation (async)
            tasks = []
            for enhanced_domain in enhanced_domains:
                tasks.append(self._check_dns_async(enhanced_domain))
            
            # Run DNS checks concurrently with a limit
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter for registered domains
            permutations = []
            for enhanced_domain, result in zip(enhanced_domains, results, strict=False):
                if isinstance(result, str) and result:
                    perm = {
                        'domain': enhanced_domain,
                        'fuzzer': 'enhanced',  # Mark as enhanced detection
                        'dns_a': [result],
                    }
                    permutations.append(perm)
            
            self.logger.info(f"Enhanced detection found {len(permutations)} registered domains")
            return permutations
            
        except Exception as e:
            self.logger.error(f"Error in enhanced detection for {domain}: {e}")
            return []
    
    async def _check_dns_async(self, domain: str):
        """
        Async DNS check for a domain.

        Args:
            domain: Domain to check

        Returns:
            The resolved IPv4 address, or None if the domain does not resolve
        """
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(
                self.executor,
                socket.gethostbyname,
                domain
            )
        except (TimeoutError, socket.gaierror, UnicodeError, OSError):
            return None
    
    async def _add_threat_intelligence(self, permutations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Add threat intelligence to permutations.
        
        Args:
            permutations: List of permutation dictionaries
            
        Returns:
            List of permutations with threat intelligence
        """
        # Check if any threat intelligence is enabled
        if not any([
            self.config.enable_urlscan,
            self.config.enable_certificate_transparency,
            self.config.enable_http_probe
        ]):
            return permutations
        
        self.logger.info(f"Gathering threat intelligence for {len(permutations)} domains")
        
        async with ThreatIntelligence(self.config) as threat_intel:
            tasks = []
            for perm in permutations:
                task = threat_intel.analyze_domain(perm['domain'])
                tasks.append(task)
            
            # Calculate batch size and delay based on API tier limits
            # URLScan free: 30 req/min = ~2 seconds per request
            
            if self.config.enable_urlscan and self.config.urlscan_free_tier:
                # URLScan free tier: 30 requests/min = ~2 seconds per request
                batch_size = min(30, self.config.max_workers)
                batch_delay = 2.0
                self.logger.info("Using URLScan free tier limits (30 requests/min)")
            else:
                # Paid tier or no API limits - use normal batching
                batch_size = self.config.max_workers
                batch_delay = 0.5
            
            # Execute threat intelligence checks in batches
            threat_results = []
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                threat_results.extend(batch_results)
                
                # Rate limiting between batches
                if i + batch_size < len(tasks):
                    await asyncio.sleep(batch_delay)
            
            # Add threat intelligence to permutations
            for perm, threat_data in zip(permutations, threat_results, strict=False):
                if isinstance(threat_data, Exception):
                    self.logger.error(f"Threat intel error for {perm['domain']}: {threat_data}")
                else:
                    perm['threat_intel'] = threat_data
        
        return permutations

    async def _enrich_with_rdap(self, permutations: list[dict[str, Any]]) -> set:
        """
        Enrich permutations with RDAP registration data.

        Args:
            permutations: Permutation dictionaries, updated in place

        Returns:
            Set of domain names RDAP could not answer for, which the caller
            may retry over WHOIS
        """
        unresolved: set = set()
        if not permutations:
            return unresolved

        connector = aiohttp.TCPConnector(limit=max(4, self.config.max_workers * 2))
        timeout = aiohttp.ClientTimeout(total=self.config.rdap_timeout + 10)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.config.user_agent},
        ) as session:
            client = RDAPClient(session, self.config, self.cache)
            semaphore = asyncio.Semaphore(max(1, self.config.max_workers))

            async def lookup_one(perm):
                domain = perm['domain']

                if self.config.use_cache:
                    cached = self.cache.get(f"rdap:{domain}")
                    if cached:
                        perm.update(cached)
                        return 'rdap'

                async with semaphore:
                    data = await client.lookup(domain)

                if data:
                    perm.update(data)
                    if self.config.use_cache:
                        self.cache.set(f"rdap:{domain}", data, ttl=self.config.cache_ttl)
                    return 'rdap'
                return None

            results = await asyncio.gather(
                *(lookup_one(p) for p in permutations), return_exceptions=True
            )

        resolved = 0
        for perm, outcome in zip(permutations, results, strict=False):
            if outcome == 'rdap':
                resolved += 1
                self.lookup_sources['rdap'] += 1
                self.whois_succeeded += 1
            else:
                if isinstance(outcome, Exception):
                    self.logger.debug(f"RDAP error for {perm['domain']}: {outcome}")
                unresolved.add(perm['domain'])

        self.logger.info(f"RDAP resolved {resolved}/{len(permutations)} domains")
        return unresolved

    async def _enrich_with_whois(self, permutations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Enrich permutations with WHOIS data.

        Args:
            permutations: List of permutation dictionaries

        Returns:
            List of enriched permutation dictionaries
        """
        tasks = []
        for perm in permutations:
            # Skip original domain marker
            if perm.get('fuzzer') == '*original':
                continue
            
            task = self._get_whois_data(perm['domain'])
            tasks.append(task)
        
        # Execute WHOIS lookups concurrently with minimal rate limiting
        whois_results = []
        for i in range(0, len(tasks), self.config.max_workers):
            batch = tasks[i:i + self.config.max_workers]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            whois_results.extend(batch_results)
            
            # Rate limiting between batches
            if i + self.config.max_workers < len(tasks):
                await asyncio.sleep(self.config.rate_limit_delay)
        
        # Merge WHOIS data with permutations
        enriched = []
        idx = 0
        for perm in permutations:
            if perm.get('fuzzer') == '*original':
                continue
            
            if idx < len(whois_results) and not isinstance(whois_results[idx], Exception):
                whois_data = whois_results[idx]
                perm.update(whois_data)
            
            enriched.append(perm)
            idx += 1
        
        return enriched

    async def _get_whois_data(self, domain: str) -> dict[str, Any]:
        """
        Get WHOIS data for a domain with caching.

        Args:
            domain: Domain to lookup

        Returns:
            Dictionary containing WHOIS data
        """
        # Check cache first
        if self.config.use_cache:
            cached = self.cache.get(f"whois:{domain}")
            if cached:
                self.logger.debug(f"Cache hit for {domain}")
                self.whois_succeeded += 1
                return cached
        
        # Perform WHOIS lookup
        loop = asyncio.get_event_loop()
        try:
            whois_data = await loop.run_in_executor(
                self.executor,
                self._whois_lookup,
                domain
            )
            
            # Cache the result
            if self.config.use_cache and whois_data:
                self.cache.set(f"whois:{domain}", whois_data, ttl=self.config.cache_ttl)

            if whois_data:
                self.whois_succeeded += 1
                self.lookup_sources['whois'] += 1
                whois_data.setdefault('registration_source', 'whois')
            else:
                self.whois_failed += 1
                self.lookup_sources['none'] += 1

            return whois_data

        except Exception as e:
            self.whois_failed += 1
            self.logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {}

    def _whois_lookup(self, domain: str) -> dict[str, Any]:
        """
        Perform synchronous WHOIS lookup.

        Args:
            domain: Domain to lookup

        Returns:
            Dictionary containing WHOIS data
        """
        attempts = 1 if self._whois_circuit_open else max(1, self.config.whois_retry_count)
        last_error = None

        for attempt in range(attempts):
            try:
                data = self._whois_query(domain)
                self._whois_consecutive_failures = 0
                self._whois_circuit_open = False
                return data
            except Exception as e:
                last_error = e
                if attempt + 1 < attempts:
                    self.logger.debug(
                        f"WHOIS attempt {attempt + 1} failed for {domain}: {e}; retrying"
                    )
                    time.sleep(self.config.whois_retry_delay)

        self._whois_consecutive_failures += 1
        if (
            not self._whois_circuit_open
            and self._whois_consecutive_failures >= self.WHOIS_FAILURE_THRESHOLD
        ):
            self._whois_circuit_open = True
            self.logger.warning(
                f"{self._whois_consecutive_failures} consecutive WHOIS lookups failed "
                f"(last error: {last_error}). Falling back to a single attempt per "
                f"domain for the rest of this run. Check outbound access to TCP port 43."
            )

        self.logger.debug(f"WHOIS error for {domain}: {last_error}")
        return {}

    def _whois_query(self, domain: str) -> dict[str, Any]:
        """
        Run a single WHOIS query, bounded by ``whois_timeout``.

        The underlying python-whois library exposes no timeout parameter, so
        the socket default is set for the duration of the call. Without this a
        silent WHOIS server can hang a worker thread indefinitely.

        Args:
            domain: Domain to lookup

        Returns:
            Dictionary containing WHOIS data

        Raises:
            Exception: Whatever the WHOIS lookup raised
        """
        previous_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.config.whois_timeout)
        try:
            w = whois.whois(domain)

            # Parse creation dates
            creation_dates = self._parse_dates(w.creation_date)
            updated_dates = self._parse_dates(w.updated_date)
            expiration_dates = self._parse_dates(w.expiration_date)
            
            # Parse emails
            emails = []
            if w.emails:
                if isinstance(w.emails, list):
                    emails = w.emails
                elif isinstance(w.emails, str):
                    emails = [w.emails]
            
            # Parse name servers
            name_servers = []
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    name_servers = [ns.lower() for ns in w.name_servers]
                elif isinstance(w.name_servers, str):
                    name_servers = [w.name_servers.lower()]
            
            return {
                'whois_created': creation_dates,
                'whois_updated': updated_dates,
                'whois_expires': expiration_dates,
                'whois_registrant': w.name if w.name else None,
                'whois_org': w.org if w.org else None,
                'whois_registrar': w.registrar if w.registrar else None,
                'whois_emails': emails,
                'whois_name_servers': name_servers,
                'whois_status': w.status if w.status else None,
                'whois_country': w.country if hasattr(w, 'country') and w.country else None,
            }
        finally:
            socket.setdefaulttimeout(previous_timeout)

    def _parse_dates(self, date_value: Any) -> list[str]:
        """
        Parse date values from WHOIS data.

        Args:
            date_value: Date value from WHOIS (can be datetime, list, or None)

        Returns:
            List of date strings in ISO format
        """
        if not date_value:
            return []
        
        dates = []
        if isinstance(date_value, list):
            for d in date_value:
                if isinstance(d, datetime):
                    dates.append(d.date().isoformat())
                elif isinstance(d, date):
                    dates.append(d.isoformat())
                elif isinstance(d, str):
                    dates.append(d)
        elif isinstance(date_value, datetime):
            dates.append(date_value.date().isoformat())
        elif isinstance(date_value, date):
            dates.append(date_value.isoformat())
        elif isinstance(date_value, str):
            dates.append(date_value)
        
        return dates

    def _filter_by_date(self, permutations: list[dict[str, Any]], months: int) -> list[dict[str, Any]]:
        """
        Filter permutations by creation date.

        Args:
            permutations: List of permutation dictionaries
            months: Number of months to filter by

        Returns:
            Filtered list of permutations
        """
        cutoff_days = int(months * 30.44)  # average month length
        filtered = []
        skipped_unknown = 0

        for perm in permutations:
            days_ago = perm.get('created_days_ago')

            if days_ago is None:
                # No usable WHOIS creation date: cannot prove it is recent
                skipped_unknown += 1
                continue

            if days_ago <= cutoff_days:
                filtered.append(perm)

        if skipped_unknown:
            self.logger.warning(
                f"{skipped_unknown} registered domains were excluded by the "
                f"--months filter because no WHOIS creation date was available"
            )

        self.logger.info(f"Filtered to {len(filtered)} domains created in last {months} months")
        return filtered
