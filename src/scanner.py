"""
Domain scanning module for Typo Sniper.

Handles domain permutation generation, WHOIS lookups, and DNS queries.
"""

import asyncio
import logging
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor

import dnstwist
import whois

from config import Config
from cache import Cache
from enhanced_detection import generate_enhanced_permutations, SoundAlikeDetector
from threat_intelligence import ThreatIntelligence, calculate_risk_score
from ml_integration import get_ml_integration


class DomainScanner:
    """Scans domains for typosquatting variants with WHOIS enrichment."""

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

    async def scan_domain(self, domain: str) -> Dict[str, Any]:
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
        
        # Merge permutations
        all_permutations = permutations + enhanced_perms
        
        # Filter for registered domains only
        registered = [p for p in all_permutations if p.get('dns_a') or p.get('dns_aaaa')]
        
        self.logger.info(f"Found {len(registered)} registered permutations for {domain} ({len(permutations)} from dnstwist, {len(enhanced_perms)} from enhanced detection)")
        
        # Enrich with WHOIS data
        enriched = await self._enrich_with_whois(registered)
        
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
        
        # Add ML predictions if enabled
        if self.config.enable_ml:
            enriched = await self._add_ml_predictions(enriched, domain)
        
        return {
            'original_domain': domain,
            'scan_date': date.today().isoformat(),
            'total_permutations': len(all_permutations),
            'registered_count': len(registered),
            'filtered_count': len(enriched),
            'permutations': enriched
        }

    async def _get_permutations(self, domain: str) -> List[Dict[str, Any]]:
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

    def _run_dnstwist(self, domain: str) -> List[Dict[str, Any]]:
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
                mxcheck=True,
                threads=self.config.max_workers
            )
        except Exception as e:
            self.logger.error(f"dnstwist error for {domain}: {e}")
            return []
    
    async def _get_enhanced_permutations(self, domain: str) -> List[Dict[str, Any]]:
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
            for enhanced_domain, result in zip(enhanced_domains, results):
                if result is True:
                    perm = {
                        'domain': enhanced_domain,
                        'fuzzer': 'enhanced',  # Mark as enhanced detection
                        'dns_a': ['resolved'],  # Placeholder
                    }
                    permutations.append(perm)
            
            self.logger.info(f"Enhanced detection found {len(permutations)} registered domains")
            return permutations
            
        except Exception as e:
            self.logger.error(f"Error in enhanced detection for {domain}: {e}")
            return []
    
    async def _check_dns_async(self, domain: str) -> bool:
        """
        Async DNS check for a domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain resolves, False otherwise
        """
        loop = asyncio.get_event_loop()
        try:
            import socket
            await loop.run_in_executor(
                self.executor,
                socket.gethostbyname,
                domain
            )
            return True
        except (socket.gaierror, Exception):
            return False
    
    async def _add_threat_intelligence(self, permutations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
            for perm, threat_data in zip(permutations, threat_results):
                if isinstance(threat_data, Exception):
                    self.logger.error(f"Threat intel error for {perm['domain']}: {threat_data}")
                else:
                    perm['threat_intel'] = threat_data
        
        return permutations

    async def _enrich_with_whois(self, permutations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
            
            # Minimal rate limiting between batches
            if i + self.config.max_workers < len(tasks):
                await asyncio.sleep(0.3)
        
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

    async def _get_whois_data(self, domain: str) -> Dict[str, Any]:
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
            
            return whois_data
        
        except Exception as e:
            self.logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {}

    def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform synchronous WHOIS lookup.

        Args:
            domain: Domain to lookup

        Returns:
            Dictionary containing WHOIS data
        """
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
        
        except Exception as e:
            self.logger.debug(f"WHOIS error for {domain}: {e}")
            return {}

    def _parse_dates(self, date_value: Any) -> List[str]:
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

    def _filter_by_date(self, permutations: List[Dict[str, Any]], months: int) -> List[Dict[str, Any]]:
        """
        Filter permutations by creation date.

        Args:
            permutations: List of permutation dictionaries
            months: Number of months to filter by

        Returns:
            Filtered list of permutations
        """
        cutoff_date = date.today() - timedelta(days=months * 30)
        filtered = []
        
        for perm in permutations:
            created_dates = perm.get('whois_created', [])
            
            if not created_dates:
                continue
            
            # Check if any creation date is after cutoff
            is_recent = False
            for date_str in created_dates:
                try:
                    creation_date = date.fromisoformat(date_str)
                    if creation_date > cutoff_date:
                        is_recent = True
                        perm['is_recent'] = True
                        break
                except (ValueError, TypeError):
                    continue
            
            if is_recent:
                filtered.append(perm)
        
        self.logger.info(f"Filtered to {len(filtered)} domains created in last {months} months")
        return filtered
    
    async def _add_ml_predictions(self, permutations: List[Dict[str, Any]], brand: str) -> List[Dict[str, Any]]:
        """
        Add ML predictions to permutations.
        
        Args:
            permutations: List of permutation dictionaries
            brand: Original brand domain
            
        Returns:
            Permutations with ML predictions added
        """
        ml = get_ml_integration(self.config)
        
        if not ml or not ml.enabled:
            self.logger.info("ML not enabled or not available")
            # Add default ML fields
            for perm in permutations:
                perm.update({
                    'ml_enabled': False,
                    'ml_risk_score': None,
                    'ml_confidence': None,
                    'ml_is_typosquat': None,
                    'ml_explanation': 'ML not enabled',
                    'ml_needs_review': False,
                    'ml_top_features': []
                })
            return permutations
        
        self.logger.info(f"Adding ML predictions for {len(permutations)} domains")
        
        # Batch predict for efficiency
        predictions = ml.predict_batch(permutations, brand, explain=False)
        
        # Add predictions to permutations
        for perm, pred in zip(permutations, predictions):
            perm.update(pred)
        
        # Log stats
        ml_enabled_count = sum(1 for p in permutations if p.get('ml_enabled'))
        typosquat_count = sum(1 for p in permutations if p.get('ml_is_typosquat'))
        review_count = sum(1 for p in permutations if p.get('ml_needs_review'))
        
        self.logger.info(
            f"ML predictions: {ml_enabled_count} processed, "
            f"{typosquat_count} flagged as typosquats, "
            f"{review_count} need review"
        )
        
        # Sort by ML risk score if available (secondary sort after rule-based risk score)
        permutations.sort(
            key=lambda x: (
                x.get('risk_score', 0),  # Primary: rule-based risk score
                x.get('ml_risk_score', 0) or 0  # Secondary: ML risk score
            ),
            reverse=True
        )
        
        return permutations
