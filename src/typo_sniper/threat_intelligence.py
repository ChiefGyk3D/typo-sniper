"""
Threat intelligence integrations for domain analysis.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import asyncio
import json
import logging
import re
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import aiohttp

from . import page_analysis

# Matches <title ...>...</title> across newlines and with attributes present
_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)


class ThreatIntelligence:
    """Threat intelligence integrations."""
    
    # API keys already validated in this process. Validation costs a live API
    # call, and a ThreatIntelligence context is entered once per scanned
    # domain, so without this a 50-domain run burns 50 requests on validation.
    _validated_keys = set()

    def __init__(self, config):
        """Initialize threat intelligence."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        # Set per scan so page analysis can count mentions of the brand being
        # defended. A lookalike that names its target is imitating it.
        self.monitored_domain = ''
    
    async def __aenter__(self):
        """Async context manager entry."""
        # Create session with connection pooling limits for better performance
        connector = aiohttp.TCPConnector(
            limit=100,  # Max total connections
            limit_per_host=30,  # Max connections per host
            ttl_dns_cache=300  # Cache DNS for 5 minutes
        )
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.config.user_agent},
        )
        # Validate API keys on startup
        await self.validate_api_keys()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def validate_api_keys(self):
        """
        Validate API keys before running scans.
        
        Raises:
            ValueError: If required API keys are invalid or missing
        """
        errors = []

        # Validate URLScan API key
        if self.config.enable_urlscan:
            if self.config.urlscan_api_key in self._validated_keys:
                return
            if not self.config.urlscan_api_key:
                errors.append("URLScan.io is enabled but API key is not set. Set TYPO_SNIPER_URLSCAN_API_KEY environment variable or urlscan_api_key in config.")
            else:
                try:
                    # Test API key with a simple search request
                    url = "https://urlscan.io/api/v1/search/?q=domain:google.com&size=1"
                    headers = {"API-Key": self.config.urlscan_api_key}
                    
                    async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 401:
                            errors.append("URLScan.io API key is invalid or unauthorized. Please check your API key.")
                        elif response.status == 403:
                            errors.append("URLScan.io API key is forbidden. Please verify your API key permissions.")
                        elif response.status == 200:
                            self._validated_keys.add(self.config.urlscan_api_key)
                        else:
                            self.logger.warning(f"URLScan.io API returned status {response.status} during validation")
                except asyncio.TimeoutError:
                    self.logger.warning("URLScan.io API validation timed out - continuing anyway")
                except Exception as e:
                    self.logger.warning(f"URLScan.io API validation failed: {e} - continuing anyway")
        
        # If there are critical errors, raise exception
        if errors:
            error_msg = "API Key Validation Failed:\n" + "\n".join(f"  • {err}" for err in errors)
            self.logger.error(error_msg)
            raise ValueError(error_msg)
    
    async def check_urlscan(self, domain: str) -> dict[str, Any] | None:
        """
        Check URLScan.io for scan results, submitting a new scan if needed.
        
        This method:
        1. Searches for existing scans of the domain
        2. If no scan exists or the latest scan is older than urlscan_max_age_days, submits a new scan
        3. Waits for and retrieves the results
        
        Args:
            domain: Domain to scan
            
        Returns:
            URLScan report or None
        """
        if not self.config.enable_urlscan or not self.config.urlscan_api_key:
            return None
        
        try:
            # First, check for existing scans
            search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1"
            headers = {"API-Key": self.config.urlscan_api_key}
            
            should_submit = False
            
            async with self.session.get(search_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    results = data.get('results', [])
                    
                    if results:
                        result = results[0]
                        task = result.get('task', {})
                        scan_time = task.get('time')
                        
                        # Check if scan is recent enough
                        if scan_time:
                            scan_date = datetime.fromisoformat(scan_time.replace('Z', '+00:00'))
                            age_days = (datetime.now(timezone.utc) - scan_date).days
                            
                            if age_days <= self.config.urlscan_max_age_days:
                                # Recent scan found, return it
                                verdicts = result.get('verdicts', {})
                                uuid = task.get('uuid')
                                
                                # Construct report URL from UUID if not provided
                                report_url = task.get('reportURL')
                                if not report_url and uuid:
                                    report_url = f"https://urlscan.io/result/{uuid}/"
                                
                                self.logger.debug(f"Found recent URLScan result for {domain} ({age_days} days old)")
                                return {
                                    'malicious': verdicts.get('overall', {}).get('malicious', False),
                                    'score': verdicts.get('overall', {}).get('score', 0),
                                    'categories': verdicts.get('overall', {}).get('categories', []),
                                    'screenshot': task.get('screenshotURL'),
                                    'report_url': report_url,
                                    'scan_age_days': age_days,
                                }
                            else:
                                self.logger.info(f"URLScan result for {domain} is {age_days} days old, submitting new scan")
                                should_submit = True
                        else:
                            should_submit = True
                    else:
                        # No existing scan found
                        self.logger.info(f"No existing URLScan result for {domain}, submitting new scan")
                        should_submit = True
                elif response.status == 429:
                    self.logger.warning(f"URLScan rate limit hit for {domain}")
                    return {'status': 'rate_limited'}
                else:
                    # An unexpected status previously fell through to a silent
                    # None, which the exporters render as "No Scan Available"
                    self.logger.warning(
                        f"URLScan search for {domain} returned HTTP {response.status}"
                    )
                    return {'status': 'error', 'error': f'HTTP {response.status}'}

            # Submit new scan if needed
            if should_submit:
                return await self._submit_urlscan(domain)

            return None
                    
        except Exception as e:
            self.logger.error(f"URLScan check failed for {domain}: {e}")
            return None
    
    async def _submit_urlscan(self, domain: str) -> dict[str, Any] | None:
        """
        Submit a new URLScan and wait for results.
        
        Args:
            domain: Domain to scan
            
        Returns:
            URLScan report or None
        """
        try:
            # Submit scan
            submit_url = "https://urlscan.io/api/v1/scan/"
            headers = {
                "API-Key": self.config.urlscan_api_key,
                "Content-Type": "application/json"
            }
            data = {
                "url": f"http://{domain}",
                "visibility": self.config.urlscan_visibility
            }
            
            async with self.session.post(submit_url, headers=headers, json=data) as response:
                if response.status == 200:
                    result = await response.json()
                    result_url = result.get('api')
                    uuid = result.get('uuid')
                    
                    if not result_url:
                        self.logger.error(f"URLScan submission succeeded but no result URL for {domain}")
                        return None
                    
                    self.logger.info(f"URLScan submitted for {domain}, waiting for results (UUID: {uuid})")
                    
                    # Wait for results (with timeout)
                    max_attempts = self.config.urlscan_wait_timeout // 5  # Check every 5 seconds
                    
                    for attempt in range(max_attempts):
                        await asyncio.sleep(5)  # Wait 5 seconds between checks
                        
                        async with self.session.get(result_url) as result_response:
                            if result_response.status == 200:
                                scan_result = await result_response.json()
                                verdicts = scan_result.get('verdicts', {})
                                task = scan_result.get('task', {})
                                
                                self.logger.info(f"URLScan results retrieved for {domain}")
                                return {
                                    'malicious': verdicts.get('overall', {}).get('malicious', False),
                                    'score': verdicts.get('overall', {}).get('score', 0),
                                    'categories': verdicts.get('overall', {}).get('categories', []),
                                    'screenshot': task.get('screenshotURL'),
                                    'report_url': task.get('reportURL'),
                                    'scan_age_days': 0,
                                    'fresh_scan': True
                                }
                            elif result_response.status == 404:
                                # Still processing
                                self.logger.debug(f"URLScan still processing {domain} (attempt {attempt + 1}/{max_attempts})")
                                continue
                            else:
                                self.logger.warning(f"URLScan result fetch error for {domain}: {result_response.status}")
                                return None
                    
                    self.logger.warning(f"URLScan timeout waiting for {domain} results after {self.config.urlscan_wait_timeout}s")
                    return {'status': 'timeout'}
                    
                elif response.status == 429:
                    self.logger.warning(f"URLScan rate limit hit when submitting {domain}")
                    return {'status': 'rate_limited'}
                elif response.status == 400:
                    error_text = await response.text()
                    self.logger.error(f"URLScan submission failed for {domain}: {response.status} - {error_text}")
                    # Parse error message if possible
                    try:
                        error_data = json.loads(error_text)
                        error_msg = error_data.get('message', 'Bad Request')
                        return {'status': 'submission_failed', 'error': error_msg}
                    except (ValueError, AttributeError):
                        return {'status': 'submission_failed', 'error': 'Bad Request'}
                else:
                    error_text = await response.text()
                    self.logger.error(f"URLScan submission failed for {domain}: {response.status} - {error_text}")
                    return {'status': 'submission_failed', 'error': f'HTTP {response.status}'}
                    
        except Exception as e:
            self.logger.error(f"URLScan submission failed for {domain}: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def check_certificate_transparency(self, domain: str) -> dict[str, Any] | None:
        """
        Check Certificate Transparency logs for domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            CT log information or None
        """
        if not self.config.enable_certificate_transparency:
            return None
        
        try:
            # Use crt.sh API with timeout. crt.sh returns 502/504 under load
            # often enough that a single attempt loses real certificate data.
            url = f"https://crt.sh/?q={quote(domain, safe='')}&output=json"

            for attempt in range(3):
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status in (429, 502, 503, 504) and attempt < 2:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return await self._parse_ct_response(domain, resp)

            return {'certificates_found': 0, 'status': 'unavailable'}

        except asyncio.TimeoutError:
            self.logger.debug(f"CT log check timed out for {domain}")
            return {'certificates_found': 0, 'status': 'timeout'}
        except Exception as e:
            self.logger.debug(f"CT log check failed for {domain}: {e}")
            return {'certificates_found': 0, 'status': 'error'}

    async def _parse_ct_response(self, domain: str, response) -> dict[str, Any]:
        """
        Turn a crt.sh response into a certificate summary.

        Args:
            domain: Domain the query was for
            response: Open aiohttp response

        Returns:
            Certificate summary dictionary
        """
        try:
            if response.status == 200:
                content_type = response.headers.get('Content-Type', '')

                # Check if response is actually JSON (not an HTML error page)
                if 'json' not in content_type.lower():
                    self.logger.debug(f"CT log returned non-JSON for {domain} (probably no certs)")
                    return {'certificates_found': 0, 'status': 'no_certificates'}

                try:
                    data = await response.json()
                except Exception as json_err:
                    self.logger.debug(f"CT log JSON parse error for {domain}: {json_err}")
                    return {'certificates_found': 0, 'status': 'parse_error'}

                if data and isinstance(data, list):
                    # crt.sh does not sort by date, so pick the newest entry
                    # rather than assuming the first one is most recent
                    recent = max(data, key=lambda c: str(c.get('not_before') or ''))

                    names = []
                    for cert in data:
                        name = cert.get('common_name')
                        if name and name not in names:
                            names.append(name)
                        if len(names) >= 10:
                            break

                    return {
                        'certificates_found': len(data),
                        'most_recent': {
                            'issuer': recent.get('issuer_name'),
                            'not_before': recent.get('not_before'),
                            'not_after': recent.get('not_after'),
                            'common_name': recent.get('common_name'),
                        },
                        'all_names': names,
                    }

                return {'certificates_found': 0, 'status': 'no_certificates'}

            self.logger.debug(f"CT log check returned status {response.status} for {domain}")
            return {'certificates_found': 0, 'status': f'http_{response.status}'}

        except Exception as e:
            self.logger.debug(f"CT log parse failed for {domain}: {e}")
            return {'certificates_found': 0, 'status': 'error'}
    
    async def http_probe(self, domain: str) -> dict[str, Any] | None:
        """
        Probe domain with HTTP/HTTPS to check if it's active.
        
        Args:
            domain: Domain to probe
            
        Returns:
            HTTP probe results or None
        """
        if not self.config.enable_http_probe:
            return None
        
        results = {
            'http_active': False,
            'https_active': False,
            'http_status': None,
            'https_status': None,
            'redirects_to': None,
            'title': None,
            'tls_verified': None,
            'page': None,
        }

        # HTTPS first: a typosquat with a valid certificate is the higher signal
        for scheme in ('https', 'http'):
            probe = await self._probe_scheme(f"{scheme}://{domain}")
            if probe is None:
                continue

            results[f'{scheme}_active'] = True
            results[f'{scheme}_status'] = probe['status']

            if scheme == 'https':
                results['tls_verified'] = probe.get('tls_verified')

            if probe['redirects_to'] and not results['redirects_to']:
                results['redirects_to'] = probe['redirects_to']

            if probe['title'] and not results['title']:
                results['title'] = probe['title']

            if probe.get('page') and not results.get('page'):
                results['page'] = probe['page']

        return results if (results['http_active'] or results['https_active']) else None
    
    async def _probe_scheme(self, url: str) -> dict[str, Any] | None:
        """
        Fetch one URL and extract its status, final URL and page title.

        The response body is read in bounded chunks. These are hostile hosts by
        definition, and an unbounded ``response.text()`` would let one of them
        exhaust the scanner's memory by streaming an endless body.

        Args:
            url: Absolute http(s) URL to probe

        Returns:
            Dictionary with status/redirects_to/title, or None if unreachable
        """
        # Certificates are always validated. A validation failure is not an
        # obstacle to work around: it is itself a finding, recorded below.
        timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
        is_https = url.startswith('https://')

        try:
            async with self.session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                max_redirects=self.config.http_max_redirects,
            ) as response:
                result = {
                    'status': response.status,
                    'redirects_to': str(response.url) if response.history else None,
                    'title': None,
                    'tls_verified': True if is_https else None,
                    'page': None,
                }

                if response.status == 200:
                    body = await self._read_body(response)
                    if body:
                        result['title'] = self._extract_title(body)
                        if self.config.enable_page_analysis:
                            # No extra request: the body is already in memory,
                            # and what the page collects is the strongest
                            # signal available about what it is for.
                            result['page'] = page_analysis.analyse(
                                body, str(response.url), self.monitored_domain
                            )

                return result

        except (aiohttp.ClientConnectorCertificateError,
                aiohttp.ClientConnectorSSLError,
                ssl.SSLError) as e:
            # The host answered and presented a certificate that failed
            # validation. That tells us two useful things at once: the domain
            # is live, and its certificate cannot be trusted.
            #
            # The probe deliberately stops here rather than retrying with
            # verification disabled. Retrying would mean reading a response
            # body over a channel just proven unauthenticated, and that body
            # becomes the page title in an analyst's report. Liveness for
            # such hosts is still established by the plain HTTP probe.
            self.logger.debug(f"Certificate validation failed for {url}: {e}")
            return {
                'status': None,
                'redirects_to': None,
                'title': None,
                'tls_verified': False,
            }

        except asyncio.TimeoutError:
            self.logger.debug(f"Timeout probing {url}")
        except Exception as e:
            self.logger.debug(f"Probe failed for {url}: {e}")

        return None

    async def _read_body(self, response) -> str | None:
        """
        Read at most ``http_max_bytes`` of a response body.

        Args:
            response: Open aiohttp response

        Returns:
            The decoded body, or None if it could not be read
        """
        try:
            chunks = []
            total = 0
            async for chunk in response.content.iter_chunked(16384):
                chunks.append(chunk)
                total += len(chunk)
                if total >= self.config.http_max_bytes:
                    break

            return b''.join(chunks).decode('utf-8', errors='replace')
        except Exception as e:
            self.logger.debug(f"Could not read response body: {e}")
            return None

    @staticmethod
    def _extract_title(body: str) -> str | None:
        """Pull <title> out of a page body."""
        match = _TITLE_RE.search(body or '')
        if match:
            # Collapse whitespace so the title stays on one report row
            return ' '.join(match.group(1).split())[:200]
        return None

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        """
        Perform comprehensive threat intelligence analysis on domain.
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Threat intelligence report
        """
        report = {
            'domain': domain,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'urlscan': None,
            'certificate_transparency': None,
            'http_probe': None,
        }
        
        # Run all checks concurrently
        tasks = []
        
        if self.config.enable_urlscan and self.config.urlscan_api_key:
            tasks.append(('urlscan', self.check_urlscan(domain)))
        
        if self.config.enable_certificate_transparency:
            tasks.append(('certificate_transparency', self.check_certificate_transparency(domain)))
        
        if self.config.enable_http_probe:
            tasks.append(('http_probe', self.http_probe(domain)))
        
        # Execute all tasks
        if tasks:
            results = await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)
            
            for (name, _), result in zip(tasks, results, strict=False):
                if isinstance(result, Exception):
                    self.logger.error(f"Error in {name} for {domain}: {result}")
                else:
                    report[name] = result
        
        return report


def calculate_risk_score(domain_data: dict[str, Any], threat_intel: dict[str, Any]) -> int:
    """
    Calculate risk score for a domain based on various factors.

    Weighting rationale, highest signal first:
      * A URLScan malicious verdict is near-conclusive.
      * A recent registration is the strongest behavioural signal for
        typosquatting, since attackers register shortly before a campaign.
      * MX records on a lookalike domain indicate credential phishing or
        business email compromise capability, not a parked domain.
      * A live site matters more than a merely registered name.

    Args:
        domain_data: Domain permutation data
        threat_intel: Threat intelligence report

    Returns:
        Risk score (0-100, higher is more risky)
    """
    score = 0

    # Base score for being registered at all
    score += 5

    # --- URLScan verdict ---------------------------------------------------
    urlscan = threat_intel.get('urlscan') or {}
    if urlscan and not urlscan.get('status'):
        if urlscan.get('malicious'):
            score += 35

        # URLScan's overall score is already a 0-100 malicious-confidence
        # value. The previous code multiplied it by 20, so any non-zero
        # verdict immediately saturated the 100-point cap and every flagged
        # domain looked equally dangerous.
        try:
            urlscan_score = float(urlscan.get('score', 0) or 0)
        except (TypeError, ValueError):
            urlscan_score = 0.0
        score += int(max(0.0, min(urlscan_score, 100.0)) * 0.25)

    # --- Registration recency ---------------------------------------------
    days = domain_data.get('created_days_ago')
    if isinstance(days, (int, float)) and days >= 0:
        if days < 30:
            score += 25
        elif days < 90:
            score += 15
        elif days < 180:
            score += 5

    # --- Phonetic confusability -------------------------------------------
    if domain_data.get('sounds_alike'):
        score += 5

    # --- Mail capability ---------------------------------------------------
    # Prefer the full SPF/DKIM/DMARC assessment when it ran: publishing SPF on
    # a lookalike is deliberate work whose only purpose is deliverable mail.
    # MX alone only shows the domain can receive.
    mail = domain_data.get('mail_intel')
    if mail:
        from .dns_intel import score_mail_capability

        score += score_mail_capability(mail)
    elif domain_data.get('dns_mx'):
        score += 15

    # --- Live content ------------------------------------------------------
    http = threat_intel.get('http_probe') or {}
    if http:
        if http.get('https_active'):
            score += 12  # Serving HTTPS implies deliberate setup
        elif http.get('http_active'):
            score += 8

        if http.get('redirects_to'):
            score += 5

        # A valid certificate on a lookalike domain means someone did the work
        if http.get('tls_verified') is True:
            score += 5

        # --- What the page is built to collect -----------------------------
        # This is the strongest single signal the scanner produces. Registering
        # a lookalike is cheap and ambiguous; standing up a form that asks for
        # a password is neither. Weighted to dominate accordingly.
        page = http.get('page') or {}
        if page.get('is_credential_form'):
            score += 30
        elif page.get('has_password_input'):
            score += 20

        if page.get('external_form_action'):
            # A form posting to a different registrable domain is an
            # exfiltration path, not a sign-in page.
            score += 15

        if page.get('brand_mentioned') and (
            page.get('has_password_input') or page.get('form_count')
        ):
            # Naming the brand is only meaningful alongside something that
            # collects: a fan page mentioning a brand is not a phishing kit.
            score += 10

    # --- Certificate Transparency -----------------------------------------
    ct = threat_intel.get('certificate_transparency') or {}
    if ct.get('certificates_found', 0) > 0:
        score += 8  # Someone obtained a certificate for this lookalike

    return max(0, min(score, 100))
