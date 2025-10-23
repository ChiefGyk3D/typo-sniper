"""
Threat intelligence integrations for domain analysis.
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Optional, Any
from datetime import datetime


class ThreatIntelligence:
    """Threat intelligence integrations."""
    
    def __init__(self, config):
        """Initialize threat intelligence."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        # Create session with connection pooling limits for better performance
        connector = aiohttp.TCPConnector(
            limit=100,  # Max total connections
            limit_per_host=30,  # Max connections per host
            ttl_dns_cache=300  # Cache DNS for 5 minutes
        )
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
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
                        elif response.status != 200:
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
    
    async def check_urlscan(self, domain: str) -> Optional[Dict[str, Any]]:
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
                            from datetime import datetime, timezone
                            scan_date = datetime.fromisoformat(scan_time.replace('Z', '+00:00'))
                            age_days = (datetime.now(timezone.utc) - scan_date).days
                            
                            if age_days <= self.config.urlscan_max_age_days:
                                # Recent scan found, return it
                                verdicts = result.get('verdicts', {})
                                self.logger.debug(f"Found recent URLScan result for {domain} ({age_days} days old)")
                                return {
                                    'malicious': verdicts.get('overall', {}).get('malicious', False),
                                    'score': verdicts.get('overall', {}).get('score', 0),
                                    'categories': verdicts.get('overall', {}).get('categories', []),
                                    'screenshot': task.get('screenshotURL'),
                                    'report_url': task.get('reportURL'),
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
            
            # Submit new scan if needed
            if should_submit:
                return await self._submit_urlscan(domain)
            
            return None
                    
        except Exception as e:
            self.logger.error(f"URLScan check failed for {domain}: {e}")
            return None
    
    async def _submit_urlscan(self, domain: str) -> Optional[Dict[str, Any]]:
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
                    import asyncio
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
                else:
                    error_text = await response.text()
                    self.logger.error(f"URLScan submission failed for {domain}: {response.status} - {error_text}")
                    return None
                    
        except Exception as e:
            self.logger.error(f"URLScan submission failed for {domain}: {e}")
            return None
    
    async def check_certificate_transparency(self, domain: str) -> Optional[Dict[str, Any]]:
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
            # Use crt.sh API with timeout
            url = f"https://crt.sh/?q={domain}&output=json"
            
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Check if response is actually JSON (not HTML error page)
                    if 'json' not in content_type.lower():
                        self.logger.debug(f"CT log returned non-JSON for {domain} (probably no certs)")
                        return {'certificates_found': 0, 'status': 'no_certificates'}
                    
                    try:
                        data = await response.json()
                    except Exception as json_err:
                        self.logger.debug(f"CT log JSON parse error for {domain}: {json_err}")
                        return {'certificates_found': 0, 'status': 'parse_error'}
                    
                    if data and isinstance(data, list):
                        # Get most recent certificate
                        recent = data[0]
                        
                        return {
                            'certificates_found': len(data),
                            'most_recent': {
                                'issuer': recent.get('issuer_name'),
                                'not_before': recent.get('not_before'),
                                'not_after': recent.get('not_after'),
                                'common_name': recent.get('common_name'),
                            },
                            'all_names': [cert.get('common_name') for cert in data[:10]]
                        }
                    else:
                        return {'certificates_found': 0, 'status': 'no_certificates'}
                else:
                    self.logger.debug(f"CT log check returned status {response.status} for {domain}")
                    return {'certificates_found': 0, 'status': f'http_{response.status}'}
                    
        except asyncio.TimeoutError:
            self.logger.debug(f"CT log check timed out for {domain}")
            return {'certificates_found': 0, 'status': 'timeout'}
        except Exception as e:
            self.logger.debug(f"CT log check failed for {domain}: {e}")
            return {'certificates_found': 0, 'status': 'error'}
    
    async def http_probe(self, domain: str) -> Optional[Dict[str, Any]]:
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
        }
        
        # Try HTTPS first
        try:
            url = f"https://{domain}"
            timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
            
            async with self.session.get(url, timeout=timeout, allow_redirects=True) as response:
                results['https_active'] = True
                results['https_status'] = response.status
                
                if response.history:
                    results['redirects_to'] = str(response.url)
                
                # Try to extract title
                if response.status == 200:
                    try:
                        html = await response.text()
                        import re
                        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                        if title_match:
                            results['title'] = title_match.group(1)[:200]
                    except:
                        pass
                        
        except asyncio.TimeoutError:
            self.logger.debug(f"HTTPS timeout for {domain}")
        except Exception as e:
            self.logger.debug(f"HTTPS probe failed for {domain}: {e}")
        
        # Try HTTP
        try:
            url = f"http://{domain}"
            timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
            
            async with self.session.get(url, timeout=timeout, allow_redirects=True) as response:
                results['http_active'] = True
                results['http_status'] = response.status
                
                if response.history and not results['redirects_to']:
                    results['redirects_to'] = str(response.url)
                
                # Try to extract title if not already found
                if response.status == 200 and not results['title']:
                    try:
                        html = await response.text()
                        import re
                        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                        if title_match:
                            results['title'] = title_match.group(1)[:200]
                    except:
                        pass
                        
        except asyncio.TimeoutError:
            self.logger.debug(f"HTTP timeout for {domain}")
        except Exception as e:
            self.logger.debug(f"HTTP probe failed for {domain}: {e}")
        
        return results if (results['http_active'] or results['https_active']) else None
    
    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive threat intelligence analysis on domain.
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Threat intelligence report
        """
        report = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
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
            
            for (name, _), result in zip(tasks, results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error in {name} for {domain}: {result}")
                else:
                    report[name] = result
        
        return report


def calculate_risk_score(domain_data: Dict[str, Any], threat_intel: Dict[str, Any]) -> int:
    """
    Calculate risk score for a domain based on various factors.
    
    Args:
        domain_data: Domain permutation data
        threat_intel: Threat intelligence report
        
    Returns:
        Risk score (0-100, higher is more risky)
    """
    score = 0
    
    # Base score for being registered
    score += 10
    
    # URLScan indicators
    urlscan = threat_intel.get('urlscan')
    if urlscan:
        if urlscan.get('malicious'):
            score += 30
        score += int(urlscan.get('score', 0) * 20)
    
    # HTTP probe indicators
    http = threat_intel.get('http_probe')
    if http:
        if http.get('http_active') or http.get('https_active'):
            score += 15  # Active site is more concerning
        if http.get('redirects_to'):
            score += 5
    
    # Certificate Transparency
    ct = threat_intel.get('certificate_transparency')
    if ct and ct.get('certificates_found', 0) > 0:
        score += 10  # Has SSL certificate
    
    # Recent registration
    if domain_data.get('created_days_ago'):
        days = domain_data['created_days_ago']
        if days < 30:
            score += 20
        elif days < 90:
            score += 10
    
    # Cap at 100
    return min(score, 100)
