"""
Feature extraction pipeline for ML-based typosquatting detection.

Extracts rich features from domains including:
- Lexical features (edit distances, character patterns)
- WHOIS features (age, registrar, privacy flags)
- DNS features (record types, MX presence, AS reputation)
- Behavioral features (TLS, hosting patterns)
- Visual features (homoglyph presence)
"""

import re
import string
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from collections import Counter
import numpy as np


class FeatureExtractor:
    """Extract features from domain data for ML classification."""
    
    def __init__(self):
        """Initialize feature extractor."""
        # Suspicious registrars (example list - expand based on observations)
        self.suspicious_registrars = {
            'namecheap', 'godaddy', 'enom'  # Common but often used by attackers
        }
        
        # Reputable registrars
        self.reputable_registrars = {
            'markmonitor', 'cscglobal', 'corporatedomains'
        }
    
    def extract_features(self, domain_data: Dict[str, Any], brand: str) -> Dict[str, float]:
        """
        Extract all features from domain data.
        
        Args:
            domain_data: Domain information including WHOIS, DNS, etc.
            brand: Original brand domain to compare against
            
        Returns:
            Dictionary of feature name -> value
        """
        features = {}
        
        domain = domain_data.get('domain', '')
        
        # Lexical features
        features.update(self._extract_lexical_features(domain, brand))
        
        # WHOIS features
        features.update(self._extract_whois_features(domain_data))
        
        # DNS features
        features.update(self._extract_dns_features(domain_data))
        
        # Behavioral features
        features.update(self._extract_behavioral_features(domain_data))
        
        # Visual/homoglyph features
        features.update(self._extract_visual_features(domain, brand))
        
        return features
    
    def _extract_lexical_features(self, domain: str, brand: str) -> Dict[str, float]:
        """Extract lexical/string-based features."""
        features = {}
        
        # Extract domain name without TLD
        domain_name = domain.split('.')[0].lower()
        brand_name = brand.split('.')[0].lower()
        
        # Basic length features
        features['length'] = len(domain_name)
        features['length_diff'] = abs(len(domain_name) - len(brand_name))
        features['length_ratio'] = len(domain_name) / max(len(brand_name), 1)
        
        # Edit distances
        features['levenshtein_distance'] = self._levenshtein_distance(domain_name, brand_name)
        features['normalized_levenshtein'] = features['levenshtein_distance'] / max(len(brand_name), 1)
        features['jaro_winkler'] = self._jaro_winkler(domain_name, brand_name)
        
        # Character composition
        features['digit_count'] = sum(c.isdigit() for c in domain_name)
        features['digit_ratio'] = features['digit_count'] / max(len(domain_name), 1)
        features['hyphen_count'] = domain_name.count('-')
        features['vowel_count'] = sum(c in 'aeiou' for c in domain_name)
        features['vowel_ratio'] = features['vowel_count'] / max(len(domain_name), 1)
        features['consonant_count'] = sum(c in 'bcdfghjklmnpqrstvwxyz' for c in domain_name)
        features['consonant_ratio'] = features['consonant_count'] / max(len(domain_name), 1)
        
        # Repeated characters
        features['repeated_chars'] = self._count_repeated_chars(domain_name)
        features['max_char_run'] = self._max_char_run(domain_name)
        
        # Character bigrams/trigrams similarity
        features['bigram_similarity'] = self._ngram_similarity(domain_name, brand_name, n=2)
        features['trigram_similarity'] = self._ngram_similarity(domain_name, brand_name, n=3)
        
        # Common typo patterns
        features['insertion_likely'] = float(len(domain_name) == len(brand_name) + 1)
        features['deletion_likely'] = float(len(domain_name) == len(brand_name) - 1)
        features['transposition_likely'] = self._check_transposition(domain_name, brand_name)
        
        # Entropy (predictability)
        features['entropy'] = self._calculate_entropy(domain_name)
        
        # Pronounceability score (simple heuristic)
        features['pronounceability'] = self._pronounceability_score(domain_name)
        
        return features
    
    def _extract_whois_features(self, domain_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract WHOIS-based features."""
        features = {}
        
        # Domain age
        created_dates = domain_data.get('whois_created', [])
        if created_dates:
            try:
                created = datetime.fromisoformat(str(created_dates[0]).replace('Z', '+00:00'))
                age_days = (datetime.now(timezone.utc) - created).days
                features['domain_age_days'] = age_days
                features['domain_age_months'] = age_days / 30.0
                features['domain_age_years'] = age_days / 365.0
                features['is_new_domain'] = float(age_days < 30)  # Less than 30 days
                features['is_very_new_domain'] = float(age_days < 7)  # Less than 1 week
            except:
                features['domain_age_days'] = -1
                features['domain_age_months'] = -1
                features['domain_age_years'] = -1
                features['is_new_domain'] = 0
                features['is_very_new_domain'] = 0
        else:
            features['domain_age_days'] = -1
            features['domain_age_months'] = -1
            features['domain_age_years'] = -1
            features['is_new_domain'] = 0
            features['is_very_new_domain'] = 0
        
        # Registrar reputation
        registrar = domain_data.get('whois_registrar', '').lower()
        features['has_registrar_info'] = float(bool(registrar))
        features['suspicious_registrar'] = float(any(s in registrar for s in self.suspicious_registrars))
        features['reputable_registrar'] = float(any(s in registrar for s in self.reputable_registrars))
        
        # Privacy/proxy detection
        registrant = domain_data.get('whois_registrant', '')
        features['privacy_protected'] = float(
            'privacy' in str(registrant).lower() or 
            'proxy' in str(registrant).lower() or
            'redacted' in str(registrant).lower()
        )
        
        # WHOIS completeness
        features['has_registrant'] = float(bool(registrant))
        features['has_org'] = float(bool(domain_data.get('whois_org')))
        features['has_country'] = float(bool(domain_data.get('whois_country')))
        features['has_emails'] = float(bool(domain_data.get('whois_emails')))
        
        return features
    
    def _extract_dns_features(self, domain_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract DNS-based features."""
        features = {}
        
        # DNS records presence
        features['has_a_record'] = float(bool(domain_data.get('dns_a')))
        features['has_aaaa_record'] = float(bool(domain_data.get('dns_aaaa')))
        features['has_mx_record'] = float(bool(domain_data.get('dns_mx')))
        features['has_ns_record'] = float(bool(domain_data.get('dns_ns')))
        features['has_mx_spy'] = float(domain_data.get('mx_spy', False))
        
        # IP count
        a_records = domain_data.get('dns_a', [])
        features['ip_count'] = len(a_records)
        features['has_multiple_ips'] = float(len(a_records) > 1)
        
        # Name server count
        ns_records = domain_data.get('whois_name_servers', [])
        features['ns_count'] = len(ns_records)
        
        # Common hosting indicators (can expand)
        features['uses_cloudflare'] = float(any('cloudflare' in str(ns).lower() for ns in ns_records))
        features['uses_aws'] = float(any('amazon' in str(ns).lower() or 'aws' in str(ns).lower() for ns in ns_records))
        
        return features
    
    def _extract_behavioral_features(self, domain_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract behavioral/operational features."""
        features = {}
        
        # Threat intelligence signals
        threat_intel = domain_data.get('threat_intel', {})
        
        # URLScan results
        urlscan = threat_intel.get('urlscan', {})
        if urlscan:
            features['urlscan_malicious'] = float(urlscan.get('malicious', False))
            features['urlscan_score'] = float(urlscan.get('score', 0))
            features['has_urlscan_data'] = 1.0
        else:
            features['urlscan_malicious'] = 0.0
            features['urlscan_score'] = 0.0
            features['has_urlscan_data'] = 0.0
        
        # Certificate transparency
        ct = threat_intel.get('certificate_transparency', {})
        if ct:
            features['ct_cert_count'] = float(ct.get('certificates_found', 0))
            features['has_ssl_cert'] = float(features['ct_cert_count'] > 0)
        else:
            features['ct_cert_count'] = 0.0
            features['has_ssl_cert'] = 0.0
        
        # HTTP probe
        http = threat_intel.get('http_probe', {})
        if http:
            features['http_active'] = float(http.get('http_active', False))
            features['https_active'] = float(http.get('https_active', False))
            features['http_status'] = float(http.get('http_status', 0))
            features['has_redirect'] = float(bool(http.get('redirects_to')))
        else:
            features['http_active'] = 0.0
            features['https_active'] = 0.0
            features['http_status'] = 0.0
            features['has_redirect'] = 0.0
        
        return features
    
    def _extract_visual_features(self, domain: str, brand: str) -> Dict[str, float]:
        """Extract visual similarity features."""
        features = {}
        
        domain_name = domain.split('.')[0].lower()
        brand_name = brand.split('.')[0].lower()
        
        # Check for common homoglyphs
        homoglyph_chars = {'0', 'o', 'O', '1', 'l', 'I', 'i'}
        features['contains_confusable_chars'] = float(any(c in homoglyph_chars for c in domain_name))
        features['confusable_char_count'] = sum(c in homoglyph_chars for c in domain_name)
        
        # Check for non-ASCII characters
        features['has_non_ascii'] = float(any(ord(c) > 127 for c in domain_name))
        features['non_ascii_count'] = sum(ord(c) > 127 for c in domain_name)
        
        # Visual similarity patterns
        features['has_rn_sequence'] = float('rn' in domain_name)  # Could look like 'm'
        features['has_vv_sequence'] = float('vv' in domain_name)  # Could look like 'w'
        features['has_cl_sequence'] = float('cl' in domain_name)  # Could look like 'd'
        
        return features
    
    # Helper methods
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _jaro_winkler(self, s1: str, s2: str) -> float:
        """Calculate Jaro-Winkler similarity."""
        # Simplified version
        if s1 == s2:
            return 1.0
        
        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0
        
        max_dist = max(len1, len2) // 2 - 1
        matches = 0
        hash_s1 = [0] * len1
        hash_s2 = [0] * len2
        
        for i in range(len1):
            for j in range(max(0, i - max_dist), min(len2, i + max_dist + 1)):
                if s1[i] == s2[j] and hash_s2[j] == 0:
                    hash_s1[i] = 1
                    hash_s2[j] = 1
                    matches += 1
                    break
        
        if matches == 0:
            return 0.0
        
        # Calculate Jaro similarity
        jaro = (matches / len1 + matches / len2 + (matches - self._transpositions(s1, s2, hash_s1, hash_s2)) / matches) / 3.0
        
        # Jaro-Winkler modification
        prefix = 0
        for i in range(min(len1, len2)):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break
        prefix = min(4, prefix)
        
        return jaro + prefix * 0.1 * (1 - jaro)
    
    def _transpositions(self, s1: str, s2: str, hash_s1: List[int], hash_s2: List[int]) -> int:
        """Count transpositions for Jaro calculation."""
        trans = 0
        point = 0
        for i in range(len(s1)):
            if hash_s1[i]:
                while hash_s2[point] == 0:
                    point += 1
                if s1[i] != s2[point]:
                    trans += 1
                point += 1
        return trans // 2
    
    def _count_repeated_chars(self, s: str) -> int:
        """Count number of repeated characters."""
        if len(s) <= 1:
            return 0
        count = 0
        for i in range(len(s) - 1):
            if s[i] == s[i + 1]:
                count += 1
        return count
    
    def _max_char_run(self, s: str) -> int:
        """Find maximum consecutive run of same character."""
        if not s:
            return 0
        max_run = 1
        current_run = 1
        for i in range(1, len(s)):
            if s[i] == s[i - 1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1
        return max_run
    
    def _ngram_similarity(self, s1: str, s2: str, n: int = 2) -> float:
        """Calculate n-gram similarity."""
        def get_ngrams(s, n):
            return set(s[i:i+n] for i in range(len(s) - n + 1))
        
        if len(s1) < n or len(s2) < n:
            return 0.0
        
        ngrams1 = get_ngrams(s1, n)
        ngrams2 = get_ngrams(s2, n)
        
        if not ngrams1 or not ngrams2:
            return 0.0
        
        intersection = len(ngrams1 & ngrams2)
        union = len(ngrams1 | ngrams2)
        
        return intersection / union if union > 0 else 0.0
    
    def _check_transposition(self, s1: str, s2: str) -> float:
        """Check if strings differ by single transposition."""
        if len(s1) != len(s2):
            return 0.0
        
        diffs = []
        for i, (c1, c2) in enumerate(zip(s1, s2)):
            if c1 != c2:
                diffs.append(i)
        
        if len(diffs) == 2:
            i, j = diffs
            if i + 1 == j and s1[i] == s2[j] and s1[j] == s2[i]:
                return 1.0
        
        return 0.0
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string."""
        if not s:
            return 0.0
        
        counts = Counter(s)
        length = len(s)
        entropy = -sum((count / length) * np.log2(count / length) for count in counts.values())
        
        return entropy
    
    def _pronounceability_score(self, s: str) -> float:
        """
        Simple pronounceability heuristic.
        Based on vowel/consonant patterns.
        """
        if not s:
            return 0.0
        
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        # Count vowel-consonant transitions (more = more pronounceable)
        transitions = 0
        for i in range(len(s) - 1):
            c1_vowel = s[i] in vowels
            c2_vowel = s[i + 1] in vowels
            if c1_vowel != c2_vowel:
                transitions += 1
        
        # Penalize long consonant runs
        max_consonant_run = 0
        current_run = 0
        for c in s:
            if c in consonants:
                current_run += 1
                max_consonant_run = max(max_consonant_run, current_run)
            else:
                current_run = 0
        
        score = transitions / max(len(s) - 1, 1)
        score -= max_consonant_run * 0.1
        
        return max(0.0, min(1.0, score))


def main():
    """Example usage."""
    extractor = FeatureExtractor()
    
    # Example domain data
    domain_data = {
        'domain': 'gooogle.com',
        'whois_created': ['2024-01-15'],
        'whois_registrar': 'Namecheap',
        'dns_a': ['1.2.3.4'],
        'dns_mx': ['mail.gooogle.com'],
        'threat_intel': {
            'urlscan': {'malicious': False, 'score': 0},
        }
    }
    
    brand = 'google.com'
    
    features = extractor.extract_features(domain_data, brand)
    
    print("=== Extracted Features ===\n")
    for feature_name, value in sorted(features.items()):
        print(f"{feature_name:30s}: {value:8.3f}")


if __name__ == '__main__':
    main()
