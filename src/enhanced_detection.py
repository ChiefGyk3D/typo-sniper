"""
Enhanced typosquatting detection algorithms.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import logging
import re
from itertools import combinations, product

logger = logging.getLogger(__name__)


class ComboSquattingDetector:
    """Detect combo-squatting variations (brand + keywords)."""
    
    # Common keywords used in combo-squatting attacks
    COMMON_KEYWORDS = [
        'login', 'secure', 'account', 'verify', 'update', 'confirm',
        'support', 'help', 'service', 'portal', 'mail', 'webmail',
        'admin', 'manage', 'auth', 'signin', 'signup', 'register',
        'password', 'reset', 'recovery', 'validation', 'checkout',
        'payment', 'billing', 'invoice', 'official', 'app', 'mobile',
        'online', 'web', 'secure', 'ssl', 'https', 'safe', 'protected',
        'customer', 'client', 'user', 'member', 'premium', 'pro',
        'cloud', 'server', 'host', 'vpn', 'proxy', 'cdn',
        'download', 'update', 'upgrade', 'install', 'software',
        'security', 'protection', 'antivirus', 'firewall', 'defender'
    ]

    # Underscores are not valid in hostnames, so they are not a separator here
    SEPARATORS = ['-', '']

    # Registrable-domain splitting uses the Public Suffix List. The previous
    # hardcoded tuple covered perhaps forty suffixes out of several thousand,
    # so anything outside it (example.com.br, example.github.io) was split
    # wrongly and generated variations in the wrong namespace.
    _psl = None
    _psl_checked = False

    # Fallback for the handful of suffixes that matter most, used only when
    # publicsuffixlist is not installed
    FALLBACK_SUFFIXES = (
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
        'com.au', 'net.au', 'org.au',
        'co.nz', 'co.za', 'co.jp', 'co.in',
        'com.br', 'com.cn', 'com.mx', 'com.sg', 'com.tr',
    )

    @classmethod
    def _get_psl(cls):
        """Load the Public Suffix List once, or None when unavailable."""
        if cls._psl_checked:
            return cls._psl

        cls._psl_checked = True
        try:
            from publicsuffixlist import PublicSuffixList

            cls._psl = PublicSuffixList()
        except ImportError:
            logger.warning(
                "publicsuffixlist is not installed; falling back to a small "
                "hardcoded suffix list. Multi-label domains outside it may be "
                "split incorrectly."
            )
            cls._psl = None

        return cls._psl

    @classmethod
    def split_domain(cls, domain: str):
        """
        Split a domain into its registrable label and public suffix.

        Args:
            domain: Domain such as "example.co.uk" or "example.github.io"

        Returns:
            Tuple of (brand, suffix), e.g. ("example", "co.uk")
        """
        domain = domain.strip().lower().rstrip('.')
        parts = [p for p in domain.split('.') if p]

        if len(parts) < 2:
            return (parts[0] if parts else domain), 'com'

        psl = cls._get_psl()
        if psl is not None:
            suffix = psl.publicsuffix(domain)
            if suffix and suffix != domain:
                remainder = domain[: -(len(suffix) + 1)].split('.')
                if remainder and remainder[-1]:
                    return remainder[-1], suffix

        # Fallback: check the two-label suffixes we know about
        last_two = '.'.join(parts[-2:])
        if len(parts) >= 3 and last_two in cls.FALLBACK_SUFFIXES:
            return parts[-3], last_two

        return parts[-2], parts[-1]

    @staticmethod
    def generate_combosquats(domain: str, keywords: list[str] | None = None) -> set[str]:
        """
        Generate combo-squatting variations.
        
        Args:
            domain: Base domain (without TLD)
            keywords: Custom keywords (uses defaults if None)
            
        Returns:
            Set of combo-squatting domain variations
        """
        if keywords is None:
            keywords = ComboSquattingDetector.COMMON_KEYWORDS
        
        brand, tld = ComboSquattingDetector.split_domain(domain)

        variations = set()

        # Deduplicate while preserving the caller's ordering intent
        for keyword in dict.fromkeys(keywords):
            for separator in ComboSquattingDetector.SEPARATORS:
                for candidate in (
                    f"{brand}{separator}{keyword}.{tld}",
                    f"{keyword}{separator}{brand}.{tld}",
                ):
                    # A label may not exceed 63 characters or start/end with a
                    # hyphen; such names can never resolve, so skip the lookup.
                    label = candidate.split('.')[0]
                    if len(label) > 63 or label.startswith('-') or label.endswith('-'):
                        continue
                    if candidate != domain:
                        variations.add(candidate)

        return variations


class SoundAlikeDetector:
    """Detect phonetically similar domains using Soundex and Metaphone algorithms."""
    
    @staticmethod
    def soundex(name: str) -> str:
        """
        Generate Soundex code for a name.
        
        Args:
            name: String to encode
            
        Returns:
            Soundex code
        """
        name = ''.join(c for c in name.upper() if c.isalpha())

        if not name:
            return '0000'

        # Keep first letter
        soundex = name[0]
        
        # Encoding table
        codes = {
            'BFPV': '1', 'CGJKQSXZ': '2', 'DT': '3',
            'L': '4', 'MN': '5', 'R': '6'
        }
        
        # Build code
        for char in name[1:]:
            for key, value in codes.items():
                if char in key:
                    if value != soundex[-1]:  # Avoid duplicates
                        soundex += value
                    break
        
        # Pad or truncate to 4 characters
        soundex = soundex[:4].ljust(4, '0')
        return soundex
    
    @staticmethod
    def metaphone(name: str, max_length: int = 4) -> str:
        """
        Generate Metaphone code for a name (simplified implementation).
        
        Args:
            name: String to encode
            max_length: Maximum code length
            
        Returns:
            Metaphone code
        """
        name = name.upper()
        
        # Simple transformations
        transformations = [
            (r'^KN', 'N'), (r'^GN', 'N'), (r'^PN', 'N'), (r'^AE', 'E'),
            (r'^WR', 'R'), (r'MB$', 'M'), (r'PH', 'F'), (r'TCH', 'CH'),
            (r'SCH', 'SK'), (r'SH', 'X'), (r'CIA', 'X'), (r'CH', 'X'),
            (r'C(?=[IEY])', 'S'), (r'C', 'K'), (r'DGE', 'J'), (r'DGI', 'J'),
            (r'DGY', 'J'), (r'GH(?![AEIOUY])', ''), (r'GN', 'N'),
            (r'G(?=[IEY])', 'J'), (r'G', 'K'), (r'QU', 'KW'), (r'Q', 'K'),
            (r'WH', 'W'), (r'X', 'KS'), (r'Z', 'S'),
            (r'[AEIOUYHW]', '')  # Remove vowels and similar
        ]
        
        result = name
        for pattern, replacement in transformations:
            result = re.sub(pattern, replacement, result)
        
        return result[:max_length]
    
    @staticmethod
    def are_similar(domain1: str, domain2: str) -> bool:
        """
        Check if two domains sound similar.
        
        Args:
            domain1: First domain
            domain2: Second domain
            
        Returns:
            True if domains sound similar
        """
        # Extract base names (without TLD)
        base1 = domain1.split('.')[0]
        base2 = domain2.split('.')[0]
        
        # Compare using both algorithms
        soundex_match = SoundAlikeDetector.soundex(base1) == SoundAlikeDetector.soundex(base2)
        metaphone_match = SoundAlikeDetector.metaphone(base1) == SoundAlikeDetector.metaphone(base2)
        
        return soundex_match or metaphone_match


class IDNHomographDetector:
    """Detect IDN (Internationalized Domain Name) homograph attacks."""
    
    # Common confusable characters (simplified set)
    CONFUSABLES = {
        'a': ['а', 'ɑ', 'α', 'ａ'],  # Latin a vs Cyrillic а, etc.
        'c': ['с', 'ϲ', 'ⅽ', 'ｃ'],  # Latin c vs Cyrillic с
        'e': ['е', 'ℯ', 'ｅ'],
        'i': ['і', 'ɩ', 'ι', 'ｉ'],
        'o': ['о', 'ο', 'օ', 'ｏ'],
        'p': ['р', 'ρ', 'ｐ'],
        's': ['ѕ', 'ꜱ', 'ｓ'],
        'x': ['х', 'ⅹ', 'ｘ'],
        'y': ['у', 'ү', 'ｙ'],
        '0': ['О', 'о', 'Ο', 'ο'],
        '1': ['l', 'I', 'і', 'ⅼ'],
    }
    
    @staticmethod
    def generate_homographs(domain: str) -> set[str]:
        """
        Generate IDN homograph variations.
        
        Args:
            domain: Base domain
            
        Returns:
            Set of homograph variations
        """
        base, tld = ComboSquattingDetector.split_domain(domain)

        # Find positions where confusables can be substituted
        substitution_positions = []
        for i, char in enumerate(base.lower()):
            if char in IDNHomographDetector.CONFUSABLES:
                substitution_positions.append((i, char))
        
        if not substitution_positions:
            return set()
        
        # Limit combinations to avoid explosion (max 3 substitutions)
        max_substitutions = min(3, len(substitution_positions))
        variations = set()
        
        # Generate variations with 1-3 character substitutions
        for num_subs in range(1, max_substitutions + 1):
            for positions in combinations(substitution_positions, num_subs):
                # Get all possible character combinations for these positions
                options = []
                for pos, original_char in positions:
                    options.append([(pos, char) for char in IDNHomographDetector.CONFUSABLES[original_char]])
                
                # Generate all combinations (limit to prevent explosion)
                for combo in product(*options):
                    new_base = list(base)
                    for pos, new_char in combo:
                        new_base[pos] = new_char
                    
                    variation = ''.join(new_base) + '.' + tld
                    
                    # Only add if it's different from original and is valid punycode
                    if variation != domain:
                        try:
                            # Convert to punycode
                            punycode = variation.encode('idna').decode('ascii')
                            variations.add(punycode)
                        except (UnicodeError, UnicodeDecodeError):
                            pass
                    
                    # Limit total variations
                    if len(variations) >= 50:
                        return variations
        
        return variations
    
    @staticmethod
    def is_homograph(domain: str) -> bool:
        """
        Check if domain contains homograph characters.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain contains confusable characters
        """
        base = domain.split('.')[0]

        for char in base:
            # Only non-ASCII characters make a domain an IDN homograph. The
            # confusable table also lists ASCII lookalikes (l and I stand in
            # for the digit 1), and matching those flagged every domain
            # containing the letter "l" as an homograph attack.
            if char.isascii():
                continue

            for confusable_list in IDNHomographDetector.CONFUSABLES.values():
                if char in confusable_list:
                    return True

        return False


def generate_enhanced_permutations(domain: str, config) -> set[str]:
    """
    Generate enhanced permutations based on configuration.
    
    Args:
        domain: Base domain
        config: Configuration object
        
    Returns:
        Set of enhanced domain permutations
    """
    enhanced = set()
    
    if hasattr(config, 'debug_mode') and config.debug_mode:
        logger.debug(f"Enhanced detection starting for: {domain}")
        logger.debug(f"  - enable_combosquatting: {config.enable_combosquatting}")
        logger.debug(f"  - enable_idn_homograph: {config.enable_idn_homograph}")
        logger.debug(f"  - enable_soundalike: {config.enable_soundalike}")
    
    # Combo-squatting
    if config.enable_combosquatting:
        custom = list(getattr(config, 'custom_keywords', None) or [])
        if custom and getattr(config, 'replace_default_keywords', False):
            keywords = custom
        elif custom:
            # Brand-specific terms first: they are the likeliest bait
            keywords = custom + ComboSquattingDetector.COMMON_KEYWORDS
        else:
            keywords = None
        combos = ComboSquattingDetector.generate_combosquats(domain, keywords)
        enhanced.update(combos)
        if hasattr(config, 'debug_mode') and config.debug_mode:
            logger.debug(f"  Generated {len(combos)} combo-squatting variations")
    
    # IDN Homographs
    if config.enable_idn_homograph:
        homographs = IDNHomographDetector.generate_homographs(domain)
        enhanced.update(homographs)
        if hasattr(config, 'debug_mode') and config.debug_mode:
            logger.debug(f"  Generated {len(homographs)} IDN homograph variations")
    
    if hasattr(config, 'debug_mode') and config.debug_mode:
        logger.debug(f"Enhanced detection complete: {len(enhanced)} total variations")
        if enhanced and len(enhanced) <= 10:
            logger.debug(f"  Examples: {list(enhanced)[:10]}")
    
    return enhanced
