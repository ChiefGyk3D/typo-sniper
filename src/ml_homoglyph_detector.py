"""
Homoglyph detection for visually similar character substitutions.

Detects sophisticated typosquatting attacks using:
- Unicode confusables (official Unicode data)
- Visual similarity scoring
- Common attack patterns (0→O, 1→l, rn→m, etc.)
"""

from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
import unicodedata


@dataclass
class HomoglyphMatch:
    """Result of homoglyph detection."""
    domain: str
    brand: str
    suspicious_chars: List[Tuple[int, str, str]]  # (position, original, substitution)
    similarity_score: float
    visual_distance: int


class HomoglyphDetector:
    """Detect homoglyph-based typosquatting."""
    
    # Unicode confusables (subset of official Unicode Security Mechanisms)
    CONFUSABLES = {
        # Latin lookalikes
        'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å', 'α', 'ɑ'],
        'b': ['ƅ', 'Ь', 'ъ'],
        'c': ['с', 'ϲ', 'ⅽ', 'ç'],
        'e': ['е', 'ė', 'ē', 'ë', 'ê', 'é', 'è', 'ε', 'ҽ'],
        'g': ['ɡ', 'ց', 'ǥ'],
        'h': ['һ', 'հ', 'ℎ'],
        'i': ['і', 'ı', 'ɩ', 'ι', 'ⅰ', '1', 'l', '|'],
        'j': ['ј', 'ϳ'],
        'k': ['κ', 'ⲕ'],
        'l': ['ӏ', 'ⅼ', '1', 'I', 'i', '|'],
        'm': ['rn', 'ⅿ', 'м'],
        'n': ['ո', 'ռ', 'ո'],
        'o': ['о', 'ο', 'օ', 'ȯ', 'ȱ', 'ơ', '0'],
        'p': ['р', 'ρ', 'ⲣ'],
        'q': ['ԛ', 'գ'],
        'r': ['г', 'ⲅ'],
        's': ['ѕ', 'ꜱ', 'ʂ', '$'],
        't': ['т', 'τ', 'ⲧ'],
        'u': ['υ', 'ս', 'ü', 'ú', 'ù'],
        'v': ['ѵ', 'ν', 'ⅴ', 'vv'],
        'w': ['ԝ', 'ѡ', 'ⱳ', 'vv'],
        'x': ['х', 'ⅹ', 'ⲭ'],
        'y': ['у', 'ү', 'ȳ', 'ÿ'],
        'z': ['ᴢ', 'ż', 'ž'],
        
        # Numbers
        '0': ['o', 'O', 'о', 'ο', 'օ'],
        '1': ['l', 'I', 'i', '|', 'ӏ'],
        '2': ['ᒿ'],
        '3': ['з', 'ȝ'],
        '5': ['Ƽ'],
        '6': ['б'],
        '8': ['৪'],
        
        # Special cases (multi-char)
        'rn': ['m'],
        'vv': ['w'],
        'cl': ['d'],
    }
    
    # Reverse mapping for detection
    CONFUSABLES_REVERSE = {}
    for original, lookalikes in CONFUSABLES.items():
        for lookalike in lookalikes:
            if lookalike not in CONFUSABLES_REVERSE:
                CONFUSABLES_REVERSE[lookalike] = []
            CONFUSABLES_REVERSE[lookalike].append(original)
    
    def __init__(self):
        """Initialize detector."""
        pass
    
    def detect(self, domain: str, brand: str, threshold: float = 0.7) -> HomoglyphMatch:
        """
        Detect homoglyph substitutions in domain vs brand.
        
        Args:
            domain: Domain to check (e.g., "gооgle.com")
            brand: Original brand (e.g., "google.com")
            threshold: Minimum similarity score to flag (0-1)
            
        Returns:
            HomoglyphMatch with detection results
        """
        # Extract domain names without TLD
        domain_name = domain.split('.')[0].lower()
        brand_name = brand.split('.')[0].lower()
        
        # Find suspicious characters
        suspicious = []
        normalized = []
        
        i = 0
        while i < len(domain_name):
            char = domain_name[i]
            
            # Check for multi-char confusables (e.g., "rn" → "m")
            if i < len(domain_name) - 1:
                two_char = domain_name[i:i+2]
                if two_char in self.CONFUSABLES_REVERSE:
                    possible_originals = self.CONFUSABLES_REVERSE[two_char]
                    suspicious.append((i, two_char, possible_originals[0]))
                    normalized.append(possible_originals[0])
                    i += 2
                    continue
            
            # Check single char confusables
            if char in self.CONFUSABLES_REVERSE:
                possible_originals = self.CONFUSABLES_REVERSE[char]
                # Pick most likely based on context (first match for now)
                original = possible_originals[0]
                suspicious.append((i, char, original))
                normalized.append(original)
            else:
                normalized.append(char)
            
            i += 1
        
        # Calculate similarity
        normalized_domain = ''.join(normalized)
        similarity = self._calculate_similarity(normalized_domain, brand_name)
        visual_distance = self._visual_distance(domain_name, brand_name)
        
        return HomoglyphMatch(
            domain=domain,
            brand=brand,
            suspicious_chars=suspicious,
            similarity_score=similarity,
            visual_distance=visual_distance
        )
    
    def is_homoglyph_attack(self, domain: str, brand: str, threshold: float = 0.8) -> bool:
        """
        Check if domain is likely a homoglyph attack on brand.
        
        Args:
            domain: Domain to check
            brand: Brand to compare against
            threshold: Minimum similarity after normalization
            
        Returns:
            True if likely homoglyph attack
        """
        match = self.detect(domain, brand, threshold)
        
        # Flag if:
        # 1. Has suspicious chars AND
        # 2. High similarity after normalization
        return len(match.suspicious_chars) > 0 and match.similarity_score >= threshold
    
    def normalize_domain(self, domain: str) -> str:
        """
        Normalize domain by replacing homoglyphs with ASCII equivalents.
        
        Args:
            domain: Domain to normalize
            
        Returns:
            Normalized domain
        """
        domain_name = domain.split('.')[0]
        tld = '.'.join(domain.split('.')[1:]) if '.' in domain else ''
        
        normalized = []
        i = 0
        while i < len(domain_name):
            char = domain_name[i]
            
            # Check multi-char
            if i < len(domain_name) - 1:
                two_char = domain_name[i:i+2]
                if two_char in self.CONFUSABLES_REVERSE:
                    normalized.append(self.CONFUSABLES_REVERSE[two_char][0])
                    i += 2
                    continue
            
            # Check single char
            if char in self.CONFUSABLES_REVERSE:
                normalized.append(self.CONFUSABLES_REVERSE[char][0])
            else:
                normalized.append(char)
            
            i += 1
        
        result = ''.join(normalized)
        return f"{result}.{tld}" if tld else result
    
    def find_homoglyph_variants(self, brand: str, domains: List[str], threshold: float = 0.8) -> List[HomoglyphMatch]:
        """
        Find all domains that are homoglyph variants of brand.
        
        Args:
            brand: Original brand
            domains: List of domains to check
            threshold: Minimum similarity threshold
            
        Returns:
            List of HomoglyphMatch for suspicious domains
        """
        matches = []
        for domain in domains:
            match = self.detect(domain, brand)
            if match.suspicious_chars and match.similarity_score >= threshold:
                matches.append(match)
        
        return matches
    
    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate string similarity (0-1)."""
        if not s1 or not s2:
            return 0.0
        
        # Use Levenshtein-based similarity
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        
        distance = self._levenshtein_distance(s1, s2)
        return 1.0 - (distance / max_len)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost of insertions, deletions, substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _visual_distance(self, s1: str, s2: str) -> int:
        """
        Calculate visual distance (number of visually different characters).
        
        This is different from edit distance - it counts how many positions
        have visually different characters.
        """
        min_len = min(len(s1), len(s2))
        different = abs(len(s1) - len(s2))  # Length difference
        
        for i in range(min_len):
            if s1[i] != s2[i]:
                # Check if they're visual confusables
                if s1[i] not in self.CONFUSABLES_REVERSE or \
                   s2[i] not in self.CONFUSABLES.get(self.CONFUSABLES_REVERSE[s1[i]][0], []):
                    different += 1
        
        return different
    
    def get_unicode_info(self, char: str) -> Dict[str, str]:
        """Get Unicode information for a character."""
        try:
            return {
                'char': char,
                'name': unicodedata.name(char),
                'category': unicodedata.category(char),
                'block': self._get_unicode_block(char),
                'codepoint': f"U+{ord(char):04X}"
            }
        except ValueError:
            return {'char': char, 'name': 'Unknown', 'category': 'Unknown'}
    
    def _get_unicode_block(self, char: str) -> str:
        """Determine Unicode block of character."""
        code = ord(char)
        
        if 0x0000 <= code <= 0x007F:
            return "Basic Latin"
        elif 0x0400 <= code <= 0x04FF:
            return "Cyrillic"
        elif 0x0370 <= code <= 0x03FF:
            return "Greek"
        elif 0x1D00 <= code <= 0x1DBF:
            return "Phonetic Extensions"
        else:
            return "Other"


def main():
    """Example usage."""
    detector = HomoglyphDetector()
    
    # Test cases
    test_cases = [
        ("gооgle.com", "google.com"),  # Cyrillic 'о' instead of Latin 'o'
        ("apple.com", "apple.com"),  # No homoglyphs
        ("раypal.com", "paypal.com"),  # Cyrillic 'р' and 'а'
        ("microsоft.com", "microsoft.com"),  # Cyrillic 'о'
    ]
    
    print("=== Homoglyph Detection Tests ===\n")
    for domain, brand in test_cases:
        match = detector.detect(domain, brand)
        print(f"Domain: {domain}")
        print(f"Brand:  {brand}")
        print(f"Suspicious chars: {len(match.suspicious_chars)}")
        for pos, char, original in match.suspicious_chars:
            info = detector.get_unicode_info(char)
            print(f"  Position {pos}: '{char}' ({info['name']}) → '{original}'")
        print(f"Similarity: {match.similarity_score:.2f}")
        print(f"Is attack: {detector.is_homoglyph_attack(domain, brand)}")
        print(f"Normalized: {detector.normalize_domain(domain)}\n")


if __name__ == '__main__':
    main()
