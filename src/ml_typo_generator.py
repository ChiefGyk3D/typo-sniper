"""
Synthetic typo generator for training data augmentation.

Generates realistic typosquatting domains using common attack patterns:
- Character insertion/deletion/substitution
- Character doubling
- Homoglyph substitution (visual similarity)
- Keyboard proximity errors
- TLD swaps
"""

import random
import string
from typing import List, Set, Dict
from dataclasses import dataclass


@dataclass
class TypoConfig:
    """Configuration for typo generation."""
    insertion_prob: float = 0.2
    deletion_prob: float = 0.2
    substitution_prob: float = 0.2
    doubling_prob: float = 0.15
    homoglyph_prob: float = 0.15
    keyboard_error_prob: float = 0.1
    tld_swap_prob: float = 0.1
    max_edits: int = 2  # Maximum number of edits per domain


class TypoGenerator:
    """Generate synthetic typosquatting domains."""
    
    # Common homoglyph substitutions (visual similarity)
    HOMOGLYPHS = {
        'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'α', 'а'],
        'e': ['è', 'é', 'ê', 'ë', 'е', 'ε'],
        'i': ['ì', 'í', 'î', 'ï', 'і', 'ι', '1', 'l'],
        'o': ['ò', 'ó', 'ô', 'õ', 'ö', 'о', 'ο', '0'],
        'u': ['ù', 'ú', 'û', 'ü', 'υ'],
        'c': ['ç', 'ć', 'č', 'ĉ'],
        'n': ['ñ', 'ń', 'ň'],
        's': ['š', 'ś', 'ş', '$'],
        'y': ['ý', 'ÿ', 'ŷ'],
        'z': ['ž', 'ź', 'ż'],
        '0': ['o', 'O'],
        '1': ['l', 'I', 'i'],
        'm': ['rn'],  # Two chars that look like one
        'w': ['vv'],
    }
    
    # Keyboard proximity (QWERTY layout)
    KEYBOARD_NEIGHBORS = {
        'a': 'qwsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx', 'e': 'wrsdf',
        'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb', 'i': 'ujklo', 'j': 'huikmn',
        'k': 'jiol,m', 'l': 'kop.,', 'm': 'njk,', 'n': 'bhjm', 'o': 'iklp',
        'p': 'ol[', 'q': 'wa', 'r': 'etdf', 's': 'awedxz', 't': 'ryfg',
        'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tghu',
        'z': 'asx',
    }
    
    # Common TLD swaps
    TLD_SWAPS = {
        'com': ['net', 'org', 'co', 'io', 'info', 'biz', 'online'],
        'net': ['com', 'org', 'co'],
        'org': ['com', 'net'],
    }
    
    def __init__(self, config: TypoConfig = None):
        """Initialize generator with config."""
        self.config = config or TypoConfig()
    
    def generate_typos(self, domain: str, count: int = 100) -> Set[str]:
        """
        Generate typosquatting variations of a domain.
        
        Args:
            domain: Original domain (e.g., "example.com")
            count: Number of typos to generate
            
        Returns:
            Set of unique typo domains
        """
        typos = set()
        
        # Parse domain
        parts = domain.lower().split('.')
        if len(parts) < 2:
            return typos
        
        name = '.'.join(parts[:-1])
        tld = parts[-1]
        
        # Generate typos until we have enough unique ones
        attempts = 0
        max_attempts = count * 10  # Prevent infinite loop
        
        while len(typos) < count and attempts < max_attempts:
            attempts += 1
            
            # Randomly select number of edits (weighted towards fewer)
            num_edits = random.choices(
                range(1, self.config.max_edits + 1),
                weights=[0.7, 0.3][:self.config.max_edits]
            )[0]
            
            typo_name = name
            for _ in range(num_edits):
                typo_name = self._apply_random_transform(typo_name)
            
            # Sometimes swap TLD
            typo_tld = tld
            if random.random() < self.config.tld_swap_prob and tld in self.TLD_SWAPS:
                typo_tld = random.choice(self.TLD_SWAPS[tld])
            
            typo = f"{typo_name}.{typo_tld}"
            
            # Only add if different from original
            if typo != domain:
                typos.add(typo)
        
        return typos
    
    def _apply_random_transform(self, text: str) -> str:
        """Apply a random transformation to the text."""
        if not text:
            return text
        
        transforms = []
        
        if random.random() < self.config.insertion_prob:
            transforms.append(self._insert_char)
        if random.random() < self.config.deletion_prob:
            transforms.append(self._delete_char)
        if random.random() < self.config.substitution_prob:
            transforms.append(self._substitute_char)
        if random.random() < self.config.doubling_prob:
            transforms.append(self._double_char)
        if random.random() < self.config.homoglyph_prob:
            transforms.append(self._homoglyph_substitute)
        if random.random() < self.config.keyboard_error_prob:
            transforms.append(self._keyboard_error)
        
        if not transforms:
            # Fallback to substitution
            return self._substitute_char(text)
        
        # Apply random transform
        transform = random.choice(transforms)
        return transform(text)
    
    def _insert_char(self, text: str) -> str:
        """Insert a random character."""
        if len(text) == 0:
            return text
        
        pos = random.randint(0, len(text))
        char = random.choice(string.ascii_lowercase + string.digits)
        return text[:pos] + char + text[pos:]
    
    def _delete_char(self, text: str) -> str:
        """Delete a random character."""
        if len(text) <= 1:
            return text
        
        pos = random.randint(0, len(text) - 1)
        return text[:pos] + text[pos + 1:]
    
    def _substitute_char(self, text: str) -> str:
        """Substitute a random character."""
        if len(text) == 0:
            return text
        
        pos = random.randint(0, len(text) - 1)
        char = random.choice(string.ascii_lowercase + string.digits)
        return text[:pos] + char + text[pos + 1:]
    
    def _double_char(self, text: str) -> str:
        """Double a random character."""
        if len(text) == 0:
            return text
        
        pos = random.randint(0, len(text) - 1)
        return text[:pos + 1] + text[pos] + text[pos + 1:]
    
    def _homoglyph_substitute(self, text: str) -> str:
        """Substitute with visually similar character."""
        if len(text) == 0:
            return text
        
        # Find positions with homoglyphs available
        eligible_positions = [
            i for i, c in enumerate(text.lower())
            if c in self.HOMOGLYPHS
        ]
        
        if not eligible_positions:
            return text
        
        pos = random.choice(eligible_positions)
        char = text[pos].lower()
        homoglyph = random.choice(self.HOMOGLYPHS[char])
        
        return text[:pos] + homoglyph + text[pos + 1:]
    
    def _keyboard_error(self, text: str) -> str:
        """Substitute with keyboard neighbor."""
        if len(text) == 0:
            return text
        
        # Find positions with neighbors available
        eligible_positions = [
            i for i, c in enumerate(text.lower())
            if c in self.KEYBOARD_NEIGHBORS
        ]
        
        if not eligible_positions:
            return text
        
        pos = random.choice(eligible_positions)
        char = text[pos].lower()
        neighbor = random.choice(self.KEYBOARD_NEIGHBORS[char])
        
        return text[:pos] + neighbor + text[pos + 1:]
    
    def generate_batch(self, domains: List[str], typos_per_domain: int = 50) -> Dict[str, Set[str]]:
        """
        Generate typos for multiple domains.
        
        Args:
            domains: List of original domains
            typos_per_domain: Number of typos per domain
            
        Returns:
            Dict mapping original domain to set of typos
        """
        results = {}
        for domain in domains:
            results[domain] = self.generate_typos(domain, typos_per_domain)
        return results


def main():
    """Example usage."""
    generator = TypoGenerator()
    
    # Test domains
    test_domains = ['google.com', 'facebook.com', 'amazon.com']
    
    for domain in test_domains:
        print(f"\n=== Typos for {domain} ===")
        typos = generator.generate_typos(domain, count=20)
        for typo in sorted(typos)[:10]:
            print(f"  {typo}")
        print(f"  ... ({len(typos)} total)")


if __name__ == '__main__':
    main()
