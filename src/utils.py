"""
Utility functions for Typo Sniper.
"""

import logging
import re
from typing import Optional

from rich.logging import RichHandler


def setup_logging(level: int = logging.INFO) -> None:
    """
    Setup logging configuration with Rich handler.
    
    Args:
        level: Logging level
    """
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)]
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('charset_normalizer').setLevel(logging.WARNING)


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid, False otherwise
    """
    # Basic domain validation regex
    # Matches: example.com, sub.example.com, example.co.uk, etc.
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if not domain or len(domain) > 253:
        return False
    
    return bool(re.match(pattern, domain))


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters for filenames
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')
    
    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    
    return sanitized or 'unnamed'


def format_bytes(bytes_size: int) -> str:
    """
    Format bytes to human-readable string.
    
    Args:
        bytes_size: Size in bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def parse_fuzzer_name(fuzzer_code: str) -> str:
    """
    Convert fuzzer code to human-readable name.
    
    Args:
        fuzzer_code: Fuzzer code from dnstwist
        
    Returns:
        Human-readable fuzzer name
    """
    fuzzer_names = {
        'addition': 'Character Addition',
        'bitsquatting': 'Bit Squatting',
        'homoglyph': 'Homoglyph',
        'hyphenation': 'Hyphenation',
        'insertion': 'Character Insertion',
        'omission': 'Character Omission',
        'repetition': 'Character Repetition',
        'replacement': 'Character Replacement',
        'subdomain': 'Subdomain',
        'transposition': 'Character Transposition',
        'vowel-swap': 'Vowel Swap',
        'various': 'Various Techniques',
        'dictionary': 'Dictionary Words',
        'tld-swap': 'TLD Swap',
    }
    
    return fuzzer_names.get(fuzzer_code, fuzzer_code.title())
