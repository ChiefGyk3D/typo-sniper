"""
Utility functions for Typo Sniper.
"""

import logging
import re
from typing import Any

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
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip().rstrip('.')

    # Unicode domains are valid input; compare against their ASCII (punycode)
    # form so that e.g. "bücher.de" is accepted rather than silently dropped.
    try:
        ascii_domain = domain.encode('idna').decode('ascii')
    except (UnicodeError, UnicodeDecodeError):
        return False

    if len(ascii_domain) > 253:
        return False

    labels = ascii_domain.split('.')
    if len(labels) < 2:
        return False

    # Every label: 1-63 chars, alphanumeric plus inner hyphens
    label_pattern = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
    if not all(label_pattern.match(label) for label in labels):
        return False

    # The TLD must be alphabetic (or a punycode IDN TLD), never all digits
    tld = labels[-1]
    if not (tld.isalpha() or tld.lower().startswith('xn--')) or len(tld) < 2:
        return False

    return True


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


# ---------------------------------------------------------------------------
# DNS result helpers
# ---------------------------------------------------------------------------

# dnstwist reports resolver errors as sentinel strings in the dns_* lists
# (e.g. "!ServFail", "!NXDOMAIN", "!Timeout"). They are not addresses, and
# treating them as such makes unregistered domains look registered.
DNS_ERROR_PREFIX = '!'


def clean_dns_records(values: Any) -> list[str]:
    """
    Strip dnstwist error sentinels from a DNS record list.

    Args:
        values: Raw dns_a / dns_aaaa / dns_mx / dns_ns value from dnstwist

    Returns:
        List of real record values (sentinels such as "!ServFail" removed)
    """
    if not values:
        return []

    if isinstance(values, str):
        values = [values]

    cleaned = []
    for value in values:
        text = str(value).strip()
        if text and not text.startswith(DNS_ERROR_PREFIX):
            cleaned.append(text)

    return cleaned


def is_registered(permutation: dict[str, Any]) -> bool:
    """
    Determine whether a dnstwist permutation actually resolves.

    A domain counts as registered only when it has at least one genuine A or
    AAAA record. Entries whose only "record" is a resolver error sentinel are
    rejected, which is what keeps unregistered domains out of the report.

    Args:
        permutation: Permutation dictionary from dnstwist

    Returns:
        True if the domain resolves to at least one address
    """
    return bool(
        clean_dns_records(permutation.get('dns_a'))
        or clean_dns_records(permutation.get('dns_aaaa'))
    )


# ---------------------------------------------------------------------------
# Output sanitisation
# ---------------------------------------------------------------------------

# Leading characters that spreadsheet applications interpret as the start of a
# formula. WHOIS registrant/org fields and HTML page titles are attacker
# controlled, so they are neutralised before they reach a .csv or .xlsx cell.
_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def sanitize_spreadsheet_value(value: Any) -> Any:
    """
    Neutralise spreadsheet formula injection in an exported cell value.

    Args:
        value: Cell value of any type

    Returns:
        The value unchanged if it cannot start a formula, otherwise the string
        prefixed with a single quote so Excel/LibreOffice treat it as text.
    """
    if not isinstance(value, str) or not value:
        return value

    if value.startswith(_FORMULA_PREFIXES):
        return "'" + value

    return value


def safe_url(url: Any) -> str | None:
    """
    Return a URL only if it uses a scheme that is safe to put in an href.

    Blocks javascript:, data: and similar schemes that would otherwise turn a
    third-party supplied URL into script execution inside the HTML report.

    Args:
        url: Candidate URL

    Returns:
        The URL if it is http(s), otherwise None
    """
    if not url or not isinstance(url, str):
        return None

    if url.lower().startswith(('http://', 'https://')):
        return url

    return None
