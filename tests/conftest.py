"""Shared pytest fixtures and import setup for the Typo Sniper test suite."""

import sys
from pathlib import Path

import pytest

# The application modules live in src/ and import each other by bare name
# (e.g. "from config import Config"), matching how the CLI is executed.
SRC = Path(__file__).resolve().parent.parent / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def config(tmp_path):
    """A Config pointed at a temporary cache directory."""
    from config import Config

    cfg = Config()
    cfg.cache_dir = tmp_path / 'cache'
    cfg.output_dir = tmp_path / 'out'
    cfg.use_cache = False
    return cfg


@pytest.fixture
def sample_results():
    """A scan result containing one benign and one hostile permutation."""
    return [
        {
            'original_domain': 'example.com',
            'scan_date': '2026-01-15',
            'total_permutations': 2,
            'registered_count': 2,
            'filtered_count': 2,
            'whois_succeeded': 2,
            'whois_failed': 0,
            'permutations': [
                {
                    'domain': 'examp1e.com',
                    'fuzzer': 'homoglyph',
                    'risk_score': 85,
                    'created_days_ago': 4,
                    'is_recent': True,
                    'dns_a': ['203.0.113.10'],
                    'dns_mx': ['mail.examp1e.com'],
                    'whois_created': ['2026-01-11'],
                    'whois_registrant': 'Totally Legit Ltd',
                    'whois_org': 'Legit',
                    'threat_intel': {
                        'urlscan': {
                            'malicious': True,
                            'score': 90,
                            'report_url': 'https://urlscan.io/result/abc/',
                        },
                        'http_probe': {'https_active': True, 'https_status': 200},
                        'certificate_transparency': {'certificates_found': 2},
                    },
                },
                {
                    'domain': 'exampl.com',
                    'fuzzer': 'omission',
                    'risk_score': 15,
                    'created_days_ago': 4000,
                    'is_recent': False,
                    'dns_a': ['203.0.113.20'],
                    'whois_created': ['2015-03-02'],
                    'whois_registrant': 'Old Owner',
                },
            ],
        }
    ]
