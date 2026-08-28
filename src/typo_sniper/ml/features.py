"""
Feature extraction for learned triage.

Turns one permutation record into a fixed-length numeric vector. Everything
here is pure and deterministic: the same record always produces the same
vector, with no network access and no dependencies beyond the standard library.
That matters for two reasons. A feature vector computed at scan time must match
one computed later from history, or a model trained on the second scores the
first incorrectly. And a security tool's inputs should be auditable — every
number below can be traced to a field a human can look at.

Feature groups:

  * lexical   - what the name itself looks like next to the brand
  * dns       - whether it resolves, and to how much
  * registration - how new it is, and whether the registrant is hidden
  * posture   - mail capability, TLS, live HTTP, certificates
  * relational - how the name relates to the domain being defended

The deterministic risk score is deliberately included as a feature rather than
replaced by the model. It encodes expert judgement that a small label set
cannot rediscover, and letting the model start from it means a handful of
labels can adjust the ranking instead of having to relearn the problem.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import math
import re
from typing import Any

# Postures ordered by how much deliberate work they represent
_MAIL_POSTURE_RANK = {
    'none': 0.0,
    'unknown': 0.0,     # A failed lookup is not evidence; it scores as absent
    'receive-only': 0.25,
    'partial': 0.5,
    'provisioned': 0.75,
    'hardened': 1.0,
}

# Words that appear in the title of a page built to harvest credentials
_CREDENTIAL_WORDS = (
    'login', 'log in', 'sign in', 'signin', 'account', 'password',
    'verify', 'secure', 'update', 'billing', 'invoice', 'wallet',
    'authenticate', 'confirm', 'suspended',
)

_PARKED_WORDS = (
    'for sale', 'domain for sale', 'parked', 'buy this domain',
    'coming soon', 'under construction', 'godaddy', 'sedo',
)

# Registrant fields that mean "hidden" rather than naming a person
_PRIVACY_WORDS = (
    'privacy', 'redacted', 'whois guard', 'whoisguard', 'protected',
    'not disclosed', 'data protected', 'gdpr', 'withheld',
)

# The order here IS the model's input order. Appending is safe; reordering or
# removing invalidates every previously trained model, which is why the list is
# explicit rather than derived from a dict at runtime.
FEATURE_NAMES = (
    'risk_score',
    'name_length',
    'label_length_delta',
    'digit_count',
    'hyphen_count',
    'is_punycode',
    'shannon_entropy',
    'edit_distance',
    'edit_distance_ratio',
    'shares_registrable_stem',
    'tld_matches_brand',
    'fuzzer_is_homoglyph',
    'fuzzer_is_tld_swap',
    'fuzzer_is_combosquat',
    'has_a_record',
    'a_record_count',
    'has_mx_record',
    'mx_record_count',
    'is_registered',
    'age_days_log',
    'is_recent',
    'registrant_is_private',
    'has_registrant',
    'mail_posture',
    'http_active',
    'https_active',
    'tls_verified',
    'tls_invalid',
    'has_title',
    'title_mentions_brand',
    'title_credential_words',
    'title_parked_words',
    'certificates_log',
    'urlscan_malicious',
    'has_credential_form',
    'has_password_input',
    'external_form_action',
    'form_count',
    'brand_mentioned_on_page',
)

FEATURE_COUNT = len(FEATURE_NAMES)


def _entropy(text: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _edit_distance(a: str, b: str) -> int:
    """
    Levenshtein distance between two strings.

    Implemented here rather than pulled from a dependency: it is fifteen lines,
    and a scoring path that must stay dependency-free cannot import one.

    Args:
        a: First string
        b: Second string

    Returns:
        Minimum single-character edits to turn a into b
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,          # deletion
                current[j - 1] + 1,       # insertion
                previous[j - 1] + (char_a != char_b),  # substitution
            ))
        previous = current
    return previous[-1]


def _split(domain: str) -> tuple[str, str]:
    """Split a domain into its first label and the rest."""
    parts = (domain or '').lower().split('.')
    return (parts[0], '.'.join(parts[1:])) if len(parts) > 1 else (parts[0], '')


def _contains_any(text: str, words) -> int:
    lowered = (text or '').lower()
    return sum(1 for word in words if word in lowered)


def extract(perm: dict[str, Any], monitored_domain: str) -> list[float]:
    """
    Build the feature vector for one permutation.

    Accepts either a live scan record or a history snapshot; the fields the two
    share are exactly the ones used here, so a vector built from history is
    identical to the one built at scan time.

    Args:
        perm: Permutation record or history snapshot
        monitored_domain: The brand domain being defended

    Returns:
        A list of floats, in FEATURE_NAMES order
    """
    domain = str(perm.get('domain') or '').lower()
    name, tld = _split(domain)
    brand_name, brand_tld = _split(monitored_domain)

    # A live record nests HTTP data; a snapshot flattens it. Read both.
    threat = perm.get('threat_intel') or {}
    http = threat.get('http_probe') or {}
    ct = threat.get('certificate_transparency') or {}
    urlscan = threat.get('urlscan') or {}
    page = http.get('page') or {}

    def field(key, http_key=None, default=None):
        if key in perm:
            return perm.get(key)
        return http.get(http_key or key, default)

    dns_a = [r for r in (perm.get('dns_a') or []) if not str(r).startswith('!')]
    dns_mx = [r for r in (perm.get('dns_mx') or []) if not str(r).startswith('!')]

    fuzzer = str(perm.get('fuzzer') or '').lower()
    registrant = str(perm.get('whois_registrant') or perm.get('whois_org') or '')
    title = str(field('title', 'title') or '')

    age_days = perm.get('created_days_ago')
    registered = bool(dns_a or perm.get('whois_registrar') or age_days is not None)

    tls_verified = field('tls_verified', 'tls_verified')
    https_active = bool(field('https_active', 'https_active'))

    distance = _edit_distance(name, brand_name)

    values = {
        # Clamped, not just scaled. The scorer keeps this in 0-100, but an
        # out-of-range value from a stale record or a future change would
        # otherwise dominate every weight in a linear model.
        'risk_score': min(max(float(perm.get('risk_score') or 0), 0.0), 100.0) / 100.0,
        'name_length': min(len(name), 63) / 63.0,
        'label_length_delta': min(abs(len(name) - len(brand_name)), 20) / 20.0,
        'digit_count': min(sum(c.isdigit() for c in name), 10) / 10.0,
        'hyphen_count': min(name.count('-'), 5) / 5.0,
        'is_punycode': float(domain.startswith('xn--') or '.xn--' in domain),
        'shannon_entropy': min(_entropy(name), 6.0) / 6.0,
        'edit_distance': min(distance, 10) / 10.0,
        # Distance relative to brand length: one edit in a 4-letter name is a
        # far bigger change than one edit in a 20-letter name.
        'edit_distance_ratio': min(distance / max(len(brand_name), 1), 1.0),
        'shares_registrable_stem': float(bool(brand_name) and brand_name in name),
        'tld_matches_brand': float(bool(tld) and tld == brand_tld),
        'fuzzer_is_homoglyph': float('homoglyph' in fuzzer or 'homograph' in fuzzer),
        'fuzzer_is_tld_swap': float('tld' in fuzzer),
        'fuzzer_is_combosquat': float('combo' in fuzzer or 'keyword' in fuzzer),
        'has_a_record': float(bool(dns_a)),
        'a_record_count': min(len(dns_a), 5) / 5.0,
        'has_mx_record': float(bool(dns_mx)),
        'mx_record_count': min(len(dns_mx), 5) / 5.0,
        'is_registered': float(registered),
        # Log-scaled: the difference between 3 and 30 days old matters far more
        # than the difference between 1000 and 1027.
        'age_days_log': (
            0.0 if age_days is None
            else 1.0 - min(math.log10(max(float(age_days), 1.0) + 1) / 4.0, 1.0)
        ),
        'is_recent': float(bool(perm.get('is_recent'))),
        'registrant_is_private': float(_contains_any(registrant, _PRIVACY_WORDS) > 0),
        'has_registrant': float(bool(registrant.strip())),
        'mail_posture': _MAIL_POSTURE_RANK.get(
            str((perm.get('mail_intel') or {}).get('posture')
                or perm.get('mail_posture') or 'unknown').lower(), 0.0),
        'http_active': float(bool(field('http_active', 'http_active'))),
        'https_active': float(https_active),
        'tls_verified': float(tls_verified is True),
        # A domain that answers on 443 with an untrusted certificate is a
        # distinct state from one that does not answer at all.
        'tls_invalid': float(https_active and tls_verified is False),
        'has_title': float(bool(title.strip())),
        'title_mentions_brand': float(
            bool(brand_name) and brand_name in title.lower()
        ),
        'title_credential_words': min(
            _contains_any(title, _CREDENTIAL_WORDS), 3) / 3.0,
        'title_parked_words': min(_contains_any(title, _PARKED_WORDS), 2) / 2.0,
        'certificates_log': min(
            math.log10(float(ct.get('certificates_found')
                             or perm.get('certificates_found') or 0) + 1) / 3.0, 1.0),
        'urlscan_malicious': float(bool(
            urlscan.get('malicious') or perm.get('urlscan_malicious')
        )),
        # Page analysis, read from either the live record's nested shape or
        # the flattened history snapshot, like every other field here.
        'has_credential_form': float(bool(
            page.get('is_credential_form') or perm.get('is_credential_form')
        )),
        'has_password_input': float(bool(
            page.get('has_password_input') or perm.get('has_password_input')
        )),
        'external_form_action': float(bool(
            page.get('external_form_action') or perm.get('external_form_action')
        )),
        'form_count': min(
            float(page.get('form_count') or perm.get('form_count') or 0), 5.0
        ) / 5.0,
        'brand_mentioned_on_page': float(bool(
            page.get('brand_mentioned') or perm.get('brand_mentioned')
        )),
    }

    return [float(values[fname]) for fname in FEATURE_NAMES]


def describe(vector: list[float]) -> dict[str, float]:
    """Pair a feature vector with its names, for inspection and debugging."""
    return dict(zip(FEATURE_NAMES, vector, strict=False))


def normalise_domain(domain: str) -> str:
    """Canonical form used as a label key."""
    return re.sub(r'^\.+|\.+$', '', str(domain or '').strip().lower())
