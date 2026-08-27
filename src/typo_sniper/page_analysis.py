"""
What a suspicious page is actually built to do.

A registered lookalike tells you someone bought a domain. A lookalike serving a
form with a password field tells you what they bought it for. That is the
difference between a finding worth watching and a finding worth a takedown
request this afternoon, and until now the scanner could not see it: it read the
page title and nothing else.

This module reads the HTML already fetched by the HTTP probe — no extra request
— and answers a narrow set of questions:

  * Does the page collect a password? Credentials are the point of most
    typosquatting, and a password input is the least deniable evidence of it.
  * Where does the form submit to? A form on ``examp1e.com`` that POSTs to a
    third domain is an exfiltration path, not a login page.
  * Does the page name the brand it is imitating?

Parsing is done with the standard library's HTMLParser rather than a
third-party parser. This is attacker-authored markup by definition, so the
smaller and more boring the parsing surface, the better: no external entity
resolution, no network fetches, no recovery heuristics that could be steered.
Every collection is bounded, because a page designed to be parsed slowly is a
cheap way to stall a scan.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import logging
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

# Bounds. A hostile page must not be able to make parsing expensive.
MAX_FORMS = 50
MAX_INPUTS = 300
MAX_TEXT_CHARS = 20_000

# Input names and ids that mean "credential" even when the type does not say so
_CREDENTIAL_NAMES = re.compile(
    r'pass|pwd|passwd|secret|otp|mfa|2fa|token|pin\b|cvv|card|ssn|account',
    re.IGNORECASE,
)
_USERNAME_NAMES = re.compile(
    r'user|login|email|e-mail|signin|sign_in|account|member',
    re.IGNORECASE,
)

# Tags whose contents are not visible text
_INVISIBLE = {'script', 'style', 'noscript', 'template', 'head'}

logger = logging.getLogger(__name__)


class _PageParser(HTMLParser):
    """Collect forms, inputs, and visible text from one page."""

    def __init__(self):
        # convert_charrefs keeps entity decoding in the standard library rather
        # than in anything hand-rolled here.
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self.inputs: list[dict[str, str]] = []
        self.text_parts: list[str] = []
        self._text_len = 0
        self._suppress = 0
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag, attrs):
        attributes = {k.lower(): (v or '') for k, v in attrs}

        if tag in _INVISIBLE:
            self._suppress += 1
            return

        if tag == 'form' and len(self.forms) < MAX_FORMS:
            self._current_form = {
                'action': attributes.get('action', ''),
                'method': attributes.get('method', 'get').lower(),
                'inputs': [],
            }
            self.forms.append(self._current_form)

        elif tag in ('input', 'select', 'textarea') and len(self.inputs) < MAX_INPUTS:
            field = {
                'type': attributes.get('type', 'text').lower(),
                'name': attributes.get('name', ''),
                'id': attributes.get('id', ''),
                'autocomplete': attributes.get('autocomplete', '').lower(),
                'placeholder': attributes.get('placeholder', ''),
            }
            self.inputs.append(field)
            if self._current_form is not None:
                self._current_form['inputs'].append(field)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in _INVISIBLE and self._suppress:
            self._suppress -= 1
        elif tag == 'form':
            self._current_form = None

    def handle_data(self, data):
        if self._suppress or self._text_len >= MAX_TEXT_CHARS:
            return
        stripped = data.strip()
        if stripped:
            self.text_parts.append(stripped)
            self._text_len += len(stripped)

    # A malformed page must not raise out of the parser
    def error(self, message):  # pragma: no cover - HTMLParser legacy hook
        pass


def _registrable(host: str) -> str:
    """
    Reduce a host to something comparable across subdomains.

    Uses the Public Suffix List already vendored for permutation generation, so
    ``login.example.co.uk`` and ``example.co.uk`` compare equal while
    ``example.github.io`` and ``other.github.io`` do not.
    """
    host = (host or '').lower().strip('.')
    if not host:
        return ''
    try:
        from publicsuffixlist import PublicSuffixList

        return PublicSuffixList().privatesuffix(host) or host
    except Exception:
        # Never let suffix lookup failure cost the whole analysis
        parts = host.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else host


def _field_is_credential(field: dict[str, str]) -> bool:
    if field.get('type') == 'password':
        return True
    if 'current-password' in field.get('autocomplete', ''):
        return True
    if 'new-password' in field.get('autocomplete', ''):
        return True
    blob = f"{field.get('name', '')} {field.get('id', '')} {field.get('placeholder', '')}"
    return bool(_CREDENTIAL_NAMES.search(blob))


def _field_is_username(field: dict[str, str]) -> bool:
    if field.get('type') == 'email':
        return True
    blob = f"{field.get('name', '')} {field.get('id', '')} {field.get('placeholder', '')}"
    return bool(_USERNAME_NAMES.search(blob))


def analyse(
    html: str, probed_url: str = '', monitored_domain: str = ''
) -> dict[str, Any]:
    """
    Describe what a fetched page appears built to collect.

    Args:
        html: Raw page source, already length-bounded by the caller
        probed_url: The URL the body came from, for resolving relative actions
        monitored_domain: The brand being defended, for mention counting

    Returns:
        A summary dictionary; never raises on malformed input
    """
    result: dict[str, Any] = {
        'form_count': 0,
        'has_password_input': False,
        'has_username_input': False,
        'is_credential_form': False,
        'external_form_action': False,
        'form_action_hosts': [],
        'brand_mentioned': False,
        'brand_mention_count': 0,
        'input_types': [],
        'parse_ok': False,
        'parse_truncated': False,
    }

    if not html:
        return result

    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:
        # A page that breaks the parser is still a page we saw, so whatever was
        # collected before the failure is kept. It is flagged as truncated
        # rather than passed off as a complete reading: "no password field
        # found" and "we stopped looking" are different claims.
        result['parse_truncated'] = True
        logger.debug('Page parsing ended early (%s)', type(e).__name__)

    result['parse_ok'] = True
    result['form_count'] = len(parser.forms)
    result['input_types'] = sorted({f['type'] for f in parser.inputs if f['type']})[:15]

    has_password = any(_field_is_credential(f) for f in parser.inputs)
    has_username = any(_field_is_username(f) for f in parser.inputs)
    result['has_password_input'] = has_password
    result['has_username_input'] = has_username

    # A credential form is the pairing: somewhere to type who you are and
    # somewhere to type the secret that proves it.
    result['is_credential_form'] = any(
        any(_field_is_credential(f) for f in form['inputs'])
        and any(_field_is_username(f) for f in form['inputs'])
        for form in parser.forms
    ) or (has_password and has_username)

    probed_host = _registrable(urlparse(probed_url).hostname or '')
    hosts = []
    for form in parser.forms:
        action = (form.get('action') or '').strip()
        if not action:
            continue
        parsed = urlparse(action)
        if not parsed.hostname:
            continue  # relative action: same origin
        host = _registrable(parsed.hostname)
        if host and host not in hosts:
            hosts.append(host)
        # A form that posts somewhere else entirely is an exfiltration path,
        # not a login page, and it is worth saying so plainly.
        if probed_host and host and host != probed_host:
            result['external_form_action'] = True

    result['form_action_hosts'] = hosts[:5]

    brand = (monitored_domain or '').split('.')[0].lower()
    if brand and len(brand) >= 3:
        text = ' '.join(parser.text_parts).lower()
        count = text.count(brand)
        result['brand_mention_count'] = min(count, 99)
        result['brand_mentioned'] = count > 0

    return result


def describe(analysis: dict[str, Any] | None) -> str:
    """
    A short human-readable summary for reports.

    Args:
        analysis: Output of ``analyse``, or None

    Returns:
        One line describing the page's apparent purpose
    """
    if not analysis or not analysis.get('parse_ok'):
        return ''

    parts = []
    if analysis.get('is_credential_form'):
        parts.append('credential form')
    elif analysis.get('has_password_input'):
        parts.append('password field')
    elif analysis.get('form_count'):
        parts.append(f"{analysis['form_count']} form(s)")

    if analysis.get('external_form_action'):
        hosts = ', '.join(analysis.get('form_action_hosts') or [])
        parts.append(f'submits off-site ({hosts})' if hosts else 'submits off-site')

    if analysis.get('brand_mentioned'):
        parts.append('names the brand')

    return '; '.join(parts)
