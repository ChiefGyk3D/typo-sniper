"""
Mail-capability intelligence for lookalike domains.

The strongest pre-attack signal a typosquat can emit is *mail provisioning*.
Registering a lookalike costs a few dollars and means little on its own. Setting
up SPF, DKIM and DMARC on it is deliberate work whose only purpose is to make
mail from that domain arrive in inboxes rather than spam folders — which is the
prerequisite for credential phishing and business email compromise, not for a
parked domain someone is holding to resell.

This module answers three questions per domain:

  * Can it receive mail?  (MX, already collected by dnstwist)
  * Is it provisioned to send mail that passes receiver checks?  (SPF, DKIM)
  * Has the operator configured a DMARC policy?

A lookalike with a full SPF/DKIM/DMARC stack is a materially different threat
from one with an A record and nothing else.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import asyncio
import logging
import re
from typing import Any

# DKIM keys live at <selector>._domainkey.<domain> and the selector is not
# discoverable from DNS. These cover the defaults used by the mail platforms an
# attacker is most likely to sign up for.
COMMON_DKIM_SELECTORS = (
    'default',        # generic / self-hosted
    'google',         # Google Workspace
    'selector1',      # Microsoft 365
    'selector2',      # Microsoft 365 (rotation pair)
    'k1',             # Mailchimp / Mandrill
    's1',             # SendGrid and others
    'mail',           # common self-hosted convention
    'dkim',           # common self-hosted convention
    'zoho',           # Zoho Mail
    'protonmail',     # Proton
)

SPF_PREFIX = 'v=spf1'
DMARC_PREFIX = 'v=dmarc1'

# SPF qualifier on the "all" mechanism, which says what to do with mail from
# senders the record does not authorise
_ALL_RE = re.compile(r'([~\-+?])all\b', re.IGNORECASE)
_DMARC_POLICY_RE = re.compile(r'\bp\s*=\s*(none|quarantine|reject)\b', re.IGNORECASE)


class DNSIntelligence:
    """Query mail-related DNS records for a domain."""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._resolver = None

    def _get_resolver(self):
        """
        Build a dnspython async resolver, or None when dnspython is absent.

        Returns:
            An async resolver, or None if DNS intelligence cannot run
        """
        if self._resolver is not None:
            return self._resolver

        try:
            import dns.asyncresolver
        except ImportError:
            self.logger.warning(
                "dnspython is not installed; SPF/DKIM/DMARC checks are unavailable"
            )
            return None

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.config.dns_timeout
        resolver.lifetime = self.config.dns_timeout
        if self.config.dns_nameservers:
            resolver.nameservers = list(self.config.dns_nameservers)

        self._resolver = resolver
        return resolver

    async def _query_txt(self, name: str) -> tuple[list[str], bool]:
        """
        Fetch TXT records for a name.

        Args:
            name: DNS name to query

        Returns:
            Tuple of (records, ok). ``ok`` is False when the lookup itself
            failed, which is not the same as the name having no TXT records.
            Conflating the two would report "no SPF" for a domain whose
            response merely exceeded UDP limits — absence of evidence
            rendered as evidence of absence.
        """
        resolver = self._get_resolver()
        if resolver is None:
            return [], False

        import dns.resolver

        # A large TXT response (many verification tokens) is truncated over
        # UDP and must be retried over TCP.
        for use_tcp in (False, True):
            try:
                answer = await resolver.resolve(name, 'TXT', tcp=use_tcp)
                records = []
                for rdata in answer:
                    # TXT rdata is a sequence of <=255-byte strings that must be
                    # concatenated; long DKIM keys always span several.
                    parts = [
                        p.decode('utf-8', 'replace') if isinstance(p, bytes) else str(p)
                        for p in rdata.strings
                    ]
                    records.append(''.join(parts))
                return records, True

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Authoritative: the name genuinely has no TXT records
                return [], True
            except Exception as e:
                if use_tcp:
                    self.logger.debug(f"TXT lookup failed for {name}: {e}")
                    return [], False

        return [], False

    # -- individual records ------------------------------------------------

    async def check_spf(self, domain: str) -> dict[str, Any] | None:
        """
        Look for an SPF record.

        Args:
            domain: Domain to query

        Returns:
            SPF summary, ``{'unknown': True}`` when the lookup failed, or None
            when the domain demonstrably has no SPF record
        """
        records, ok = await self._query_txt(domain)
        if not ok:
            return {'unknown': True}

        for record in records:
            if record.lower().startswith(SPF_PREFIX):
                match = _ALL_RE.search(record)
                qualifier = match.group(1) if match else None
                return {
                    'present': True,
                    'record': record[:450],
                    'all_qualifier': qualifier,
                    'policy': {
                        '-': 'fail', '~': 'softfail',
                        '+': 'pass', '?': 'neutral',
                    }.get(qualifier),
                    # Third-party senders the domain authorises. A squat that
                    # includes a bulk-mail provider is set up to send campaigns.
                    'includes': re.findall(r'include:([^\s]+)', record)[:10],
                }
        return None

    async def check_dmarc(self, domain: str) -> dict[str, Any] | None:
        """
        Look for a DMARC policy.

        Args:
            domain: Domain to query

        Returns:
            DMARC summary, ``{'unknown': True}`` when the lookup failed, or
            None when the domain has no DMARC record
        """
        records, ok = await self._query_txt(f'_dmarc.{domain}')
        if not ok:
            return {'unknown': True}

        for record in records:
            if record.lower().startswith(DMARC_PREFIX):
                match = _DMARC_POLICY_RE.search(record)
                return {
                    'present': True,
                    'record': record[:450],
                    'policy': match.group(1).lower() if match else None,
                    # rua/ruf show where aggregate reports go, which sometimes
                    # exposes the operator's real infrastructure
                    'rua': re.findall(r'rua=([^;]+)', record)[:3],
                }
        return None

    async def check_dkim(self, domain: str) -> dict[str, Any] | None:
        """
        Probe common DKIM selectors.

        A negative result is weak evidence: the selector namespace is
        unbounded, so an absent key only means none of the common selectors
        matched, not that DKIM is unconfigured.

        Args:
            domain: Domain to query

        Returns:
            DKIM summary, or None when no common selector responded
        """
        if not self.config.enable_dkim_probe:
            return None

        selectors = list(self.config.dkim_selectors or COMMON_DKIM_SELECTORS)

        async def probe(selector):
            records, _ = await self._query_txt(f'{selector}._domainkey.{domain}')
            for record in records:
                lowered = record.lower()
                if 'v=dkim1' in lowered or 'p=' in lowered:
                    return selector
            return None

        results = await asyncio.gather(
            *(probe(s) for s in selectors), return_exceptions=True
        )
        found = [r for r in results if isinstance(r, str)]

        if not found:
            return None

        return {'present': True, 'selectors': found}

    # -- aggregate ---------------------------------------------------------

    async def analyze(self, domain: str, has_mx: bool = False) -> dict[str, Any]:
        """
        Assess a domain's mail-sending capability.

        Args:
            domain: Domain to assess
            has_mx: Whether the domain already has known MX records

        Returns:
            Mail capability report
        """
        spf, dmarc, dkim = await asyncio.gather(
            self.check_spf(domain),
            self.check_dmarc(domain),
            self.check_dkim(domain),
            return_exceptions=True,
        )

        spf = spf if isinstance(spf, dict) else None
        dmarc = dmarc if isinstance(dmarc, dict) else None
        dkim = dkim if isinstance(dkim, dict) else None

        # A lookup that failed tells us nothing. Reporting it as "no mail
        # capability" would be the same mistake as treating a WHOIS timeout as
        # "no registration date": a silent failure dressed up as a finding.
        lookup_failed = any(
            isinstance(x, dict) and x.get('unknown') for x in (spf, dmarc)
        )

        spf = None if (spf or {}).get('unknown') else spf
        dmarc = None if (dmarc or {}).get('unknown') else dmarc

        return {
            'spf': spf,
            'dmarc': dmarc,
            'dkim': dkim,
            'lookup_failed': lookup_failed,
            'can_receive': bool(has_mx),
            'can_send': None if lookup_failed else bool(spf),
            'posture': (
                'unknown' if lookup_failed
                else classify_mail_posture(spf, dmarc, dkim, has_mx)
            ),
        }


def classify_mail_posture(spf, dmarc, dkim, has_mx: bool) -> str:
    """
    Summarise what a domain's mail configuration says about intent.

    Args:
        spf: SPF summary or None
        dmarc: DMARC summary or None
        dkim: DKIM summary or None
        has_mx: Whether MX records exist

    Returns:
        One of: none, receive-only, partial, provisioned, hardened
    """
    signals = sum(bool(x) for x in (spf, dmarc, dkim))

    if not signals and not has_mx:
        return 'none'
    if not signals:
        return 'receive-only'

    # A full stack means someone did the work to make mail deliverable
    if spf and dkim and dmarc:
        policy = (dmarc or {}).get('policy')
        return 'hardened' if policy in ('quarantine', 'reject') else 'provisioned'

    if spf and (dkim or dmarc):
        return 'provisioned'

    return 'partial'


def score_mail_capability(mail: dict[str, Any] | None) -> int:
    """
    Convert a mail capability report into risk points.

    Weighting reflects effort and intent rather than record count. Publishing
    SPF on a lookalike is a deliberate act with one obvious purpose; a full
    signed-and-aligned stack is a mail operation, not a parked name.

    Args:
        mail: Mail capability report, or None

    Returns:
        Risk points to add (0-25)
    """
    if not mail or mail.get('posture') == 'unknown':
        # No evidence either way: score it as though the check never ran,
        # rather than rewarding a domain for a failed lookup.
        return 0

    posture = mail.get('posture')
    base = {
        'none': 0,
        'receive-only': 3,
        'partial': 8,
        'provisioned': 18,
        'hardened': 22,
    }.get(posture, 0)

    # Authorising a bulk-mail provider on a lookalike points at campaigns
    spf = mail.get('spf') or {}
    if spf.get('includes'):
        base += 3

    return min(base, 25)
